"""Registering and resolving OIDC clients.

The boundary between "somebody asked for a client" and "a client this broker
will issue tokens to". Registration validates everything the authorization
endpoint later relies on — redirect URIs, scopes, the secret's length — so a
registration that could never work is refused while an operator is still looking
at it.

`OidcClient.__post_init__` does that validation, and this module is what makes it
unavoidable: every read reconstructs the frozen dataclass from the row, so a
stored registration that would fail today's rules fails loudly on read rather
than being used under rules that no longer exist. It is the same argument as the
federation registry re-parsing metadata on every resolve.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from campusid.errors import ReasonCode
from campusid.oidc.claims import SUPPORTED_SCOPES
from campusid.oidc.clients import (
    MIN_SECRET_LENGTH,
    ClientType,
    OidcClient,
    generate_secret,
    hash_secret,
)
from campusid.oidc.errors import INVALID_CLIENT, OAuthError
from campusid.oidc.models import OidcClientRecord


class ClientRegistry:
    """Reads and writes the set of registered relying parties."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = session_factory

    async def register(
        self,
        *,
        client_id: str,
        client_type: ClientType,
        redirect_uris: tuple[str, ...],
        allowed_scopes: frozenset[str],
        display_name: str | None = None,
        require_pushed_authorization_requests: bool = False,
        backchannel_logout_uri: str | None = None,
        post_logout_redirect_uris: tuple[str, ...] = (),
        secret: str | None = None,
    ) -> tuple[OidcClient, str | None]:
        """Register or update a client, returning it with its secret.

        The secret comes back exactly once, here. There is no column that could
        hold the plaintext and no endpoint that could show it again — a secret a
        system can redisplay is one that ends up in a screenshot.
        """
        unknown_scopes = allowed_scopes - set(SUPPORTED_SCOPES)
        if unknown_scopes:
            # A scope the broker cannot fulfil would be granted and release
            # nothing, which a client cannot tell from a policy denial.
            raise ValueError(f"unknown scopes {sorted(unknown_scopes)}")

        if client_type is ClientType.CONFIDENTIAL:
            secret = secret or generate_secret()
            if len(secret) < MIN_SECRET_LENGTH:
                # The argument for hashing these with SHA-256 rests on them
                # being long and machine-generated. Enforced, not assumed.
                raise ValueError(f"a client secret must be at least {MIN_SECRET_LENGTH} characters")
        elif secret is not None:
            raise ValueError(f"{client_type.value} clients cannot hold a secret")

        # Constructed before anything is written, so an invalid registration is
        # refused rather than stored and rejected on every later read.
        client = OidcClient(
            client_id=client_id,
            client_type=client_type,
            redirect_uris=redirect_uris,
            allowed_scopes=allowed_scopes,
            secret_hash=hash_secret(secret) if secret else None,
            display_name=display_name,
            require_pushed_authorization_requests=require_pushed_authorization_requests,
            backchannel_logout_uri=backchannel_logout_uri,
            post_logout_redirect_uris=post_logout_redirect_uris,
        )

        async with self._sessions() as session, session.begin():
            existing = await session.scalar(
                select(OidcClientRecord).where(OidcClientRecord.client_id == client_id)
            )
            if existing is None:
                session.add(_to_record(client))
            else:
                _update_record(existing, client)

        return client, secret

    async def get(self, client_id: str) -> OidcClient | None:
        """The client, or None if it is unknown or disabled.

        Both answer None on purpose: from the authorization endpoint's point of
        view a disabled client is not a client, and distinguishing the two in a
        response would tell an unauthenticated caller which client_ids exist.
        """
        async with self._sessions() as session:
            record = await session.scalar(
                select(OidcClientRecord).where(
                    OidcClientRecord.client_id == client_id,
                    OidcClientRecord.enabled.is_(True),
                )
            )
        return _from_record(record) if record is not None else None

    async def require(self, client_id: str | None) -> OidcClient:
        """The client, or an `invalid_client` refusal.

        Never redirectable: until a client is known there is no registered URI
        to redirect to, and the one the caller supplied is exactly the value in
        question.
        """
        client = await self.get(client_id) if client_id else None
        if client is None:
            raise OAuthError(
                INVALID_CLIENT, ReasonCode.UNKNOWN_CLIENT, f"no such client: {client_id!r}"
            )
        return client

    async def list_clients(self) -> list[OidcClient]:
        """Every registered client, enabled or not, for the admin view."""
        async with self._sessions() as session:
            records = await session.scalars(
                select(OidcClientRecord).order_by(OidcClientRecord.client_id)
            )
            return [_from_record(record) for record in records]

    async def set_enabled(self, client_id: str, enabled: bool) -> None:
        """Turn a client's registration on or off without losing its history."""
        async with self._sessions() as session, session.begin():
            record = await session.scalar(
                select(OidcClientRecord).where(OidcClientRecord.client_id == client_id)
            )
            if record is None:
                raise OAuthError(
                    INVALID_CLIENT, ReasonCode.UNKNOWN_CLIENT, f"no such client: {client_id!r}"
                )
            record.enabled = enabled


def _to_record(client: OidcClient) -> OidcClientRecord:
    return OidcClientRecord(
        client_id=client.client_id,
        client_type=client.client_type.value,
        display_name=client.display_name,
        redirect_uris=list(client.redirect_uris),
        allowed_scopes=sorted(client.allowed_scopes),
        post_logout_redirect_uris=list(client.post_logout_redirect_uris),
        secret_hash=client.secret_hash,
        require_pushed_authorization_requests=client.require_pushed_authorization_requests,
        backchannel_logout_uri=client.backchannel_logout_uri,
    )


def _update_record(record: OidcClientRecord, client: OidcClient) -> None:
    record.client_type = client.client_type.value
    record.display_name = client.display_name
    record.redirect_uris = list(client.redirect_uris)
    record.allowed_scopes = sorted(client.allowed_scopes)
    record.post_logout_redirect_uris = list(client.post_logout_redirect_uris)
    record.require_pushed_authorization_requests = client.require_pushed_authorization_requests
    record.backchannel_logout_uri = client.backchannel_logout_uri
    if client.secret_hash is not None:
        # A re-registration that supplies no secret keeps the existing one:
        # rotating a secret is a deliberate act, not a side effect of editing a
        # redirect URI.
        record.secret_hash = client.secret_hash


def _from_record(record: OidcClientRecord) -> OidcClient:
    """Rebuild the frozen client from its row.

    Runs `OidcClient`'s validation on every read, so a registration stored under
    looser rules fails loudly the first time it is used rather than continuing
    to work under rules that no longer exist.
    """
    return OidcClient(
        client_id=record.client_id,
        client_type=ClientType(record.client_type),
        redirect_uris=tuple(record.redirect_uris),
        allowed_scopes=frozenset(record.allowed_scopes),
        secret_hash=record.secret_hash,
        display_name=record.display_name,
        require_pushed_authorization_requests=record.require_pushed_authorization_requests,
        backchannel_logout_uri=record.backchannel_logout_uri,
        post_logout_redirect_uris=tuple(record.post_logout_redirect_uris),
    )
