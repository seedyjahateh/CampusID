"""Server-side session storage (FR-SES-01/02/03/06).

Everything about a session lives in Redis; the cookie carries nothing but an
opaque identifier. That is the requirement, and it is also what makes
`terminate` meaningful — a self-contained signed cookie cannot be revoked
before it expires, so an administrator killing a compromised session would be
issuing a request the browser is free to ignore.

Both timeouts are enforced against stored timestamps rather than by cookie
expiry. A cookie `Max-Age` is a request to the browser; a stored
`absolute_expiry` is a fact the server checks. Redis TTL is set to the *idle*
window and refreshed on each load, so an abandoned session also disappears on
its own rather than accumulating.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final

from redis.asyncio import Redis

from campusid.saml.stores import utcnow

SESSION_KEY_PREFIX: Final = "session:"

IDLE_TIMEOUT: Final = timedelta(minutes=30)
ABSOLUTE_TIMEOUT: Final = timedelta(hours=12)

SID_BYTES: Final = 32
"""256 bits from a CSPRNG (NFR-SEC-02). The identifier is the only thing
standing between an attacker and someone else's session, so it is sized to make
guessing hopeless rather than merely unlikely."""


@dataclass(frozen=True, slots=True)
class Session:
    """An authenticated browser session."""

    sid: str
    idp_entity_id: str
    name_id: str
    name_id_format: str | None
    auth_time: datetime
    created_at: datetime
    last_seen_at: datetime
    absolute_expiry: datetime
    acr: str | None = None
    amr: tuple[str, ...] = ()
    session_index: str | None = None
    attributes: dict[str, list[str]] = field(default_factory=dict)

    @property
    def subject_key(self) -> str:
        """How this browser's user is identified for now.

        The pair of issuing IdP and `NameID`, because a `NameID` is only
        meaningful within the IdP that minted it. M3 replaces this with a
        `person_uuid` once the identity registry exists to allocate one.
        """
        return f"{self.idp_entity_id}|{self.name_id}"

    def to_json(self) -> str:
        payload = asdict(self)
        payload["amr"] = list(self.amr)
        for name in ("auth_time", "created_at", "last_seen_at", "absolute_expiry"):
            payload[name] = getattr(self, name).isoformat()
        return json.dumps(payload)

    @classmethod
    def from_json(cls, raw: str) -> Session:
        payload = json.loads(raw)
        payload["amr"] = tuple(payload["amr"])
        for name in ("auth_time", "created_at", "last_seen_at", "absolute_expiry"):
            payload[name] = datetime.fromisoformat(payload[name])
        return cls(**payload)


class SessionStore:
    """Redis-backed session storage."""

    def __init__(
        self,
        redis: Redis,
        *,
        idle_timeout: timedelta = IDLE_TIMEOUT,
        absolute_timeout: timedelta = ABSOLUTE_TIMEOUT,
        prefix: str = SESSION_KEY_PREFIX,
    ) -> None:
        self._redis = redis
        self._idle = idle_timeout
        self._absolute = absolute_timeout
        self._prefix = prefix

    async def create(
        self,
        *,
        idp_entity_id: str,
        name_id: str,
        name_id_format: str | None = None,
        auth_time: datetime | None = None,
        acr: str | None = None,
        amr: tuple[str, ...] = (),
        session_index: str | None = None,
        attributes: dict[str, list[str]] | None = None,
        now: datetime | None = None,
    ) -> Session:
        """Start a session and return it."""
        now = now or utcnow()
        session = Session(
            sid=new_sid(),
            idp_entity_id=idp_entity_id,
            name_id=name_id,
            name_id_format=name_id_format,
            auth_time=auth_time or now,
            created_at=now,
            last_seen_at=now,
            absolute_expiry=now + self._absolute,
            acr=acr,
            amr=amr,
            session_index=session_index,
            attributes=attributes or {},
        )
        await self._write(session)
        return session

    async def load(self, sid: str, *, now: datetime | None = None) -> Session | None:
        """Fetch a session, enforcing both timeouts and refreshing idle time.

        Returns None for an unknown, idle-expired or absolutely-expired
        session, and deletes the record in the last case so it cannot be
        resurrected by a clock adjustment.
        """
        now = now or utcnow()
        raw = await self._redis.get(self._key(sid))
        if raw is None:
            return None

        session = Session.from_json(raw)
        if now >= session.absolute_expiry or now - session.last_seen_at >= self._idle:
            await self.destroy(sid)
            return None

        touched = _replace(session, last_seen_at=now)
        await self._write(touched, now=now)
        return touched

    async def rotate(self, sid: str, *, now: datetime | None = None) -> Session | None:
        """Move a session to a fresh identifier, discarding the old one.

        Called on authentication and on any privilege change (FR-SES-03). An
        attacker who fixed a victim's pre-authentication identifier holds a
        value that no longer addresses anything.
        """
        now = now or utcnow()
        session = await self.load(sid, now=now)
        if session is None:
            return None

        rotated = _replace(session, sid=new_sid(), last_seen_at=now)
        await self._write(rotated, now=now)
        await self.destroy(sid)
        return rotated

    async def elevate(
        self,
        sid: str,
        *,
        acr: str,
        amr: tuple[str, ...],
        now: datetime | None = None,
    ) -> Session | None:
        """Raise the assurance of a session, rotating its identifier.

        The rotation is the point: assurance changing is a privilege change,
        and reusing the identifier across it would let a session captured at
        the lower level be replayed at the higher one. Used by step-up in M4.
        """
        now = now or utcnow()
        session = await self.load(sid, now=now)
        if session is None:
            return None

        elevated = _replace(
            session, sid=new_sid(), acr=acr, amr=amr, auth_time=now, last_seen_at=now
        )
        await self._write(elevated, now=now)
        await self.destroy(sid)
        return elevated

    async def destroy(self, sid: str) -> None:
        """Delete a session. Immediate, because the state is server-side."""
        await self._redis.delete(self._key(sid))

    async def _write(self, session: Session, *, now: datetime | None = None) -> None:
        now = now or utcnow()
        # TTL is the idle window, refreshed on every load, so an abandoned
        # session expires on its own; the absolute deadline is checked from the
        # stored value because Redis can only express one expiry.
        remaining = (session.absolute_expiry - now).total_seconds()
        ttl = max(int(min(self._idle.total_seconds(), remaining)), 1)
        await self._redis.set(self._key(session.sid), session.to_json(), ex=ttl)

    def _key(self, sid: str) -> str:
        return f"{self._prefix}{sid}"


def new_sid() -> str:
    """A 256-bit session identifier."""
    return secrets.token_urlsafe(SID_BYTES)


def _replace(session: Session, **changes: Any) -> Session:
    """`dataclasses.replace` equivalent, spelled out.

    `Session` is `slots=True` and frozen, and the field list is written here so
    adding a field without deciding how rotation treats it fails loudly rather
    than silently dropping it.
    """
    payload: dict[str, Any] = {
        name: getattr(session, name)
        for name in (
            "sid",
            "idp_entity_id",
            "name_id",
            "name_id_format",
            "auth_time",
            "created_at",
            "last_seen_at",
            "absolute_expiry",
            "acr",
            "amr",
            "session_index",
            "attributes",
        )
    }
    payload.update(changes)
    return Session(**payload)
