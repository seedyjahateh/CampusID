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

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Final

from redis.asyncio import Redis

from campusid.cache import expire_key, set_add, set_members, set_remove
from campusid.saml.stores import utcnow

SESSION_KEY_PREFIX: Final = "session:"

SUBJECT_INDEX_PREFIX: Final = "session:subject:"
"""Maps a person to their live session ids, so an administrator can end all of
them (FR-SES-05) without scanning every key in Redis.

The index is keyed by a hash of the subject rather than by the subject itself. A
`NameID` in a Redis key name would put an identifier from the IdP into every
`KEYS` listing, every slow-log entry and every memory dump — none of which are
places a person's identifier belongs, and none of which need it to be readable.
"""

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
    person_uuid: str | None = None
    """Who this is, once the identity registry has said so.

    Optional only because a session may predate the resolution — a stored
    session written before this field existed still loads. Every session
    established after M3 carries one.
    """

    @property
    def subject_key(self) -> str:
        """How this browser's user is identified.

        The `person_uuid` when there is one, because that is what makes "end
        every session this person has" mean every session rather than every
        session from one IdP. Somebody who logged in through the campus IdP and
        again through a partner has two subjects under the older key and one
        under this one, and a deprovisioning that ended only half of them would
        be the failure FR-LC-03 exists to prevent.

        The IdP-and-`NameID` pair remains the fallback: a `NameID` is meaningful
        only within the IdP that minted it, so the two parts are never separated.
        """
        return self.person_uuid or f"{self.idp_entity_id}|{self.name_id}"

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
        person_uuid: str | None = None,
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
            person_uuid=person_uuid,
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
        raw = await self._redis.get(self._key(sid))
        if raw is not None:
            # Read before deleting so the subject index can be pruned. Leaving
            # a dead sid in the index would make an administrator's "terminate
            # everything" report successes for sessions that no longer exist,
            # which is the wrong direction for that particular reassurance.
            session = Session.from_json(raw)
            await set_remove(self._redis, self._subject_key(session.subject_key), sid)
        await self._redis.delete(self._key(sid))

    async def sids_for(self, subject_key: str) -> list[str]:
        """Every live session id for one person (FR-SES-05)."""
        return await set_members(self._redis, self._subject_key(subject_key))

    async def terminate_subject(self, subject_key: str) -> list[str]:
        """End every session this person has, returning the ids that were ended.

        The ids are returned rather than swallowed because the caller has more
        to do with them: back-channel logout has to reach the clients that hold
        each one, and an audit record has to name them.
        """
        sids = await self.sids_for(subject_key)
        for sid in sids:
            await self.destroy(sid)
        await self._redis.delete(self._subject_key(subject_key))
        return sids

    async def _write(self, session: Session, *, now: datetime | None = None) -> None:
        now = now or utcnow()
        # TTL is the idle window, refreshed on every load, so an abandoned
        # session expires on its own; the absolute deadline is checked from the
        # stored value because Redis can only express one expiry.
        remaining = (session.absolute_expiry - now).total_seconds()
        ttl = max(int(min(self._idle.total_seconds(), remaining)), 1)
        await self._redis.set(self._key(session.sid), session.to_json(), ex=ttl)

        index = self._subject_key(session.subject_key)
        await set_add(self._redis, index, session.sid)
        # The index expires with the longest-lived session that could be in it.
        # Without a TTL it would be the one structure here that grows forever,
        # accumulating a member per login for the life of the deployment.
        await expire_key(self._redis, index, max(int(self._absolute.total_seconds()), 1))

    def _key(self, sid: str) -> str:
        return f"{self._prefix}{sid}"

    def _subject_key(self, subject_key: str) -> str:
        digest = hashlib.sha256(subject_key.encode("utf-8")).hexdigest()
        return f"{SUBJECT_INDEX_PREFIX}{digest}"


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
