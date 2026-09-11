"""Reading the directory (FR-DIR-01, 04, 05, 08).

One search per login and one membership expansion behind it, against a server
that is not ours and will not always be there.

**Synchronous underneath, awaited above.** `ldap3` is pure Python and blocking,
so every call runs in a worker thread. That is a deliberate trade: an async LDAP
client means Twisted or a hand-written ASN.1 codec, and this integration does one
search per login. Blocking the event loop on it would be the actual mistake, and
`to_thread` is what stops that.

**Every search is paged.** RFC 2696's simple paged results control, 500 entries a
page. A directory with fifty thousand people answers an unpaged search by either
truncating it silently at the server's `sizelimit` or by trying to send all of
it; the first is worse, because the answer looks complete.

**A directory outage degrades rather than fails.** FR-DIR-08: group membership is
cached, and when the server is unreachable the cached answer is used, the session
is marked degraded, and the fact is audited. The alternative is that a directory
restart logs out the campus. What is *not* cached is the absence of membership —
a cache miss during an outage means we do not know, and "we do not know" must not
be answered as "no groups", which would silently revoke access.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final

from campusid.directory.connection import Connector, DirectoryUnavailable
from campusid.directory.groups import Expansion, expand
from campusid.directory.profiles import ACCOUNT_DISABLED_BIT, DirectoryProfile
from campusid.logging import get_logger

__all__ = ["CACHE_PREFIX", "PAGE_SIZE", "DirectoryClient", "DirectoryUnavailable", "DirectoryUser"]

log = get_logger(__name__)

PAGE_SIZE: Final = 500
"""FR-DIR-05. Large enough that a page is worth its round trip, small enough
that a page fits comfortably under any server's own limits."""

CACHE_TTL: Final = timedelta(minutes=15)
"""FR-DIR-08's window. Long enough to ride out a directory restart, short enough
that a revoked membership stops granting access within a coffee break."""

CACHE_PREFIX: Final = "directory:groups:"


@dataclass(frozen=True, slots=True)
class DirectoryUser:
    """One entry, in our vocabulary rather than the directory's."""

    dn: str
    immutable_id: str
    login: str
    mail: str | None = None
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    member_of: tuple[str, ...] = ()
    disabled: bool = False
    """Whether the directory considers this account disabled.

    Read from the same search that found them. Reconciliation walks every person
    and asking a second time for each would turn a report into an afternoon.
    """


@dataclass(frozen=True, slots=True)
class GroupResult:
    """Membership, and how confident we are in it."""

    groups: frozenset[str] = field(default_factory=frozenset)
    direct: frozenset[str] = field(default_factory=frozenset)
    degraded: bool = False
    """Answered from cache because the directory was unreachable. Carried into
    the session so a later decision can tell a fresh answer from a stale one,
    which FR-DIR-08 asks be surfaced rather than smoothed over."""

    truncated: bool = False


class DirectoryClient:
    """Searches and membership lookups against one directory."""

    def __init__(
        self,
        *,
        profile: DirectoryProfile,
        url: str,
        base_dn: str,
        bind_dn: str = "",
        bind_password: str = "",
        start_tls: bool = True,
        allow_plaintext: bool = False,
        cache: Any = None,
        connector: Any = None,
    ) -> None:
        self._profile = profile
        self._base_dn = base_dn
        self._cache = cache
        # Injected so the client is testable without a server. The default is
        # the real one; a test supplies a fake.
        self._connector = connector or Connector(
            url=url,
            bind_dn=bind_dn,
            bind_password=bind_password,
            start_tls=start_tls,
            allow_plaintext=allow_plaintext,
        )

    # --- reading ----------------------------------------------------------

    async def find_user(self, login: str) -> DirectoryUser | None:
        """One person, by whatever this directory calls a login.

        Returns None when the search succeeded and matched nobody, and raises
        when it could not be run. A caller that cannot tell those apart will
        eventually treat an outage as a departure.
        """
        entries = await self._search(
            self._base_dn,
            self._profile.user_filter(login),
            list(self._profile.attributes()),
        )
        if not entries:
            return None
        if len(entries) > 1:
            # Two entries answering to one login is a directory that cannot say
            # who somebody is, and picking the first would pick differently on
            # a different day.
            log.warning("directory.user.ambiguous", login=login, matches=len(entries))
            return None
        return self._to_user(entries[0])

    async def groups_for(self, user: DirectoryUser) -> GroupResult:
        """Every group this person is in, nested membership included.

        Falls back to the cache when the directory is unreachable, and says so.
        """
        try:
            direct = await self._direct_groups(user)
            expansion = await expand(direct, self._parents_of)
        except DirectoryUnavailable:
            cached = await self._cached(user.immutable_id)
            if cached is None:
                # A miss during an outage means we do not know. Answering "no
                # groups" would silently revoke access campus-wide the moment
                # the directory blinked.
                log.warning("directory.degraded.no_cache", user=user.immutable_id)
                raise
            log.warning("directory.degraded.served_from_cache", user=user.immutable_id)
            return GroupResult(groups=cached, direct=cached, degraded=True)

        await self._remember(user.immutable_id, expansion)
        return GroupResult(
            groups=expansion.groups,
            direct=expansion.direct,
            truncated=expansion.truncated,
        )

    async def healthy(self) -> bool:
        """Whether the directory is answering, for `/healthz` (FR-DIR-08).

        A search rather than a connect: a server that accepts TCP and refuses to
        bind is down for every purpose we have, and a probe that only connects
        would report it healthy.
        """
        try:
            await self._search(self._base_dn, "(objectClass=*)", ["1.1"], limit=1)
        except DirectoryUnavailable:
            return False
        return True

    # --- membership -------------------------------------------------------

    async def _direct_groups(self, user: DirectoryUser) -> list[str]:
        """`memberOf` where the directory maintains it, a reverse search where
        it does not (FR-DIR-04).

        The overlay that provides `memberOf` is optional in OpenLDAP and many
        deployments do not enable it, so the fallback is the common case rather
        than a corner.
        """
        if user.member_of:
            return list(user.member_of)

        entries = await self._search(
            self._base_dn,
            self._profile.group_members_filter(user.dn),
            ["1.1"],
        )
        return [str(entry["dn"]) for entry in entries]

    async def _parents_of(self, group_dn: str) -> list[str]:
        """Which groups this group is itself in."""
        entries = await self._search(
            self._base_dn,
            self._profile.group_members_filter(group_dn),
            ["1.1"],
        )
        return [str(entry["dn"]) for entry in entries]

    # --- the cache --------------------------------------------------------

    async def _cached(self, key: str) -> frozenset[str] | None:
        if self._cache is None:
            return None
        raw = await self._cache.get(f"{CACHE_PREFIX}{key}")
        if raw is None:
            return None
        try:
            return frozenset(json.loads(raw))
        except (TypeError, ValueError):
            # A cache entry we cannot read is a cache miss, not an error: the
            # directory is the source of truth and this is only a shortcut.
            return None

    async def _remember(self, key: str, expansion: Expansion) -> None:
        """Cache a *successful* expansion only.

        A truncated one is not cached: it is an incomplete answer, and caching
        it would keep somebody's missing memberships missing for fifteen minutes
        after whatever caused the truncation was fixed.
        """
        if self._cache is None or expansion.truncated:
            return
        await self._cache.set(
            f"{CACHE_PREFIX}{key}",
            json.dumps(sorted(expansion.groups)),
            ex=int(CACHE_TTL.total_seconds()),
        )

    # --- the wire ---------------------------------------------------------

    async def _search(
        self, base: str, search_filter: str, attributes: list[str], *, limit: int = 0
    ) -> list[dict[str, Any]]:
        """Run a paged search in a worker thread.

        Every failure becomes `DirectoryUnavailable`. The caller's decision is
        the same for a refused connection, a dropped one and a server that
        answered with an error, and distinguishing them here would push a
        three-way branch into every call site to no purpose.
        """
        try:
            return await asyncio.to_thread(
                self._search_blocking, base, search_filter, attributes, limit
            )
        except DirectoryUnavailable:
            raise
        except Exception as exc:
            log.warning("directory.search_failed", error=str(exc), filter=search_filter)
            raise DirectoryUnavailable(str(exc)) from exc

    def _search_blocking(
        self, base: str, search_filter: str, attributes: list[str], limit: int
    ) -> list[dict[str, Any]]:
        connection = self._connector()
        try:
            entries = connection.extend.standard.paged_search(
                search_base=base,
                search_filter=search_filter,
                attributes=attributes,
                paged_size=PAGE_SIZE,
                generator=False,
            )
        finally:
            connection.unbind()

        found = [entry for entry in entries if entry.get("type") == "searchResEntry"]
        return found[:limit] if limit else found

    def _to_user(self, entry: dict[str, Any]) -> DirectoryUser:
        """Convert one entry into our vocabulary at the boundary.

        Nothing above this line sees an ldap3 type or a directory's attribute
        name, which is what keeps the untyped dependency one file wide.
        """
        attributes = entry.get("attributes", {})
        profile = self._profile
        return DirectoryUser(
            dn=str(entry["dn"]),
            immutable_id=_one(attributes, profile.immutable_id) or str(entry["dn"]),
            login=_one(attributes, *profile.login_attributes) or "",
            mail=_one(attributes, profile.mail),
            display_name=_one(attributes, profile.display_name),
            given_name=_one(attributes, profile.given_name),
            surname=_one(attributes, profile.surname),
            member_of=tuple(_many(attributes, profile.member_of)),
            disabled=self._disabled(attributes),
        )

    def _disabled(self, attributes: dict[str, Any]) -> bool:
        """Whether this directory says the account is off.

        Two shapes, and they are read differently. Active Directory keeps a bit
        field, so the question is whether one bit is set — a truthiness check
        would call every enabled account disabled, because a normal account is
        512. OpenLDAP writes a lock timestamp, so the question is whether there
        is one at all.
        """
        profile = self._profile
        if profile.disabled_flag:
            raw = _one(attributes, profile.disabled_flag)
            try:
                return bool(int(raw or 0) & ACCOUNT_DISABLED_BIT)
            except ValueError:
                return False
        return bool(_one(attributes, profile.lock_attribute))


def _one(attributes: dict[str, Any], *names: str) -> str | None:
    """The first value of the first attribute that has one.

    LDAP has no single-valued reads: everything is a list, except when a server
    decides to send a bare string, which several do. Both shapes are handled
    here so no caller has to.
    """
    for name in names:
        value = attributes.get(name)
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if value not in (None, ""):
            return str(value)
    return None


def _many(attributes: dict[str, Any], name: str) -> list[str]:
    value = attributes.get(name)
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [
        item.decode("utf-8", "replace") if isinstance(item, bytes) else str(item) for item in value
    ]
