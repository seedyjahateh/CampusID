"""Opening a connection to the directory (FR-DIR-01).

One place where the transport decision is made, because reads and writes must
not be able to disagree about it. A writer that bound in the clear while the
reader used TLS would be a hole nobody would look for, since the reader is the
one anybody thinks about.

**StartTLS before the bind, always.** Afterwards would mean sending the service
account's password in the clear and then encrypting the rest of a session whose
credential was already gone.

**A connection per operation rather than a pool.** `ldap3`'s pooling is bound to
its own threading model, and this crosses a thread boundary already; two
mechanisms sharing responsibility for connection lifetime is how a connection
ends up used from two threads at once. The cost is a handshake per login, which
the group cache absorbs.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Any, Final

CONNECT_TIMEOUT: Final = 5
"""Seconds. A directory that is slow is, for a login, a directory that is down.

A whole number rather than a float: ldap3 packs the receive timeout into a
`SO_RCVTIMEO` socket option, which refuses anything else with a message about
an integer argument that names neither the option nor the value.
"""

LOCKED_FOREVER: Final = "000001010000Z"
"""The ppolicy sentinel for an account locked with no expiry.

A real timestamp would unlock the account when it passed, which for a
deprovisioning is precisely wrong — the whole point is that it does not come
back on its own.
"""


class DirectoryUnavailable(Exception):
    """The directory could not be reached or would not answer.

    Distinct from "the entry is not there": one is our problem and the other is
    an answer. Conflating them is how an outage becomes a silent mass
    deprovisioning.
    """


@dataclass(frozen=True, slots=True)
class Connector:
    """Everything needed to open one bound connection."""

    url: str
    bind_dn: str = ""
    bind_password: str = ""
    start_tls: bool = True
    allow_plaintext: bool = False

    def __call__(self) -> Any:
        from ldap3 import ALL, Connection, Server, Tls

        secure = self.url.startswith("ldaps://")
        if not secure and not self.start_tls and not self.allow_plaintext:
            # Refused here rather than at configuration time as well, because a
            # connector can be built in code and the transport decision should
            # fail at the point it would otherwise be made silently.
            raise DirectoryUnavailable(
                "refusing a plaintext bind; set ldap_start_tls or ldap_allow_plaintext"
            )

        tls = Tls(validate=ssl.CERT_REQUIRED) if secure or self.start_tls else None
        server = Server(self.url, get_info=ALL, tls=tls, connect_timeout=CONNECT_TIMEOUT)
        connection = Connection(
            server,
            user=self.bind_dn or None,
            password=self.bind_password or None,
            auto_bind=False,
            raise_exceptions=True,
            receive_timeout=CONNECT_TIMEOUT,
        )
        connection.open()
        if not secure and self.start_tls:
            connection.start_tls()
        connection.bind()
        return connection
