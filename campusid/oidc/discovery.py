"""The OpenID Provider metadata document (FR-OP-01).

What a client reads to configure itself. Built as a pure function of the issuer
so the endpoints in it cannot drift from the routes that serve them — everything
derives from one base URL, which is the same argument `Settings.saml_entity_id`
makes on the SAML side.

The document is also a set of promises, and two of them are narrower than most
providers advertise:

- `code_challenge_methods_supported` lists **S256 alone**. A provider that also
  advertises `plain` is telling every client that the weak option is acceptable,
  and some client library will take it.
- `response_types_supported` lists **`code` alone**. The implicit and hybrid
  flows put tokens in a URL fragment, where they reach browser history, referrer
  headers and any script on the page. They are deprecated in OAuth 2.1 and there
  is no reason for a new provider to carry them.

Advertising less than you support is harmless. Advertising more is a promise the
first client to rely on it discovers you cannot keep.
"""

from __future__ import annotations

from typing import Any, Final

from campusid.oidc.claims import SUPPORTED_CLAIMS, SUPPORTED_SCOPES
from campusid.oidc.jwt import RS256
from campusid.oidc.pkce import S256

PROTOCOL_CLAIMS: Final[tuple[str, ...]] = (
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
)
"""What every ID token carries regardless of scope. Advertised alongside the
identity claims so a client can see the whole set it may receive."""

TOKEN_ENDPOINT_AUTH_METHODS: Final[tuple[str, ...]] = (
    "client_secret_basic",
    "client_secret_post",
    "none",
)
"""`none` is for public and native clients, which hold no secret. It is not a
weaker option a confidential client may choose: the registration decides, and
`authenticate` refuses a confidential client that presents nothing."""


def discovery_document(issuer: str) -> dict[str, Any]:
    """The document served at `/.well-known/openid-configuration`."""
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth2/authorize",
        "token_endpoint": f"{issuer}/oauth2/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "end_session_endpoint": f"{issuer}/oauth2/logout",
        "pushed_authorization_request_endpoint": f"{issuer}/oauth2/par",
        "introspection_endpoint": f"{issuer}/oauth2/introspect",
        "revocation_endpoint": f"{issuer}/oauth2/revoke",
        "scopes_supported": list(SUPPORTED_SCOPES),
        "claims_supported": [*PROTOCOL_CLAIMS, *SUPPORTED_CLAIMS],
        # Code only. See the module docstring: the implicit and hybrid flows put
        # tokens in a URL fragment.
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        # Pairwise is this broker's default and the only mode a client can rely
        # on; an SP configured for `shared` gets a public subject, but that is a
        # per-SP policy decision rather than something a client may request.
        "subject_types_supported": ["pairwise", "public"],
        "id_token_signing_alg_values_supported": [RS256],
        "code_challenge_methods_supported": [S256],
        "token_endpoint_auth_methods_supported": list(TOKEN_ENDPOINT_AUTH_METHODS),
        "request_parameter_supported": False,
        "request_uri_parameter_supported": True,
        "require_request_uri_registration": False,
        "claims_parameter_supported": False,
        # FR-OP-12. `session_supported` says our logout token carries `sid`, so
        # a client can end one session rather than every session that person has.
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "frontchannel_logout_supported": False,
        "service_documentation": f"{issuer}/docs",
    }
