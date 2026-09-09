"""Redirect URI matching and client registration (FR-OP-05).

The PRD asks for eight near-miss cases. They are all here, and they are all the
same case: a matcher that is anything other than string equality disagrees with
an attacker about where a URL ends, and the disagreement is worth an
authorization code.
"""

from __future__ import annotations

import pytest

from campusid.errors import ReasonCode
from campusid.oidc.clients import (
    ClientType,
    OidcClient,
    generate_secret,
    hash_secret,
)
from campusid.oidc.errors import INVALID_CLIENT, INVALID_REQUEST, INVALID_SCOPE, OAuthError

pytestmark = pytest.mark.security

REGISTERED = "https://portal.campus.test/oidc/callback"
SCOPES = frozenset({"openid", "profile", "email"})


@pytest.fixture
def client() -> OidcClient:
    return OidcClient(
        client_id="campus-portal",
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(REGISTERED,),
        allowed_scopes=SCOPES,
        secret_hash=hash_secret("s" * 43),
    )


def test_the_registered_uri_is_accepted(client: OidcClient) -> None:
    assert client.validated_redirect_uri(REGISTERED) == REGISTERED


@pytest.mark.parametrize(
    ("candidate", "why"),
    [
        (REGISTERED + "/", "a trailing slash is a different path"),
        (REGISTERED.replace("/callback", "/Callback"), "paths are case-sensitive"),
        (REGISTERED + "?next=https://evil.test", "an added query parameter"),
        (REGISTERED + ".evil.test", "what a prefix matcher would admit"),
        ("https://portal.campus.test.evil.test/oidc/callback", "a suffixed host"),
        ("https://portal.campus.test@evil.test/oidc/callback", "userinfo hiding the real host"),
        ("http://portal.campus.test/oidc/callback", "downgraded to http"),
        ("https://portal.campus.test/oidc/callback/../../elsewhere", "a traversal that normalises"),
        ("https://evil.test/oidc/callback", "an unrelated host entirely"),
    ],
)
def test_near_misses_are_refused(client: OidcClient, candidate: str, why: str) -> None:
    with pytest.raises(OAuthError) as raised:
        client.validated_redirect_uri(candidate)

    assert raised.value.reason is ReasonCode.REDIRECT_URI_MISMATCH, why


def test_a_missing_redirect_uri_is_refused(client: OidcClient) -> None:
    with pytest.raises(OAuthError, match="required"):
        client.validated_redirect_uri(None)


def test_a_redirect_uri_error_is_never_redirected(client: OidcClient) -> None:
    """The one refusal that must land on our own error page.

    Reporting "your redirect_uri is wrong" *to* that redirect_uri would forward
    the user to the attacker's URL with the broker's blessing, which is the open
    redirect the exact-match rule exists to prevent.
    """
    with pytest.raises(OAuthError) as raised:
        client.validated_redirect_uri("https://evil.test/cb")

    assert raised.value.redirectable is False
    assert raised.value.error == INVALID_REQUEST


# --- the loopback exception ------------------------------------------------


@pytest.fixture
def native() -> OidcClient:
    return OidcClient(
        client_id="campus-desktop",
        client_type=ClientType.NATIVE,
        redirect_uris=("http://127.0.0.1/oidc/callback", "com.campus.app:/callback"),
        allowed_scopes=SCOPES,
    )


@pytest.mark.parametrize("port", [1024, 49152, 65535])
def test_a_native_client_may_vary_the_loopback_port(native: OidcClient, port: int) -> None:
    """RFC 8252 §7.3: a desktop app binds an ephemeral port at launch, so the
    port genuinely cannot be known at registration. Only the port."""
    candidate = f"http://127.0.0.1:{port}/oidc/callback"

    assert native.validated_redirect_uri(candidate) == candidate


@pytest.mark.parametrize(
    "candidate",
    [
        "http://127.0.0.1:5000/oidc/other",
        "http://127.0.0.1:5000/oidc/callback?next=https://evil.test",
        "http://127.0.0.2:5000/oidc/callback",
        "http://localhost:5000/oidc/callback",
        "https://127.0.0.1:5000/oidc/callback",
    ],
)
def test_the_loopback_allowance_covers_only_the_port(native: OidcClient, candidate: str) -> None:
    """`localhost` is in this list on purpose. RFC 8252 §8.3 excludes it because
    it resolves through the hosts file and DNS, so another process on the
    machine can win the race and be handed the code."""
    with pytest.raises(OAuthError):
        native.validated_redirect_uri(candidate)


def test_a_confidential_client_gets_no_loopback_allowance() -> None:
    """The allowance exists because an installed app cannot know its port; a
    server-side client can. It is refused a rung earlier than expected — the
    plain-http loopback URI cannot be *registered* at all — which is the
    stronger of the two places to stop it, since the looser matching rule then
    has nothing to match against.
    """
    with pytest.raises(ValueError, match="must use https"):
        OidcClient(
            client_id="server-side",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=("http://127.0.0.1/cb",),
            allowed_scopes=SCOPES,
            secret_hash=hash_secret("s" * 43),
        )


def test_a_native_client_may_register_a_private_use_scheme(native: OidcClient) -> None:
    assert native.validated_redirect_uri("com.campus.app:/callback") == "com.campus.app:/callback"


# --- registration-time checks ----------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "/oidc/callback",
        "https://portal.campus.test/cb#fragment",
        "http://portal.campus.test/cb",
        "com.campus.app:/callback",
        "https:///cb",
    ],
)
def test_an_unsafe_redirect_uri_cannot_be_registered(uri: str) -> None:
    """Registration is the only moment a human is looking. After it, the URI is
    an exact-matched, permanently trusted destination."""
    with pytest.raises(ValueError):
        OidcClient(
            client_id="c",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(uri,),
            allowed_scopes=SCOPES,
            secret_hash=hash_secret("s" * 43),
        )


def test_a_client_with_no_redirect_uri_cannot_be_registered() -> None:
    with pytest.raises(ValueError, match="no redirect URI"):
        OidcClient(
            client_id="c",
            client_type=ClientType.PUBLIC,
            redirect_uris=(),
            allowed_scopes=SCOPES,
        )


def test_a_confidential_client_must_have_a_secret() -> None:
    with pytest.raises(ValueError, match="no secret"):
        OidcClient(
            client_id="c",
            client_type=ClientType.CONFIDENTIAL,
            redirect_uris=(REGISTERED,),
            allowed_scopes=SCOPES,
        )


def test_a_public_client_cannot_hold_a_secret() -> None:
    """A secret shipped to a browser is not a secret, and treating one as proof
    of identity is worse than having none."""
    with pytest.raises(ValueError, match="cannot hold a secret"):
        OidcClient(
            client_id="c",
            client_type=ClientType.PUBLIC,
            redirect_uris=(REGISTERED,),
            allowed_scopes=SCOPES,
            secret_hash=hash_secret("s" * 43),
        )


def test_a_client_must_be_allowed_the_openid_scope() -> None:
    with pytest.raises(ValueError, match="openid"):
        OidcClient(
            client_id="c",
            client_type=ClientType.PUBLIC,
            redirect_uris=(REGISTERED,),
            allowed_scopes=frozenset({"profile"}),
        )


# --- client authentication -------------------------------------------------


def test_a_correct_secret_authenticates() -> None:
    secret = generate_secret()
    client = OidcClient(
        client_id="c",
        client_type=ClientType.CONFIDENTIAL,
        redirect_uris=(REGISTERED,),
        allowed_scopes=SCOPES,
        secret_hash=hash_secret(secret),
    )

    client.authenticate(secret)


@pytest.mark.parametrize("presented", [None, "", "wrong"])
def test_a_wrong_secret_is_refused(client: OidcClient, presented: str | None) -> None:
    with pytest.raises(OAuthError) as raised:
        client.authenticate(presented)

    assert raised.value.reason is ReasonCode.CLIENT_AUTHENTICATION_FAILED
    assert raised.value.error == INVALID_CLIENT


def test_a_public_client_cannot_authenticate(native: OidcClient) -> None:
    """It holds no secret, so anything it presents came from somewhere else."""
    with pytest.raises(OAuthError, match="not a confidential client"):
        native.authenticate("anything")


def test_a_generated_secret_carries_full_entropy() -> None:
    """The argument for hashing client secrets with plain SHA-256 rests on them
    being machine-generated and long. If that stopped being true, the hash
    choice would need to change with it."""
    assert len(generate_secret()) >= 43
    assert generate_secret() != generate_secret()


# --- scopes ----------------------------------------------------------------


def test_permitted_scopes_are_granted(client: OidcClient) -> None:
    assert client.granted_scopes("openid email") == frozenset({"openid", "email"})


def test_an_unpermitted_scope_is_refused_not_dropped(client: OidcClient) -> None:
    """Silently narrowing lets a client believe it holds `admin` and act on a
    claim that was never released."""
    with pytest.raises(OAuthError) as raised:
        client.granted_scopes("openid admin")

    assert raised.value.reason is ReasonCode.SCOPE_NOT_PERMITTED
    assert raised.value.error == INVALID_SCOPE


@pytest.mark.parametrize("requested", [None, "", "profile email"])
def test_a_request_without_openid_is_refused(client: OidcClient, requested: str | None) -> None:
    """Without `openid` this is plain OAuth and no ID token is issued — which
    is not what a client asking this broker for a login means."""
    with pytest.raises(OAuthError, match="openid"):
        client.granted_scopes(requested)


def test_a_scope_error_may_be_reported_to_the_client(client: OidcClient) -> None:
    """Unlike a redirect URI error: by the time scopes are read the URI has been
    matched against the registration, so the destination is one we trust."""
    with pytest.raises(OAuthError) as raised:
        client.granted_scopes("openid admin")

    assert raised.value.redirectable is True
