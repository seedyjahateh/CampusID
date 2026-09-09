"""Signing key persistence and rotation (FR-OP-02).

The requirement is one sentence — "two keys during rotation, tokens signed with
the old `kid` verify until expiry" — and every test here is about what happens
either side of that overlap.
"""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from campusid.oidc import keys
from campusid.oidc.jwt import JwtError, decode, encode

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
KEY_SIZE = 2048  # smaller than production, so the suite is not dominated by RSA


def _claims() -> dict[str, object]:
    return {
        "iss": "https://broker.test",
        "aud": "campus-portal",
        "sub": "subject",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
    }


def _verifies(token: str, key_set: keys.KeySet) -> bool:
    try:
        decode(
            token,
            key_set.verification_keys,
            issuer="https://broker.test",
            audience="campus-portal",
            now=NOW,
        )
    except JwtError:
        return False
    return True


# --- persistence -----------------------------------------------------------


def test_a_key_set_is_created_on_first_use(tmp_path: Path) -> None:
    key_set = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    assert (tmp_path / keys.ACTIVE_KEY_FILE).is_file()
    assert key_set.retiring == ()


def test_the_same_key_comes_back_on_restart(tmp_path: Path) -> None:
    """An ephemeral signing key invalidates every outstanding token the moment
    the process comes back, and every client that cached our JWKS starts
    refusing tokens it should honour."""
    first = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    second = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    assert first.active.kid == second.active.kid


def test_a_token_survives_a_restart(tmp_path: Path) -> None:
    key_set = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)
    token = encode(_claims(), key_set.active)

    assert _verifies(token, keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE))


def test_the_private_key_is_not_world_readable(tmp_path: Path) -> None:
    """The mode is set at creation rather than afterwards, so there is no window
    in which the key exists and is readable — the same reasoning as the SAML
    keypair."""
    keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    mode = (tmp_path / keys.ACTIVE_KEY_FILE).stat().st_mode

    assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)


def test_something_that_is_not_an_rsa_key_is_refused(tmp_path: Path) -> None:
    """A truncated or replaced key file must fail loudly at startup rather than
    producing an obscure error on the first token request."""
    (tmp_path / keys.ACTIVE_KEY_FILE).write_bytes(b"not a key")

    with pytest.raises(ValueError):
        keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)


# --- rotation --------------------------------------------------------------


def test_rotation_mints_a_new_active_key(tmp_path: Path) -> None:
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    after = keys.rotate(tmp_path, key_size=KEY_SIZE)

    assert after.active.kid != before.active.kid


def test_both_keys_are_published_during_a_rotation(tmp_path: Path) -> None:
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    after = keys.rotate(tmp_path, key_size=KEY_SIZE)

    published = {entry["kid"] for entry in after.as_jwks()["keys"]}
    assert published == {before.active.kid, after.active.kid}


def test_a_token_signed_before_a_rotation_still_verifies(tmp_path: Path) -> None:
    """The requirement, as one assertion. Retiring a key at the moment of
    rotation would break every session holding a token minted a second
    earlier."""
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)
    token = encode(_claims(), before.active)

    assert _verifies(token, keys.rotate(tmp_path, key_size=KEY_SIZE))


def test_a_rotation_survives_a_restart(tmp_path: Path) -> None:
    """The retiring key is on disk, not in memory: a restart during the overlap
    window must not end the overlap."""
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)
    token = encode(_claims(), before.active)
    keys.rotate(tmp_path, key_size=KEY_SIZE)

    assert _verifies(token, keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE))


def test_new_tokens_are_signed_with_the_new_key(tmp_path: Path) -> None:
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    after = keys.rotate(tmp_path, key_size=KEY_SIZE)

    assert after.active.kid != before.active.kid
    assert before.active.kid in {key.kid for key in after.retiring}


def test_two_rotations_keep_both_predecessors(tmp_path: Path) -> None:
    """Nothing is dropped implicitly. An operator who rotates twice in a week
    has not silently ended the first overlap."""
    first = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)
    second = keys.rotate(tmp_path, key_size=KEY_SIZE)
    third = keys.rotate(tmp_path, key_size=KEY_SIZE)

    assert {key.kid for key in third.retiring} == {first.active.kid, second.active.kid}


# --- retirement ------------------------------------------------------------


def test_retiring_a_key_ends_its_overlap(tmp_path: Path) -> None:
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)
    token = encode(_claims(), before.active)
    keys.rotate(tmp_path, key_size=KEY_SIZE)

    after = keys.retire(tmp_path, before.active.kid)

    assert not _verifies(token, after)
    assert after.retiring == ()


def test_retirement_is_a_separate_act_from_rotation(tmp_path: Path) -> None:
    """Deliberately not automatic. Dropping a retired key on a timer means a
    clock problem or a long-lived refresh token turns into every session
    breaking at once, so it is a decision an operator makes."""
    before = keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    after = keys.rotate(tmp_path, key_size=KEY_SIZE)

    assert before.active.kid in {key.kid for key in after.retiring}


def test_retiring_an_unknown_key_is_harmless(tmp_path: Path) -> None:
    """Idempotent, so a runbook step that is run twice does not fail the second
    time and send somebody looking for a problem that is not there."""
    keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    assert keys.retire(tmp_path, "never-existed").retiring == ()


@pytest.mark.parametrize("kid", ["../oidc-active", "a/b", "a\\b", "", ".", ".."])
def test_a_kid_that_is_not_a_filename_is_refused(tmp_path: Path, kid: str) -> None:
    """A thumbprint is base64url and never contains a separator, so this cannot
    happen — asserted rather than assumed, because a `kid` reaching the
    filesystem with one in it would be a path traversal whose payload is our own
    key material."""
    keys.load_or_create_key_set(tmp_path, key_size=KEY_SIZE)

    with pytest.raises(ValueError, match="filename"):
        keys.retire(tmp_path, kid)

    assert (tmp_path / keys.ACTIVE_KEY_FILE).is_file()
