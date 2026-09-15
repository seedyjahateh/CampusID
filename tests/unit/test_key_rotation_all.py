"""Rotating every key this broker holds (NFR-SEC-06).

Four kinds of key material, and the requirement asks that each have a rotation
procedure with an overlap window. The overlap is the whole subject: a key nobody
else has seen can be replaced in one step, and none of these qualify. A peer has
pinned our SAML certificate in its metadata, a relying party has cached our JWKS,
and an SP has stored the pairwise identifiers our salt produced.

What differs between them is the *direction* of the overlap, which is what these
tests are mostly about:

**SAML signing** — we sign, the peer verifies. The new certificate has to be
published and picked up before anything is signed with it, or a peer that has not
refreshed rejects a login. Publish, wait, then use.

**SAML encryption** — the peer encrypts, we decrypt. The risk runs the other way:
a peer still holding the old certificate sends ciphertext only the old private
key opens. Publish the new one, keep accepting the old, retire it after the
window.

**OIDC signing** — we sign, the relying party verifies against a JWKS it refetches
on an unknown `kid`. That refetch is why this one can rotate in a single step and
the SAML signing key cannot.

**The pairwise salt** — no overlap exists, and saying so is the honest answer
rather than a gap. Every SP's identifier for every person is derived from it, so
changing it replaces each SP's entire user base with strangers simultaneously.
The test here asserts that property rather than a procedure, because it is what
makes the runbook's answer — a coordinated migration, not a rotation — correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from campusid import keys
from campusid.keys import KeySet, fingerprint, load_or_create_set
from campusid.oidc import keys as oidc_keys
from campusid.policy.pairwise import pairwise_id

SUBJECT = "https://broker.test"
PERSON = "6f9619ff-8b86-4d01-b42d-00cf4fc964ff"
SP = "https://lms.campus.test/shibboleth"
SCOPE = "campus.test"


@pytest.fixture
def key_dir(tmp_path: Path) -> Path:
    return tmp_path / "saml"


@pytest.fixture
def signing(key_dir: Path) -> KeySet:
    return load_or_create_set(key_dir, "sp-signing", SUBJECT)


# --- the shape of a set ------------------------------------------------------


def test_a_fresh_deployment_publishes_exactly_one_certificate(signing: KeySet) -> None:
    """Outside a rotation there is nothing to overlap, and metadata carrying two
    certificates when only one is in use is a question a peer's administrator
    has to ask somebody."""
    assert signing.additional == ()
    assert signing.certificates == (signing.active.certificate_pem,)


def test_loading_twice_returns_the_same_key(key_dir: Path) -> None:
    """Idempotent, because a restart that minted a new certificate would silently
    break every peer that had pinned the old one."""
    first = load_or_create_set(key_dir, "sp-signing", SUBJECT)
    second = load_or_create_set(key_dir, "sp-signing", SUBJECT)

    assert first.active.certificate_pem == second.active.certificate_pem


def test_a_fingerprint_names_one_certificate(signing: KeySet) -> None:
    """Derived from the material rather than assigned, so it cannot name the
    wrong key — and it is what a peer's administrator sees at their end."""
    value = fingerprint(signing.active.certificate_pem)

    assert len(value) == 64
    assert value == value.lower()
    assert set(value) <= set("0123456789abcdef")


# --- SAML signing: publish, then use -----------------------------------------


def test_staging_publishes_the_successor_without_using_it(key_dir: Path, signing: KeySet) -> None:
    """The first half of a signing rotation, and the half that must come first.

    A peer that has not refreshed our metadata would reject a request signed with
    a certificate it has never seen, so nothing may be signed with the new key
    until the old metadata has aged out everywhere.
    """
    before = signing.active.certificate_pem

    keys.stage(key_dir, "sp-signing", SUBJECT)
    after = load_or_create_set(key_dir, "sp-signing", SUBJECT)

    assert after.active.certificate_pem == before, "staging must not change what signs"
    assert len(after.certificates) == 2


def test_promoting_switches_what_signs_and_keeps_both_published(
    key_dir: Path, signing: KeySet
) -> None:
    """The second half. The outgoing certificate stays in metadata, because a
    peer mid-refresh may still be verifying against it — dropping it here would
    make this step the outage the overlap exists to prevent."""
    outgoing = signing.active.certificate_pem
    incoming = keys.stage(key_dir, "sp-signing", SUBJECT)

    rotated = keys.promote(key_dir, "sp-signing", fingerprint(incoming.certificate_pem))

    assert rotated.active.certificate_pem == incoming.certificate_pem
    assert set(rotated.certificates) == {outgoing, incoming.certificate_pem}


def test_retiring_ends_the_overlap(key_dir: Path, signing: KeySet) -> None:
    outgoing = fingerprint(signing.active.certificate_pem)
    incoming = keys.stage(key_dir, "sp-signing", SUBJECT)
    keys.promote(key_dir, "sp-signing", fingerprint(incoming.certificate_pem))

    final = keys.retire(key_dir, "sp-signing", outgoing)

    assert final.certificates == (incoming.certificate_pem,)
    assert final.active.certificate_pem == incoming.certificate_pem


def test_the_active_key_cannot_be_retired(key_dir: Path, signing: KeySet) -> None:
    """The mistake is one fingerprint away from the operation above, and its
    result is not a rotation that went wrong but a broker that cannot sign."""
    with pytest.raises(ValueError, match="active key"):
        keys.retire(key_dir, "sp-signing", fingerprint(signing.active.certificate_pem))


def test_promoting_an_unknown_fingerprint_is_refused(key_dir: Path, signing: KeySet) -> None:
    """A typo in a 64-character hex string is not a rare event, and the failure
    has to happen before anything moves."""
    with pytest.raises(KeyError):
        keys.promote(key_dir, "sp-signing", "0" * 64)


def test_a_rotation_survives_a_restart(key_dir: Path, signing: KeySet) -> None:
    """Every step writes through to the volume rather than to process state.

    An overlap that lived in memory would collapse on the next deployment, which
    is precisely when somebody restarts the broker to pick up a rotation.
    """
    incoming = keys.stage(key_dir, "sp-signing", SUBJECT)
    keys.promote(key_dir, "sp-signing", fingerprint(incoming.certificate_pem))

    reloaded = load_or_create_set(key_dir, "sp-signing", SUBJECT)

    assert reloaded.active.certificate_pem == incoming.certificate_pem
    assert len(reloaded.certificates) == 2


def test_a_half_written_pair_does_not_stop_the_broker_starting(
    key_dir: Path, signing: KeySet
) -> None:
    """A key with no certificate cannot be published and cannot be named, so it
    is skipped. Refusing to start would turn an interrupted rotation into an
    outage at the worst possible moment."""
    incoming = keys.stage(key_dir, "sp-signing", SUBJECT)
    stem = fingerprint(incoming.certificate_pem)
    (key_dir / "sp-signing-additional" / f"{stem}.crt").unlink()

    reloaded = load_or_create_set(key_dir, "sp-signing", SUBJECT)

    assert reloaded.certificates == (signing.active.certificate_pem,)


# --- SAML encryption: use, then unpublish ------------------------------------


def test_both_private_keys_are_held_during_an_encryption_overlap(key_dir: Path) -> None:
    """What the gate needs, and the reason the set exposes private keys at all.

    An IdP that has not refreshed our metadata is still encrypting to the
    outgoing certificate. Holding only the current key would make the overlap
    window an outage for exactly the peers it exists to protect.
    """
    current = load_or_create_set(key_dir, "sp-encryption", SUBJECT)
    incoming = keys.stage(key_dir, "sp-encryption", SUBJECT)

    rotated = load_or_create_set(key_dir, "sp-encryption", SUBJECT)

    assert set(rotated.private_keys) == {current.active.private_pem, incoming.private_pem}


def test_signing_and_encryption_are_separate_material(key_dir: Path) -> None:
    """Not one key used twice.

    Sharing would let a peer ask us to decrypt something we had signed, and the
    two rotate in opposite directions besides — one key could not be mid-rotation
    in both.
    """
    signing = load_or_create_set(key_dir, "sp-signing", SUBJECT)
    encryption = load_or_create_set(key_dir, "sp-encryption", SUBJECT)

    assert signing.active.private_pem != encryption.active.private_pem


def test_rotating_one_role_leaves_the_other_alone(key_dir: Path) -> None:
    signing = load_or_create_set(key_dir, "sp-signing", SUBJECT)
    load_or_create_set(key_dir, "sp-encryption", SUBJECT)

    keys.stage(key_dir, "sp-encryption", SUBJECT)

    assert load_or_create_set(key_dir, "sp-signing", SUBJECT).certificates == signing.certificates


# --- OIDC signing: one step, because clients refetch -------------------------


def test_the_outgoing_oidc_key_stays_in_the_published_jwks(tmp_path: Path) -> None:
    """Tokens already issued must keep verifying until they expire.

    This is why the OIDC rotation is one step where the SAML one is two: a
    relying party refetches the JWKS when it meets an unknown `kid`, so the new
    key needs no advance notice — but a token signed a minute ago still has to
    verify.
    """
    before = oidc_keys.load_or_create_key_set(tmp_path, key_size=2048)

    after = oidc_keys.rotate(tmp_path, key_size=2048)

    assert after.active.kid != before.active.kid
    assert before.active.kid in after.verification_keys
    assert {key["kid"] for key in after.as_jwks()["keys"]} == {after.active.kid, before.active.kid}


def test_retiring_an_oidc_key_is_a_separate_decision(tmp_path: Path) -> None:
    """Deliberately not on a timer.

    Doing it automatically means a clock problem or one long-lived refresh token
    turns into every session failing at once, so an operator decides when the
    longest-lived token bearing that `kid` has expired.
    """
    before = oidc_keys.load_or_create_key_set(tmp_path, key_size=2048)
    oidc_keys.rotate(tmp_path, key_size=2048)

    final = oidc_keys.retire(tmp_path, before.active.kid)

    assert before.active.kid not in final.verification_keys


# --- the pairwise salt: not a rotation ---------------------------------------


def test_a_new_salt_changes_every_identifier_at_every_sp() -> None:
    """The property that makes this a migration rather than a rotation.

    There is no overlap to design: an SP stores the identifier it was given and
    has no way to be told that a different string now means the same person.
    """
    old = pairwise_id(b"the-old-salt", PERSON, SP, SCOPE)
    new = pairwise_id(b"a-different-salt", PERSON, SP, SCOPE)

    assert old != new


def test_the_same_salt_gives_the_same_identifier_forever() -> None:
    """Which is what the SP is relying on, and why the value is backed up with
    the database rather than treated as configuration."""
    first = pairwise_id(b"the-salt", PERSON, SP, SCOPE)
    second = pairwise_id(b"the-salt", PERSON, SP, SCOPE)

    assert first == second


def test_one_salt_still_gives_each_sp_a_different_identifier() -> None:
    """The property the salt exists for, asserted here because a migration that
    got it wrong would be indistinguishable from a successful one until two SPs
    compared notes."""
    lms = pairwise_id(b"the-salt", PERSON, SP, SCOPE)
    library = pairwise_id(b"the-salt", PERSON, "https://library.campus.test/sp", SCOPE)

    assert lms != library
