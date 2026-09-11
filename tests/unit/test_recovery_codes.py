"""Generating and hashing recovery codes (FR-MFA-05).

The factor of last resort, and the only credential here that gets written down.
Every property below is about that: enough entropy that the paper is the weak
link rather than the code, a hash that stays expensive if part of one leaks, and
a typed form forgiving enough that somebody reading it off a printout is not told
they are wrong when they are not.
"""

from __future__ import annotations

import pytest

from campusid.mfa.recovery import (
    ALPHABET,
    CODE_BYTES,
    COUNT,
    MEMORY_COST,
    PARALLELISM,
    TIME_COST,
    generate,
    hash_code,
    matches,
    normalise,
)

pytestmark = pytest.mark.security


# --- the codes themselves ---------------------------------------------------


def test_ten_codes_are_issued() -> None:
    """Enough that losing a phone is survivable, few enough that a sheet of them
    is not a permanent second password."""
    assert len(generate()) == COUNT == 10


def test_the_codes_are_all_different() -> None:
    assert len(set(generate())) == COUNT


def test_two_sheets_share_nothing() -> None:
    assert not set(generate()) & set(generate())


def test_a_code_carries_eighty_bits() -> None:
    """A recovery code has no expiry and no window of its own, so the guessing
    bound has to come from the code."""
    digits = normalise(generate()[0])

    assert len(digits) == CODE_BYTES * 8 // 5
    assert CODE_BYTES * 8 == 80


def test_the_alphabet_avoids_the_confusable_letters() -> None:
    """A code read aloud or copied by hand is where transcription errors come
    from, and zero-versus-O is the classic one. RFC 4648's base32 alphabet
    contains all three of these, which is why this is not that."""
    for confusable in "ILOU":
        assert confusable not in ALPHABET


@pytest.mark.parametrize(
    ("typed", "meant"), [("O", "0"), ("I", "1"), ("L", "1"), ("o", "0"), ("l", "1")]
)
def test_a_confusable_letter_is_read_as_what_it_looks_like(typed: str, meant: str) -> None:
    """Somebody who types the letter O meant the digit, because the letter is not
    in the alphabet the code came from."""
    assert normalise(typed) == meant


def test_a_code_is_grouped_for_reading() -> None:
    code = generate()[0]

    assert "-" in code
    assert all(len(group) == 4 for group in code.split("-"))


def test_every_character_is_from_the_alphabet() -> None:
    for code in generate():
        assert set(normalise(code)) <= set(ALPHABET)


# --- what the person may type -----------------------------------------------


@pytest.mark.parametrize(
    "typed",
    ["ABCD-EFGH-2345-6789", "abcd-efgh-2345-6789", "ABCDEFGH23456789", "ABCD EFGH 2345 6789"],
)
def test_presentation_is_not_part_of_the_secret(typed: str) -> None:
    """Case and grouping are presentation. Refusing them teaches somebody the
    code is wrong when it is not."""
    assert normalise(typed) == "ABCDEFGH23456789"


def test_normalising_drops_nothing_that_carries_meaning() -> None:
    original = generate()[0]

    assert normalise(original) == original.replace("-", "")


# --- hashing ----------------------------------------------------------------


async def test_a_code_verifies_against_its_hash() -> None:
    code = generate()[0]

    assert await matches(await hash_code(code), code) is True


async def test_another_code_does_not() -> None:
    first, second = generate()[:2]

    assert await matches(await hash_code(first), second) is False


async def test_the_typed_form_verifies() -> None:
    """The stored hash is of the normalised code, so what the person types has
    to be normalised the same way on the way in."""
    code = generate()[0]

    assert await matches(await hash_code(code), code.replace("-", "").lower()) is True


async def test_the_hash_is_argon2id() -> None:
    """Named rather than left to a library default that may move. The parameters
    are a security decision, and a quiet change to them is invisible until
    somebody has the database."""
    stored = await hash_code(generate()[0])

    assert stored.startswith("$argon2id$")


async def test_the_parameters_are_the_ones_that_were_chosen() -> None:
    """Pinned because they are a security decision, and a quiet change to them is
    invisible until somebody has the database. OWASP's first recommended
    configuration: 19 MiB, two passes, one lane."""
    stored = await hash_code(generate()[0])

    assert f"m={MEMORY_COST},t={TIME_COST},p={PARALLELISM}" in stored


async def test_two_hashes_of_one_code_differ() -> None:
    """Salted. Identical hashes would let somebody with the table see that two
    people share a code, and make a precomputed attack worth mounting."""
    code = generate()[0]

    assert await hash_code(code) != await hash_code(code)


async def test_the_hash_does_not_contain_the_code() -> None:
    code = generate()[0]

    assert normalise(code) not in await hash_code(code)


async def test_a_corrupt_stored_hash_is_a_mismatch() -> None:
    """It means that row cannot authenticate anybody. Raising would turn one bad
    row into a failure for every code the person has."""
    assert await matches("not a hash", generate()[0]) is False


async def test_an_empty_code_matches_nothing() -> None:
    assert await matches(await hash_code(generate()[0]), "") is False
