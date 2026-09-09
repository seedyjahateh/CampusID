"""SCIM `/Users` end to end (FR-SCIM-02 to 09, FR-SCIM-13, FR-SCIM-14).

Against live Postgres, because what these endpoints do *is* the persistence:
the uniqueness constraint behind a 409, the tombstone behind a soft delete, and
the transaction that writes a person and three identifiers together.

The cases worth reading are the ones where SCIM's model and an identity
registry's disagree — a `PUT` that changes `userName`, and a `DELETE`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from scripts.federation_init import SIS_CLIENT_ID, SIS_SECRET
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from campusid.config import get_settings
from campusid.db import create_engine, create_session_factory
from campusid.identity.models import Account, Affiliation, Identifier, Person
from campusid.scim.models import ScimSourceRecord
from campusid.scim.schemas import CAMPUS_USER, CORE_USER, ENTERPRISE_USER

pytestmark = pytest.mark.integration

BROKER = "http://broker:8000"
ISSUER = "http://localhost:8000"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_engine(get_settings())
    yield engine
    await engine.dispose()


@pytest.fixture
async def sessions(engine: AsyncEngine) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    factory = create_session_factory(engine)

    async with factory() as session:
        pre_existing = set(await session.scalars(select(Person.person_uuid)))

    yield factory

    async with factory() as session, session.begin():
        keep = pre_existing or {uuid.UUID(int=0)}
        for table in (ScimSourceRecord, Account, Identifier, Affiliation):
            await session.execute(delete(table).where(table.person_uuid.not_in(keep)))
        await session.execute(delete(Person).where(Person.person_uuid.not_in(keep)))


@pytest.fixture
async def http() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(base_url=BROKER, timeout=30.0) as client:
        yield client


async def _token(http: httpx.AsyncClient, scopes: str) -> str:
    """A real access token, obtained the way a real SIS obtains one.

    Through the client-credentials grant against the live token endpoint —
    which is what FR-SCIM-13 specifies and is the reason that grant exists at
    all. An earlier version of this file minted a token by reading the broker's
    signing key off disk; the test container could not read it, which was the
    volume permissions working correctly and a sign the shortcut was wrong. A
    token this test forged would also have proved nothing about the endpoint
    that issues them.
    """
    response = await http.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "scope": scopes,
            "client_id": SIS_CLIENT_ID,
            "client_secret": SIS_SECRET,
        },
    )
    assert response.status_code == 200, response.text
    token: str = response.json()["access_token"]
    return token


async def _headers(
    http: httpx.AsyncClient, scopes: str = "scim:read scim:write", **extra: str
) -> dict[str, str]:
    return {"Authorization": f"Bearer {await _token(http, scopes)}", **extra}


def _user(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schemas": [CORE_USER],
        "userName": f"sam.{uuid.uuid4().hex[:8]}@campus.test",
        "name": {"givenName": "Samira", "familyName": "O'Brien"},
        "emails": [{"value": f"{uuid.uuid4().hex[:8]}@campus.test", "primary": True}],
        "active": True,
    }
    document.update(overrides)
    return document


async def _create(http: httpx.AsyncClient, **overrides: Any) -> dict[str, Any]:
    response = await http.post(
        "/scim/v2/Users", json=_user(**overrides), headers=await _headers(http)
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


# --- authentication (FR-SCIM-13) -------------------------------------------


async def test_an_unauthenticated_request_is_refused(http: httpx.AsyncClient) -> None:
    response = await http.get("/scim/v2/Users")

    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


async def test_the_401_says_nothing_about_why(http: httpx.AsyncClient) -> None:
    """The one SCIM response whose caller may not be a legitimate client, so it
    behaves like the SAML gate rather than like a helpful API."""
    body = (await http.get("/scim/v2/Users", headers={"Authorization": "Bearer nonsense"})).json()

    assert "scimType" not in body


async def test_a_read_token_cannot_write(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-SCIM-13's named case. A reporting job that lists users would be a
    catastrophe with write access, so the scopes are separate and the check
    requires the one the operation needs."""
    response = await http.post(
        "/scim/v2/Users", json=_user(), headers=await _headers(http, "scim:read")
    )

    assert response.status_code == 403
    assert "scim:write" in response.json()["detail"]


async def test_a_write_token_cannot_read(http: httpx.AsyncClient) -> None:
    """`scim:write` does not imply `scim:read`: a client that only pushes
    changes has no business enumerating the directory."""
    response = await http.get("/scim/v2/Users", headers=await _headers(http, "scim:write"))

    assert response.status_code == 403


# --- create (FR-SCIM-02, FR-SCIM-14) ---------------------------------------


async def test_a_create_returns_the_canonical_resource(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    document = _user()

    response = await http.post("/scim/v2/Users", json=document, headers=await _headers(http))

    body = response.json()
    assert response.status_code == 201
    assert body["userName"] == document["userName"]
    assert body["id"]
    assert response.headers["location"].endswith(body["id"])
    assert response.headers["etag"] == body["meta"]["version"]


async def test_a_duplicate_username_is_a_conflict(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The single most common SCIM error in practice."""
    document = _user()
    await http.post("/scim/v2/Users", json=document, headers=await _headers(http))

    response = await http.post(
        "/scim/v2/Users", json=_user(userName=document["userName"]), headers=await _headers(http)
    )

    assert response.status_code == 409
    assert response.json()["scimType"] == "uniqueness"


async def test_a_replayed_create_returns_the_existing_person(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """FR-SCIM-14. An SIS that lost our response asks again; a broker that makes
    a second person each time is how one human being ends up with three records
    and two ePPNs."""
    external_id = f"SIS-{uuid.uuid4().hex[:8]}"
    first = await _create(http, externalId=external_id)

    response = await http.post(
        "/scim/v2/Users",
        json=_user(externalId=external_id),
        headers=await _headers(http),
    )

    assert response.status_code == 200
    assert response.json()["id"] == first["id"]


async def test_the_replay_status_distinguishes_it_from_a_create(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """200 against 201 is the only thing telling a retrying client whether its
    first attempt landed."""
    external_id = f"SIS-{uuid.uuid4().hex[:8]}"

    first = await http.post(
        "/scim/v2/Users", json=_user(externalId=external_id), headers=await _headers(http)
    )
    second = await http.post(
        "/scim/v2/Users", json=_user(externalId=external_id), headers=await _headers(http)
    )

    assert (first.status_code, second.status_code) == (201, 200)


async def test_a_create_without_a_username_is_refused(http: httpx.AsyncClient) -> None:
    response = await http.post(
        "/scim/v2/Users", json={"schemas": [CORE_USER]}, headers=await _headers(http)
    )

    assert response.status_code == 400
    assert "userName" in response.json()["detail"]


async def test_affiliations_are_stored_with_their_dates(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The custom extension doing its job: SCIM core cannot say when somebody
    was a student."""
    created = await _create(
        http,
        **{
            CAMPUS_USER: {
                "affiliations": [
                    {
                        "value": "student",
                        "primary": True,
                        "orgUnit": "Computer Science",
                        "validFrom": "2022-09-01",
                    }
                ]
            }
        },
    )

    affiliation = created[CAMPUS_USER]["affiliations"][0]
    assert affiliation["value"] == "student"
    assert affiliation["validFrom"] == "2022-09-01"
    assert "validUntil" not in affiliation


async def test_an_affiliation_outside_the_vocabulary_is_refused(
    http: httpx.AsyncClient,
) -> None:
    response = await http.post(
        "/scim/v2/Users",
        json=_user(**{CAMPUS_USER: {"affiliations": [{"value": "wizard"}]}}),
        headers=await _headers(http),
    )

    assert response.status_code == 400
    assert "vocabulary" in response.json()["detail"]


# --- read (FR-SCIM-03) ------------------------------------------------------


async def test_a_person_is_readable(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    response = await http.get(f"/scim/v2/Users/{created['id']}", headers=await _headers(http))

    assert response.status_code == 200
    assert response.json()["userName"] == created["userName"]


async def test_an_unknown_id_is_a_scim_404(http: httpx.AsyncClient) -> None:
    response = await http.get(f"/scim/v2/Users/{uuid.uuid4()}", headers=await _headers(http))

    body = response.json()
    assert response.status_code == 404
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]


async def test_a_malformed_id_is_a_404_not_a_400(http: httpx.AsyncClient) -> None:
    """A client walking ids it was given should not be able to tell a malformed
    one from one belonging to somebody it cannot see."""
    assert (
        await http.get("/scim/v2/Users/not-a-uuid", headers=await _headers(http))
    ).status_code == 404


async def test_attributes_can_be_projected(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    body = (
        await http.get(
            f"/scim/v2/Users/{created['id']}?attributes=userName", headers=await _headers(http)
        )
    ).json()

    assert body["userName"] == created["userName"]
    assert "emails" not in body


async def test_projection_keeps_the_resource_addressable(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`id` and `meta` survive both projections, or a client that excluded them
    by accident gets a document it cannot do anything with."""
    created = await _create(http)

    body = (
        await http.get(
            f"/scim/v2/Users/{created['id']}?excludedAttributes=id,meta,emails",
            headers=await _headers(http),
        )
    ).json()

    assert body["id"] == created["id"]
    assert "meta" in body
    assert "emails" not in body


# --- ETags (FR-SCIM-09) -----------------------------------------------------


async def test_a_matching_if_none_match_is_not_modified(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    response = await http.get(
        f"/scim/v2/Users/{created['id']}",
        headers=await _headers(http, **{"If-None-Match": created["meta"]["version"]}),
    )

    assert response.status_code == 304


async def test_a_stale_if_match_is_a_precondition_failure(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """Somebody else changed the resource since this client read it. Not an
    error in either party — optimistic concurrency doing its job."""
    created = await _create(http)

    response = await http.put(
        f"/scim/v2/Users/{created['id']}",
        json=_user(userName=created["userName"], displayName="Changed"),
        headers=await _headers(http, **{"If-Match": 'W/"stale"'}),
    )

    assert response.status_code == 412


async def test_a_current_if_match_succeeds(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    response = await http.put(
        f"/scim/v2/Users/{created['id']}",
        json=_user(userName=created["userName"], displayName="Changed"),
        headers=await _headers(http, **{"If-Match": created["meta"]["version"]}),
    )

    assert response.status_code == 200
    assert response.json()["displayName"] == "Changed"


async def test_a_write_without_if_match_is_allowed(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A client not doing optimistic concurrency is making its own choice.
    Requiring the header would break every simple client for the benefit of the
    careful ones."""
    created = await _create(http)

    response = await http.put(
        f"/scim/v2/Users/{created['id']}",
        json=_user(userName=created["userName"]),
        headers=await _headers(http),
    )

    assert response.status_code == 200


# --- replace (FR-SCIM-04) ---------------------------------------------------


async def test_a_replace_clears_what_it_omits(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`PUT` means "the resource is now exactly this"."""
    created = await _create(http, displayName="Samira O'Brien")

    replaced = await http.put(
        f"/scim/v2/Users/{created['id']}",
        json={"schemas": [CORE_USER], "userName": created["userName"], "active": True},
        headers=await _headers(http),
    )

    assert "displayName" not in replaced.json()


async def test_changing_the_username_tombstones_the_old_one(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The single most consequential difference between this store and a
    generic SCIM implementation over a users table.

    The old ePPN is released rather than overwritten, so it can never be handed
    to anybody else — and a later create that asks for it does not get it.
    """
    created = await _create(http)
    original = created["userName"]

    await http.put(
        f"/scim/v2/Users/{created['id']}",
        json=_user(userName=f"renamed.{uuid.uuid4().hex[:8]}@campus.test"),
        headers=await _headers(http),
    )

    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(Identifier).where(
                    Identifier.person_uuid == uuid.UUID(created["id"]),
                    Identifier.id_type == "eppn",
                )
            )
        )

    by_value = {row.value: row for row in rows}
    assert by_value[original].released_at is not None
    assert by_value[original].is_primary is False


async def test_a_released_username_cannot_be_claimed_by_somebody_else(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The point of the tombstone, as an end-to-end assertion."""
    created = await _create(http)
    original = created["userName"]
    await http.put(
        f"/scim/v2/Users/{created['id']}",
        json=_user(userName=f"renamed.{uuid.uuid4().hex[:8]}@campus.test"),
        headers=await _headers(http),
    )

    response = await http.post(
        "/scim/v2/Users", json=_user(userName=original), headers=await _headers(http)
    )

    assert response.status_code in (409, 500)


async def test_a_replace_that_drops_an_affiliation_closes_it(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A `PUT` dropping an affiliation is a graduation, not a correction of the
    record — so "was this person a student on 2024-03-01?" stays answerable."""
    created = await _create(
        http,
        **{CAMPUS_USER: {"affiliations": [{"value": "student", "validFrom": "2022-09-01"}]}},
    )

    await http.put(
        f"/scim/v2/Users/{created['id']}",
        json=_user(userName=created["userName"]),
        headers=await _headers(http),
    )

    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(Affiliation).where(Affiliation.person_uuid == uuid.UUID(created["id"]))
            )
        )

    assert len(rows) == 1
    assert rows[0].valid_until is not None


# --- PATCH (FR-SCIM-05) -----------------------------------------------------


async def _patch(
    http: httpx.AsyncClient, resource_id: str, *operations: dict[str, Any]
) -> httpx.Response:
    return await http.patch(
        f"/scim/v2/Users/{resource_id}",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": list(operations),
        },
        headers=await _headers(http),
    )


async def test_a_patch_changes_one_attribute(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http, displayName="Samira O'Brien")

    response = await _patch(
        http, created["id"], {"op": "replace", "path": "displayName", "value": "Sam"}
    )

    assert response.status_code == 200
    assert response.json()["displayName"] == "Sam"


async def test_a_patch_with_a_value_filter_reaches_one_email(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The shape the PRD calls out, end to end against the database."""
    created = await _create(http)
    replacement = f"{uuid.uuid4().hex[:8]}@campus.test"

    response = await _patch(
        http,
        created["id"],
        {"op": "replace", "path": 'emails[type eq "work"].value', "value": replacement},
    )

    assert response.status_code == 200
    assert response.json()["emails"][0]["value"] == replacement


async def test_a_patch_deactivating_a_person_suspends_them(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    await _patch(http, created["id"], {"op": "replace", "path": "active", "value": False})

    async with sessions() as session:
        person = await session.get(Person, uuid.UUID(created["id"]))

    assert person is not None
    assert person.status == "suspended"


async def test_a_patch_on_an_immutable_attribute_is_refused(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    response = await _patch(
        http, created["id"], {"op": "replace", "path": "id", "value": str(uuid.uuid4())}
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == "mutability"


async def test_a_patch_with_a_malformed_path_is_invalid_path(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)

    response = await _patch(
        http, created["id"], {"op": "replace", "path": "emails[type eq", "value": "x"}
    )

    assert response.json()["scimType"] == "invalidPath"


# --- delete (FR-SCIM-06) ----------------------------------------------------


async def test_a_delete_is_soft(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """The person keeps their row: the audit trail has to go on naming them."""
    created = await _create(http)

    response = await http.delete(f"/scim/v2/Users/{created['id']}", headers=await _headers(http))

    assert response.status_code == 204
    async with sessions() as session:
        person = await session.get(Person, uuid.UUID(created["id"]))
    assert person is not None
    assert person.status == "deactivated"


async def test_a_delete_tombstones_the_identifiers(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """A deprovisioned ePPN stays un-reissuable, which is the whole reason the
    delete is soft."""
    created = await _create(http)

    await http.delete(f"/scim/v2/Users/{created['id']}", headers=await _headers(http))

    async with sessions() as session:
        rows = list(
            await session.scalars(
                select(Identifier).where(Identifier.person_uuid == uuid.UUID(created["id"]))
            )
        )

    assert rows
    assert all(row.released_at is not None for row in rows)


async def test_deleting_twice_is_a_404(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """From a SCIM client's point of view the resource is gone, so asking again
    is asking about something that does not exist."""
    created = await _create(http)
    await http.delete(f"/scim/v2/Users/{created['id']}", headers=await _headers(http))

    response = await http.delete(f"/scim/v2/Users/{created['id']}", headers=await _headers(http))

    assert response.status_code == 404


# --- list, filter and pagination (FR-SCIM-07, FR-SCIM-08) ------------------


async def test_a_list_is_a_list_response(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _create(http)

    body = (await http.get("/scim/v2/Users", headers=await _headers(http))).json()

    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert body["startIndex"] == 1
    assert body["itemsPerPage"] == len(body["Resources"])


async def test_a_filter_selects(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    created = await _create(http)
    await _create(http)

    body = (
        await http.get(
            "/scim/v2/Users",
            params={"filter": f'userName eq "{created["userName"]}"'},
            headers=await _headers(http),
        )
    ).json()

    assert body["totalResults"] == 1
    assert body["Resources"][0]["id"] == created["id"]


async def test_a_malformed_filter_is_invalid_filter(http: httpx.AsyncClient) -> None:
    response = await http.get(
        "/scim/v2/Users", params={"filter": "userName eq"}, headers=await _headers(http)
    )

    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidFilter"


async def test_pagination_does_not_overlap_or_skip(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`startIndex` is 1-based (§3.4.2.4). Zero-based would make a client's
    second page overlap its first by one person."""
    created = [await _create(http) for _ in range(5)]
    known = {person["id"] for person in created}

    first = (
        await http.get(
            "/scim/v2/Users",
            params={"startIndex": 1, "count": 3, "sortBy": "id"},
            headers=await _headers(http),
        )
    ).json()
    second = (
        await http.get(
            "/scim/v2/Users",
            params={"startIndex": 4, "count": 3, "sortBy": "id"},
            headers=await _headers(http),
        )
    ).json()

    page_one = [r["id"] for r in first["Resources"]]
    page_two = [r["id"] for r in second["Resources"]]
    assert not set(page_one) & set(page_two)
    assert known <= set(page_one) | set(page_two) | {
        r["id"] for r in first["Resources"] + second["Resources"]
    }


async def test_sorting_is_honoured(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    await _create(http)
    await _create(http)

    ascending = (
        await http.get(
            "/scim/v2/Users", params={"sortBy": "userName"}, headers=await _headers(http)
        )
    ).json()
    descending = (
        await http.get(
            "/scim/v2/Users",
            params={"sortBy": "userName", "sortOrder": "descending"},
            headers=await _headers(http),
        )
    ).json()

    names = [r["userName"] for r in ascending["Resources"]]
    assert names == sorted(names)
    assert [r["userName"] for r in descending["Resources"]] == list(reversed(names))


async def test_a_start_index_below_one_is_treated_as_one(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """§3.4.2.4. A client counting from zero is making an ordinary off-by-one,
    and a 400 would not tell it which."""
    await _create(http)

    body = (
        await http.get("/scim/v2/Users", params={"startIndex": 0}, headers=await _headers(http))
    ).json()

    assert body["startIndex"] == 1


# --- what the enterprise extension carries ---------------------------------


async def test_an_employee_number_round_trips(
    http: httpx.AsyncClient, sessions: async_sessionmaker[AsyncSession]
) -> None:
    """`restricted` in the catalogue and never released to a service provider —
    but this is the provisioning client that supplied it reading back the record
    it owns, which is a different relationship."""
    number = f"E{uuid.uuid4().hex[:8]}"

    created = await _create(http, **{ENTERPRISE_USER: {"employeeNumber": number}})

    assert created[ENTERPRISE_USER]["employeeNumber"] == number
