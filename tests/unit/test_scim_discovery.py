"""SCIM discovery (FR-SCIM-01, RFC 7643 §7).

Every flag in `ServiceProviderConfig` is a promise a conformance client will
hold the server to, so these tests check the promises match what the code
actually does — and, for the custom extension, that it is discoverable rather
than a private arrangement between us and one SIS.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient

from campusid.routes.scim import SCIM_CONTENT_TYPE
from campusid.scim.schemas import (
    CAMPUS_USER,
    CORE_USER,
    ENTERPRISE_USER,
    LIST_RESPONSE,
    MAX_BULK_OPERATIONS,
    MAX_RESULTS,
)

ISSUER = "https://broker.test"


async def test_the_provider_config_is_served(client: AsyncClient) -> None:
    response = await client.get("/scim/v2/ServiceProviderConfig")

    assert response.status_code == 200
    assert response.json()["patch"]["supported"] is True


async def test_every_document_uses_the_scim_media_type(client: AsyncClient) -> None:
    """RFC 7644 §8.1. A conformance client checks it, and `application/json` is
    a documented interoperability failure rather than a harmless difference."""
    for path in (
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas",
    ):
        response = await client.get(path)
        assert response.headers["content-type"].startswith(SCIM_CONTENT_TYPE), path


async def test_change_password_is_not_supported(client: AsyncClient) -> None:
    """This broker holds no passwords — the IdP authenticates people — and
    claiming otherwise would have clients trying."""
    config = (await client.get("/scim/v2/ServiceProviderConfig")).json()

    assert config["changePassword"]["supported"] is False


async def test_the_advertised_limits_match_the_code(client: AsyncClient) -> None:
    """A ceiling a client discovers by trial is a ceiling it discovers in
    production."""
    config = (await client.get("/scim/v2/ServiceProviderConfig")).json()

    assert config["filter"]["maxResults"] == MAX_RESULTS
    assert config["bulk"]["maxOperations"] == MAX_BULK_OPERATIONS


async def test_the_authentication_scheme_is_a_bearer_token(client: AsyncClient) -> None:
    """FR-SCIM-13. The client needs to know what to send before it sends it."""
    config = (await client.get("/scim/v2/ServiceProviderConfig")).json()

    assert config["authenticationSchemes"][0]["type"] == "oauthbearertoken"


# --- resource types ---------------------------------------------------------


async def test_resource_types_are_a_list_response(client: AsyncClient) -> None:
    """RFC 7644 §4 requires the envelope even for a fixed collection. A bare
    array works with a hand-written client and fails with a conformant one,
    which is the wrong way round."""
    body = (await client.get("/scim/v2/ResourceTypes")).json()

    assert body["schemas"] == [LIST_RESPONSE]
    assert body["totalResults"] == len(body["Resources"])
    assert body["startIndex"] == 1


async def test_the_user_type_declares_both_extensions(client: AsyncClient) -> None:
    body = (await client.get("/scim/v2/ResourceTypes")).json()
    user = next(r for r in body["Resources"] if r["id"] == "User")

    declared = {extension["schema"] for extension in user["schemaExtensions"]}
    assert declared == {ENTERPRISE_USER, CAMPUS_USER}


async def test_the_campus_extension_is_not_required(client: AsyncClient) -> None:
    """A plain SCIM client still works — it simply cannot express when an
    affiliation started or ended."""
    body = (await client.get("/scim/v2/ResourceTypes")).json()
    user = next(r for r in body["Resources"] if r["id"] == "User")

    campus = next(e for e in user["schemaExtensions"] if e["schema"] == CAMPUS_USER)
    assert campus["required"] is False


async def test_one_resource_type_is_addressable(client: AsyncClient) -> None:
    response = await client.get("/scim/v2/ResourceTypes/User")

    assert response.status_code == 200
    assert response.json()["endpoint"] == "/Users"


async def test_an_unknown_resource_type_is_a_scim_error(client: AsyncClient) -> None:
    response = await client.get("/scim/v2/ResourceTypes/Widget")

    body = response.json()
    assert response.status_code == 404
    assert body["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert body["status"] == "404"


# --- schemas ----------------------------------------------------------------


async def test_every_schema_is_listed(client: AsyncClient) -> None:
    body = (await client.get("/scim/v2/Schemas")).json()

    assert {schema["id"] for schema in body["Resources"]} == {
        CORE_USER,
        ENTERPRISE_USER,
        CAMPUS_USER,
    }


async def test_a_schema_is_addressable_by_its_urn(client: AsyncClient) -> None:
    """The id is a URN full of colons and dots, which the path converter has to
    carry intact."""
    response = await client.get(f"/scim/v2/Schemas/{CAMPUS_USER}")

    assert response.status_code == 200
    assert response.json()["id"] == CAMPUS_USER


async def test_an_unknown_schema_is_a_scim_error(client: AsyncClient) -> None:
    response = await client.get("/scim/v2/Schemas/urn:example:made:up")

    assert response.status_code == 404
    assert response.json()["status"] == "404"


async def test_the_campus_extension_declares_temporal_affiliations(
    client: AsyncClient,
) -> None:
    """The reason the extension exists. Core `User` can say somebody is a
    student; it cannot say they were one from September 2022 to June 2026."""
    schema = (await client.get(f"/scim/v2/Schemas/{CAMPUS_USER}")).json()
    affiliations = next(a for a in schema["attributes"] if a["name"] == "affiliations")

    sub = {attribute["name"] for attribute in affiliations["subAttributes"]}
    assert {"value", "validFrom", "validUntil"} <= sub
    assert affiliations["multiValued"] is True


async def test_the_campus_extension_declares_the_ferpa_flag(client: AsyncClient) -> None:
    schema = (await client.get(f"/scim/v2/Schemas/{CAMPUS_USER}")).json()

    names = {attribute["name"] for attribute in schema["attributes"]}
    assert "ferpaDirectorySuppressed" in names


async def test_username_is_declared_unique(client: AsyncClient) -> None:
    """A client reads this to know a duplicate is a 409 rather than a second
    record."""
    schema = (await client.get(f"/scim/v2/Schemas/{CORE_USER}")).json()
    user_name = next(a for a in schema["attributes"] if a["name"] == "userName")

    assert user_name["uniqueness"] == "server"
    assert user_name["required"] is True


async def test_groups_are_read_only_on_a_user(client: AsyncClient) -> None:
    """RFC 7643 §4.1.2. Membership changes through `/Groups`, and a client that
    writes here would believe it had changed something."""
    schema = (await client.get(f"/scim/v2/Schemas/{CORE_USER}")).json()
    groups = next(a for a in schema["attributes"] if a["name"] == "groups")

    assert groups["mutability"] == "readOnly"


@pytest.mark.parametrize("required", ["name", "type", "multiValued", "mutability", "returned"])
async def test_every_attribute_definition_is_complete(client: AsyncClient, required: str) -> None:
    """RFC 7643 §7 gives these defaults, and a client reads them to decide how
    to treat an attribute. Omitting one from a definition is not a mistake
    anybody spots by eye."""
    body = (await client.get("/scim/v2/Schemas")).json()

    for schema in body["Resources"]:
        for attribute in schema["attributes"]:
            assert required in attribute, f"{schema['id']}.{attribute.get('name')}"


async def test_discovery_needs_no_token(client: AsyncClient) -> None:
    """RFC 7644 §2 permits either. These describe the server rather than
    anybody in it, and requiring a token to learn which features exist would
    mean an integrator cannot check compatibility before asking for
    credentials."""
    for path in ("/scim/v2/ServiceProviderConfig", "/scim/v2/Schemas"):
        assert (await client.get(path)).status_code == 200


async def test_no_discovery_document_names_a_person(client: AsyncClient) -> None:
    """The precondition for serving them unauthenticated."""
    for path in (
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas",
    ):
        body: Any = (await client.get(path)).text
        assert "sam.obrien" not in body
        assert "@campus.test" not in body
