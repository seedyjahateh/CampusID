"""SCIM schemas and discovery documents (FR-SCIM-01, RFC 7643 §7).

What a conformance client reads before it sends anything: which features this
server supports, which resource types exist, and what attributes each carries.

Most of it is transcription. The part that is not is the custom extension.

**SCIM has no temporal model and a university needs one.** Core `User` can say
somebody is a student; it cannot say they were a student from September 2022 to
June 2026 and an alum since. `enterprise:2.0:User` does not help — it has one
`department` and no dates. So `urn:campusid:scim:schemas:extension:2.0:User`
carries `affiliations[]` with `validFrom` and `validUntil`, which is the shape
the registry already stores because "was this person a student on 2024-03-01?"
has to be answerable.

Declaring it in `/Schemas` is what makes it discoverable rather than a private
arrangement: a conformance client can find it, and an SIS integrator can read
what the broker expects without asking anybody.
"""

from __future__ import annotations

from typing import Any, Final

CORE_USER: Final = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE_USER: Final = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
CAMPUS_USER: Final = "urn:campusid:scim:schemas:extension:2.0:User"
CORE_GROUP: Final = "urn:ietf:params:scim:schemas:core:2.0:Group"

LIST_RESPONSE: Final = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SERVICE_PROVIDER_CONFIG: Final = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
RESOURCE_TYPE: Final = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA: Final = "urn:ietf:params:scim:schemas:core:2.0:Schema"

MAX_RESULTS: Final = 200
"""FR-SCIM-01's `filter.maxResults`. A client asking for more is paginated
rather than refused — but it is told the ceiling here so it can size its pages
before it discovers them by trial."""

MAX_BULK_OPERATIONS: Final = 100
MAX_BULK_PAYLOAD: Final = 1024 * 1024


def service_provider_config(issuer: str) -> dict[str, Any]:
    """`GET /scim/v2/ServiceProviderConfig`.

    Every flag here is a promise a conformance client will hold us to, so each
    is set from what actually works rather than from what would look complete.
    `changePassword` is false because this broker holds no passwords — the IdP
    does — and claiming otherwise would have clients trying.
    """
    return {
        "schemas": [SERVICE_PROVIDER_CONFIG],
        "documentationUri": f"{issuer}/docs",
        "patch": {"supported": True},
        "bulk": {
            "supported": True,
            "maxOperations": MAX_BULK_OPERATIONS,
            "maxPayloadSize": MAX_BULK_PAYLOAD,
        },
        "filter": {"supported": True, "maxResults": MAX_RESULTS},
        # No passwords here to change. The upstream IdP authenticates people;
        # this broker never sees a credential.
        "changePassword": {"supported": False},
        "sort": {"supported": True},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": (
                    "An access token from this broker's token endpoint, carrying "
                    "the scim:read or scim:write scope."
                ),
                "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": (f"{issuer}/scim/v2/ServiceProviderConfig"),
        },
    }


def resource_types(issuer: str) -> list[dict[str, Any]]:
    """`GET /scim/v2/ResourceTypes`."""
    return [
        {
            "schemas": [RESOURCE_TYPE],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "A person in the campus identity registry",
            "schema": CORE_USER,
            "schemaExtensions": [
                {"schema": ENTERPRISE_USER, "required": False},
                # Not required, so a plain SCIM client still works — it simply
                # cannot express when an affiliation started or ended.
                {"schema": CAMPUS_USER, "required": False},
            ],
            "meta": {
                "resourceType": "ResourceType",
                "location": f"{issuer}/scim/v2/ResourceTypes/User",
            },
        },
        {
            "schemas": [RESOURCE_TYPE],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "A group of people",
            "schema": CORE_GROUP,
            "schemaExtensions": [],
            "meta": {
                "resourceType": "ResourceType",
                "location": f"{issuer}/scim/v2/ResourceTypes/Group",
            },
        },
    ]


def _attribute(
    name: str,
    kind: str = "string",
    *,
    multi: bool = False,
    required: bool = False,
    mutability: str = "readWrite",
    case_exact: bool = False,
    uniqueness: str = "none",
    returned: str = "default",
    sub_attributes: list[dict[str, Any]] | None = None,
    description: str = "",
) -> dict[str, Any]:
    """One attribute definition, with RFC 7643 §7's defaults filled in.

    A helper rather than literal dictionaries because the defaults are what a
    client reads when deciding how to treat an attribute, and omitting
    `caseExact` from one of forty definitions is not a mistake anybody spots.
    """
    definition: dict[str, Any] = {
        "name": name,
        "type": kind,
        "multiValued": multi,
        "description": description,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": returned,
        "uniqueness": uniqueness,
    }
    if sub_attributes is not None:
        definition["subAttributes"] = sub_attributes
    return definition


def schemas(issuer: str) -> list[dict[str, Any]]:
    """`GET /scim/v2/Schemas` — every schema this server understands."""
    return [_core_user(issuer), _enterprise_user(issuer), _campus_user(issuer), _core_group(issuer)]


def _core_group(issuer: str) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SCHEMA],
        "id": CORE_GROUP,
        "name": "Group",
        "description": "SCIM core Group",
        "attributes": [
            _attribute(
                "displayName",
                required=True,
                uniqueness="server",
                description="The group's name. Unique; a duplicate is a 409.",
            ),
            _attribute(
                "externalId",
                case_exact=True,
                description="The provisioning client's key. Drives idempotency on retry.",
            ),
            _attribute(
                "members",
                "complex",
                multi=True,
                returned="request",
                description=(
                    "Returned only when asked for by name. A group here may have tens of "
                    "thousands of members, and serving them on every read would make listing "
                    "groups cost the whole membership table. For a large group, ask "
                    '/Users?filter=groups.value eq "<id>" instead, which pages.'
                ),
                sub_attributes=[
                    _attribute("value"),
                    _attribute("display", mutability="immutable"),
                    _attribute("type", mutability="immutable"),
                ],
            ),
        ],
        "meta": {"resourceType": "Schema", "location": f"{issuer}/scim/v2/Schemas/{CORE_GROUP}"},
    }


def _core_user(issuer: str) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SCHEMA],
        "id": CORE_USER,
        "name": "User",
        "description": "SCIM core User",
        "attributes": [
            _attribute(
                "userName",
                required=True,
                uniqueness="server",
                description="The eduPersonPrincipalName. Unique; a duplicate is a 409.",
            ),
            _attribute(
                "name",
                "complex",
                sub_attributes=[
                    _attribute("formatted"),
                    _attribute("givenName"),
                    _attribute("familyName"),
                ],
            ),
            _attribute("displayName"),
            _attribute("preferredLanguage"),
            _attribute(
                "active",
                "boolean",
                description="False moves the person to suspended and triggers the leaver path.",
            ),
            _attribute(
                "emails",
                "complex",
                multi=True,
                sub_attributes=[
                    _attribute("value"),
                    _attribute("type"),
                    _attribute("primary", "boolean"),
                ],
            ),
            _attribute(
                "groups",
                "complex",
                multi=True,
                mutability="readOnly",
                description=(
                    "Read-only per RFC 7643 §4.1.2. Membership is changed through "
                    "/Groups, not by writing here."
                ),
                sub_attributes=[
                    _attribute("value", mutability="readOnly"),
                    _attribute("display", mutability="readOnly"),
                ],
            ),
            _attribute(
                "externalId",
                case_exact=True,
                description="The SIS primary key. Drives idempotency on retry.",
            ),
        ],
        "meta": {"resourceType": "Schema", "location": f"{issuer}/scim/v2/Schemas/{CORE_USER}"},
    }


def _enterprise_user(issuer: str) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SCHEMA],
        "id": ENTERPRISE_USER,
        "name": "EnterpriseUser",
        "description": "SCIM enterprise User extension",
        "attributes": [
            _attribute(
                "employeeNumber",
                description=(
                    "Stored as a restricted identifier. Accepted from the SIS and "
                    "never released to any service provider."
                ),
            ),
            _attribute("department"),
            _attribute(
                "manager",
                "complex",
                sub_attributes=[_attribute("value"), _attribute("displayName")],
            ),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": f"{issuer}/scim/v2/Schemas/{ENTERPRISE_USER}",
        },
    }


def _campus_user(issuer: str) -> dict[str, Any]:
    """The custom extension. See the module docstring for why it exists."""
    return {
        "schemas": [SCHEMA_SCHEMA],
        "id": CAMPUS_USER,
        "name": "CampusUser",
        "description": (
            "The temporal affiliation model SCIM core lacks. Core User can say "
            "somebody is a student; it cannot say they were one from September "
            "2022 to June 2026 and have been an alum since."
        ),
        "attributes": [
            _attribute(
                "affiliations",
                "complex",
                multi=True,
                description="Time-bounded relationships to the institution.",
                sub_attributes=[
                    _attribute(
                        "value",
                        description="An eduPerson affiliation: student, staff, alum, …",
                    ),
                    _attribute("primary", "boolean"),
                    _attribute("orgUnit"),
                    _attribute("validFrom", "dateTime"),
                    _attribute(
                        "validUntil",
                        "dateTime",
                        description="Absent means current.",
                    ),
                ],
            ),
            _attribute(
                "ferpaDirectorySuppressed",
                "boolean",
                description=(
                    "34 CFR §99.37. When true, directory information is withheld "
                    "from every service provider not operating under the "
                    "school-official exception."
                ),
            ),
        ],
        "meta": {"resourceType": "Schema", "location": f"{issuer}/scim/v2/Schemas/{CAMPUS_USER}"},
    }
