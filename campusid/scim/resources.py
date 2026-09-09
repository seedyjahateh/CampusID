"""Between the identity registry and a SCIM User (PRD §8.5).

Two directions, and they are not symmetric.

**Outward** — registry to SCIM — is a projection. A `Person` plus their
identifiers and affiliations become one JSON document, and what a client is
allowed to see is decided here rather than by whatever happens to be in the
row. `employeeNumber` is the case that matters: the SIS sends it, we store it,
and it is classified `restricted`, so it goes back only to the provisioning
client that owns the record and never anywhere near a release policy.

**Inward** — SCIM to registry — is a translation with judgement in it. A SCIM
`User` carries `active: true`; the registry carries a status with four values,
because "suspended by an administrator" and "deactivated at the end of a
contract" are different facts that a boolean cannot hold. Mapping `false` onto
`suspended` and leaving the other two to the admin API is a decision, and losing
it would make a leaver indistinguishable from an archived record.

The `meta.version` is a weak ETag over the projected document. Weak because two
representations that differ only in attribute order are the same resource, and
strong comparison would make a client's `If-Match` fail for no reason.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Final

from campusid.identity.models import Affiliation, Identifier, Person
from campusid.scim.errors import ScimType, invalid_value
from campusid.scim.schemas import CAMPUS_USER, CORE_USER, ENTERPRISE_USER

ID_EPPN: Final = "eppn"
ID_MAIL: Final = "mail"
ID_EMPLOYEE: Final = "employee_id"
ID_STUDENT: Final = "student_id"

STATUS_ACTIVE: Final = "active"
STATUS_SUSPENDED: Final = "suspended"
"""What `active: false` means.

The registry has four statuses and SCIM has a boolean, so the mapping has to
choose. `suspended` is the reversible one, which is right for a flag a client
can flip back — `deactivated` and `archived` are end-states an administrator
decides on, and reaching them through a boolean would make them accidental.
"""


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Everything the projection needs, gathered once.

    A dataclass rather than three arguments because the caller has to load all
    of it anyway, and a projection that could be called with a person and
    somebody else's identifiers is a projection that eventually will be.
    """

    person: Person
    identifiers: list[Identifier]
    affiliations: list[Affiliation]
    external_id: str | None = None


def to_scim(record: UserRecord, *, issuer: str) -> dict[str, Any]:
    """Project a registry record as a SCIM User."""
    person = record.person
    resource: dict[str, Any] = {
        "schemas": [CORE_USER],
        "id": str(person.person_uuid),
        "userName": _primary(record.identifiers, ID_EPPN),
        "active": person.status == STATUS_ACTIVE,
    }

    if record.external_id:
        resource["externalId"] = record.external_id

    name = {
        key: value
        for key, value in (
            ("formatted", person.display_name),
            ("givenName", person.given_name),
            ("familyName", person.surname),
        )
        if value
    }
    if name:
        resource["name"] = name
    if person.display_name:
        resource["displayName"] = person.display_name
    if person.preferred_language:
        resource["preferredLanguage"] = person.preferred_language

    emails = _emails(record.identifiers)
    if emails:
        resource["emails"] = emails

    enterprise = _enterprise(record)
    if enterprise:
        resource["schemas"].append(ENTERPRISE_USER)
        resource[ENTERPRISE_USER] = enterprise

    campus = _campus(record)
    if campus:
        resource["schemas"].append(CAMPUS_USER)
        resource[CAMPUS_USER] = campus

    resource["meta"] = {
        "resourceType": "User",
        "created": _instant(person.created_at),
        "lastModified": _instant(person.updated_at),
        "location": f"{issuer}/scim/v2/Users/{person.person_uuid}",
        "version": etag(resource),
    }
    return resource


def etag(resource: dict[str, Any]) -> str:
    """A weak ETag over the resource (FR-SCIM-09).

    Weak — `W/"…"` — because two representations differing only in attribute
    order are the same resource, and strong comparison would make a client's
    `If-Match` fail for a reason it could never diagnose.

    Computed over the document with `meta` excluded, so the version does not
    depend on itself and a projection is stable across two reads that changed
    nothing.
    """
    without_meta = {key: value for key, value in resource.items() if key != "meta"}
    canonical = json.dumps(without_meta, sort_keys=True, separators=(",", ":"))
    return f'W/"{hashlib.sha256(canonical.encode()).hexdigest()[:32]}"'


def _emails(identifiers: list[Identifier]) -> list[dict[str, Any]]:
    """Live mail identifiers, primary first.

    Released ones are omitted. They are kept in the registry forever so the
    address is never reissued, but an address somebody no longer has is not a
    way to reach them and should not appear in their record.
    """
    return [
        {"value": identifier.value, "type": "work", "primary": identifier.is_primary}
        for identifier in sorted(
            (i for i in identifiers if i.id_type == ID_MAIL and i.released_at is None),
            key=lambda i: (not i.is_primary, i.value),
        )
    ]


def _enterprise(record: UserRecord) -> dict[str, Any]:
    """The enterprise extension.

    `employeeNumber` is `restricted` in the catalogue — never released to a
    service provider by any policy. It appears *here* because SCIM is not
    attribute release: this is the provisioning client that supplied the value
    reading back the record it owns, which is a different relationship from an
    SP asking what it may learn about somebody.
    """
    extension: dict[str, Any] = {}

    employee_number = _primary(record.identifiers, ID_EMPLOYEE)
    if employee_number:
        extension["employeeNumber"] = employee_number

    current = _current(record.affiliations)
    org_unit = next((a.org_unit for a in current if a.org_unit), None)
    if org_unit:
        extension["department"] = org_unit

    return extension


def _campus(record: UserRecord) -> dict[str, Any]:
    """The custom extension: affiliations with their dates, and the FERPA flag."""
    extension: dict[str, Any] = {}

    if record.affiliations:
        extension["affiliations"] = [
            {
                key: value
                for key, value in (
                    ("value", affiliation.affiliation),
                    ("primary", affiliation.is_primary),
                    ("orgUnit", affiliation.org_unit),
                    ("validFrom", affiliation.valid_from.isoformat()),
                    (
                        "validUntil",
                        affiliation.valid_until.isoformat() if affiliation.valid_until else None,
                    ),
                )
                if value is not None
            }
            for affiliation in sorted(record.affiliations, key=lambda a: a.valid_from)
        ]

    if record.person.ferpa_directory_suppressed:
        extension["ferpaDirectorySuppressed"] = True

    return extension


# --- inward -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedUser:
    """A SCIM User, read into the shapes the registry stores.

    Not a `Person` — the registry decides identifiers and status transitions,
    and handing it a half-built row would put that decision in the parser.
    """

    user_name: str
    external_id: str | None
    display_name: str | None
    given_name: str | None
    surname: str | None
    preferred_language: str | None
    active: bool
    emails: list[tuple[str, bool]]
    """`(address, is_primary)`."""

    employee_number: str | None
    ferpa_directory_suppressed: bool
    affiliations: list[ParsedAffiliation]

    @property
    def status(self) -> str:
        """The registry status this resource implies. See `STATUS_SUSPENDED`."""
        return STATUS_ACTIVE if self.active else STATUS_SUSPENDED


@dataclass(frozen=True, slots=True)
class ParsedAffiliation:
    value: str
    is_primary: bool
    org_unit: str | None
    valid_from: date
    valid_until: date | None


def from_scim(document: Any) -> ParsedUser:
    """Read a SCIM User, refusing anything the registry could not store.

    Validation happens here rather than at the database, because a `400` naming
    the attribute is what lets an SIS integrator fix their mapping, while an
    integrity error surfaces as a 500 and tells them nothing.
    """
    if not isinstance(document, dict):
        raise invalid_value("a User must be an object", ScimType.INVALID_SYNTAX)

    user_name = document.get("userName")
    if not isinstance(user_name, str) or not user_name.strip():
        raise invalid_value("userName is required")

    raw_name = document.get("name")
    name: dict[str, Any] = raw_name if isinstance(raw_name, dict) else {}
    enterprise = _extension(document, ENTERPRISE_USER)
    campus = _extension(document, CAMPUS_USER)

    active = document.get("active", True)
    if not isinstance(active, bool):
        raise invalid_value("active must be true or false")

    return ParsedUser(
        user_name=user_name.strip().lower(),
        external_id=_optional_string(document, "externalId"),
        display_name=_optional_string(document, "displayName")
        or _optional_string(name, "formatted"),
        given_name=_optional_string(name, "givenName"),
        surname=_optional_string(name, "familyName"),
        preferred_language=_optional_string(document, "preferredLanguage"),
        active=active,
        emails=_parse_emails(document.get("emails")),
        employee_number=_optional_string(enterprise, "employeeNumber"),
        ferpa_directory_suppressed=bool(campus.get("ferpaDirectorySuppressed", False)),
        affiliations=_parse_affiliations(campus.get("affiliations")),
    )


def _parse_emails(raw: Any) -> list[tuple[str, bool]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise invalid_value("emails must be an array", ScimType.INVALID_SYNTAX)

    parsed: list[tuple[str, bool]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise invalid_value("each email must be an object", ScimType.INVALID_SYNTAX)
        value = entry.get("value")
        if not isinstance(value, str) or "@" not in value:
            raise invalid_value(f"{value!r} is not an email address")
        parsed.append((value.strip().lower(), bool(entry.get("primary", False))))

    if sum(1 for _, primary in parsed if primary) > 1:
        # RFC 7643 §2.4: at most one member of a multi-valued attribute may be
        # primary. Two would make "the primary address" a question with two
        # answers, and which one won would depend on iteration order.
        raise invalid_value("at most one email may be primary")
    return parsed


def _parse_affiliations(raw: Any) -> list[ParsedAffiliation]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise invalid_value("affiliations must be an array", ScimType.INVALID_SYNTAX)

    parsed: list[ParsedAffiliation] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise invalid_value("each affiliation must be an object", ScimType.INVALID_SYNTAX)

        value = entry.get("value")
        if not isinstance(value, str) or not value:
            raise invalid_value("an affiliation needs a value")

        valid_from = _parse_date(entry.get("validFrom"), "validFrom") or date.today()
        valid_until = _parse_date(entry.get("validUntil"), "validUntil")
        if valid_until is not None and valid_until < valid_from:
            raise invalid_value("an affiliation cannot end before it starts")

        parsed.append(
            ParsedAffiliation(
                value=value.strip().lower(),
                is_primary=bool(entry.get("primary", False)),
                org_unit=_optional_string(entry, "orgUnit"),
                valid_from=valid_from,
                valid_until=valid_until,
            )
        )

    if sum(1 for affiliation in parsed if affiliation.is_primary) > 1:
        raise invalid_value("at most one affiliation may be primary")
    return parsed


def _parse_date(raw: Any, field: str) -> date | None:
    """Accept a date or a full timestamp.

    The schema declares `dateTime` because SCIM has no bare date type, but an
    SIS sends `2026-06-30` as often as it sends an instant, and refusing the
    shorter form would be conformance theatre at an integrator's expense.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise invalid_value(f"{field} must be a date")
    try:
        if "T" in raw:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC).date()
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise invalid_value(f"{field} is not a valid date: {raw!r}") from exc


def _extension(document: dict[str, Any], urn: str) -> dict[str, Any]:
    value = document.get(urn)
    return value if isinstance(value, dict) else {}


def _optional_string(container: dict[str, Any], name: str) -> str | None:
    value = container.get(name)
    return value.strip() or None if isinstance(value, str) else None


def _primary(identifiers: list[Identifier], id_type: str) -> str | None:
    """The live primary value of one identifier type, or any live one.

    Falling back to a non-primary matters: an identifier issued before the
    concept of primary existed, or one whose primary was released, would
    otherwise make the record look like it has no ePPN at all.
    """
    live = [i for i in identifiers if i.id_type == id_type and i.released_at is None]
    primary = next((i.value for i in live if i.is_primary), None)
    return primary or next((i.value for i in live), None)


def _current(affiliations: list[Affiliation]) -> list[Affiliation]:
    today = date.today()
    return [
        affiliation
        for affiliation in affiliations
        if affiliation.valid_from <= today
        and (affiliation.valid_until is None or affiliation.valid_until > today)
    ]


def _instant(value: datetime) -> str:
    """RFC 3339 with a `Z`, which is what every SCIM client expects to parse."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
