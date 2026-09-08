"""XSD validation against the vendored SAML schemas.

Shared by metadata generation and by the `AuthnRequest` builder, because both
produce documents a peer will parse strictly. Validating our own output is
cheap insurance against the failure mode where a descriptor or a request is
accepted by lenient tooling and rejected by the one implementation that
matters.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from lxml import etree

SCHEMA_DIR: Final = Path(__file__).resolve().parent / "schemas"

METADATA_SCHEMA: Final = "saml-schema-metadata-2.0.xsd"
PROTOCOL_SCHEMA: Final = "saml-schema-protocol-2.0.xsd"


class LocalSchemaResolver(etree.Resolver):
    """Map schema imports to the vendored files.

    The SAML schemas import xmldsig, xmlenc and the XML namespace by absolute
    `http://` URL. Without this, loading one would reach out to w3.org —
    turning validation into a network call that is slow, flaky, unavailable in
    CI, and controlled by whoever can answer that request. Anything not
    vendored is refused rather than fetched.
    """

    # lxml-stubs omits the `context` parameter that lxml actually passes.
    def resolve(self, system_url: str, public_id: str | None, context: Any) -> Any:  # type: ignore[override]
        candidate = SCHEMA_DIR / system_url.rsplit("/", 1)[-1]
        if candidate.is_file():
            return self.resolve_filename(str(candidate), context)  # type: ignore[attr-defined]
        raise FileNotFoundError(
            f"schema {system_url!r} is not vendored in {SCHEMA_DIR}; "
            "add it there rather than allowing a network fetch"
        )


@lru_cache(maxsize=4)
def load_schema(name: str) -> etree.XMLSchema:
    """Compile a vendored schema. Compilation costs ~50ms, so it is cached."""
    parser = etree.XMLParser(no_network=True)
    parser.resolvers.add(LocalSchemaResolver())
    return etree.XMLSchema(etree.parse(str(SCHEMA_DIR / name), parser=parser))
