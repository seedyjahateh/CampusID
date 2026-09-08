# Vendored schemas

Verbatim copies of the SAML 2.0 and W3C schemas the metadata validator needs.
Vendored rather than fetched so validation works offline, cannot be influenced
by a network attacker, and gives identical results on every machine and in CI.

| File | Source |
|---|---|
| `saml-schema-metadata-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd |
| `saml-schema-assertion-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd |
| `saml-schema-protocol-2.0.xsd` | https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd |
| `xmldsig-core-schema.xsd` | https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd |
| `xenc-schema.xsd` | https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd |
| `xml.xsd` | https://www.w3.org/2001/xml.xsd |

Retrieved 2026-09-08. These are stable published standards; the SAML 2.0 files
have not changed since 2005.

The metadata schema imports three of these by **absolute URL** and one by
relative path, so loading it needs a resolver that maps those URLs to the local
files. That is `_LocalSchemaResolver` in `../metadata_sp.py`, which refuses
anything it cannot resolve locally rather than falling back to the network.

Copyright remains with OASIS and W3C, under licences that permit
redistribution. Not covered by this project's MIT licence.
