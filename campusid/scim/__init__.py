"""SCIM 2.0 provisioning (RFC 7643, RFC 7644).

The protocol an SIS or an HR system speaks to create, update and deprovision
people without anybody writing an integration. Most of it is ordinary REST; two
parts are not, and both come down to the same grammar.

`PATCH` (RFC 7644 §3.5.2) addresses *parts* of a resource by path, and those
paths can carry filters — `emails[type eq "work"].value` means "the value
sub-attribute of whichever email is the work one". A provisioning client that
sends this and gets it silently mishandled will believe it changed somebody's
address when it did not, which is a worse failure than an error.

Query filters (§3.4.2.2) use the same expression grammar with the same operators
and the same precedence, so they are parsed by the same code. That is the reason
`filters.py` exists as its own module rather than as two half-implementations.
"""
