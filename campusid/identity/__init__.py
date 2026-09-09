"""The identity registry: who a person is, and how the broker knows.

Everything before this milestone identified people by whatever the IdP happened
to say — `idp_entity_id|NameID`, good enough for a session and useless for
anything that has to outlive one. This package is the answer to "the same human
being, seen twice".

One design decision runs through all of it, from PRD §8.1: **the immutable
identifier is internal**. `person.person_uuid` never changes and is never
released. Everything a person is known by outside — an ePPN, an email address, a
`sAMAccountName` — is an *attribute of* the person, not the person's key, and
every one of them is reassignable in principle.

That distinction is not academic. It is the difference between a graduating
student's ePPN being handed to a new arrival who then inherits their grades, and
the same ePPN being tombstoned forever because the row that owns it belongs to
somebody who has left.
"""
