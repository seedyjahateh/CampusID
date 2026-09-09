"""The audit trail.

Separate from application logging on purpose. Logs are for operators debugging
a system; the audit trail is evidence — it answers "why does this app see my
name?" to a registrar, "was this account used after we disabled it?" to an
investigator, and under FERPA §99.32 it *is* the record of disclosures the
institution is required to keep.

That difference shows up in three places: it goes to Postgres rather than
stdout, nothing in the application ever updates or deletes a row, and what may
appear in it is constrained rather than left to whoever writes the call.
"""
