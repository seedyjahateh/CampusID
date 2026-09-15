"""Measured performance runs against a live stack (NFR-PROV-01, 02, 03).

Not tests. A test asserts a property and fails; these produce a number and a
report somebody reads, because the requirements they serve are stated as
percentiles and a percentile is not a pass or a fail until somebody has looked at
the distribution behind it.

They live outside `tests/` for that reason, and because they need a running
broker, a database and a directory — everything the unit suite was built to avoid
needing.
"""
