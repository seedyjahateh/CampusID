"""Operational scripts.

A package rather than a loose directory for one reason: the SCIM integration
tests import the development SIS credentials from `federation_init` instead of
restating them, and without an `__init__.py` the same file reaches mypy under
two module names — once from the command line, once through that import.
"""
