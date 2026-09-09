"""LDAP and Active Directory integration (FR-DIR-01 to 08).

The directory is where a campus keeps the accounts people actually log into and
the groups that actually grant access. The broker reads it to resolve group
membership and writes to it on lifecycle events, and both directions have to
work against two conventions that agree on almost nothing.
"""
