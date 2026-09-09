"""The upstream relying-party side.

The broker is a SAML SP and an OIDC RP *upstream*, and an OIDC OP downstream.
This package is the first of those: authenticating people against somebody
else's OpenID Provider — a partner institution, a national federation's proxy, a
cloud directory — and turning what it says into the same internal facts a SAML
assertion produces.

The asymmetry with `campusid/oidc/` is the thing to hold on to. There we mint
tokens and control the keys; here we consume tokens minted by a party we do not
control, whose keys rotate without telling us, over a channel an attacker would
love to influence. Every decision in this package follows from being the
sceptical side of that relationship.
"""
