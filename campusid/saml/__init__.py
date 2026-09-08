"""SAML 2.0 Service Provider.

Module boundaries are deliberate:

``parser``      the only module permitted to parse untrusted XML
``algorithms``  signature/digest/canonicalisation allowlists
``xsw``         structural predicates defending against signature wrapping
``signature``   XML-DSig verification over signxml
``gate``        the ordered validation pipeline that composes the above
"""
