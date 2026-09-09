# Attribute release policies

One file per service provider. Adding an app to the federation is adding a file
here, which means the review diff shows that one app's policy rather than a
line buried in a document describing every app at once.

The engine is **default-deny**: an attribute with no rule permitting it is not
released. An SP with no file at all can authenticate people and learns nothing
else about them, which is the right state for something nobody has reviewed yet.

## Rule kinds

| `effect` | Meaning |
|---|---|
| `allow` | Release every value of the attribute. |
| `allow-value` | Release only the values matching `value_filter`. The pattern is anchored at both ends. |
| `deny` | Never release it, whatever else says. Give it a low `precedence` so it runs before the permission it overrides. |
| `require-consent` | Withhold until the subject agrees. Fails closed: an attribute nobody has consented to is not released. |

`entity_categories` is the fifth kind, expressed as a property of the SP rather
than as a rule: an SP tagged with REFEDS R&S receives that bundle without any
per-attribute configuration. A category an SP earns once is reviewable; two
hundred hand-written per-SP rules are not.

## What the loader refuses

All of these fail at load time, where the person who made the change is looking
at it, rather than at 3am as "the app isn't getting the attribute":

- an attribute name that is not in the catalogue (a typo produces a rule that
  never matches, and the reflex fix for that is a broader rule)
- a `restricted` attribute — a student or employee number is an education record
  under FERPA and is never releasable, by any policy, to anyone
- an `allow-value` with no filter, or a filter on a plain `allow` (both read as
  though they restrict something and do not)
- a `value_filter` that does not compile
- two rules sharing an `id`, since rule ids are what audit records cite
- an unknown top-level key — a typo in `internal_school_official` is the
  difference between a working LMS and a FERPA finding
- a quoted boolean: YAML makes `true` a boolean and `"true"` a string, so
  accepting the string would let a value mean the opposite of what it reads as

A file that fails to load leaves the **previously loaded policy in place**. An
empty policy set would lock every user out of every app at once, and a
permissive fallback would be a disclosure; keeping what was already working is
the only failure direction anybody can recover from. The failure is logged as
`policy_reload_failed` and clears itself once the file parses again.

## Editing

Files are re-read when they change — no restart. The store fingerprints names
and modification times, so deleting a policy stops it applying too.

## Attribute names

Use the `urn:oid:` form. Shibboleth and Keycloak both key their mappers on it;
the friendly form (`mail`, `eduPersonPrincipalName`) silently releases nothing.
`campusid/policy/attributes.py` is the catalogue, and the loader validates
against it.
