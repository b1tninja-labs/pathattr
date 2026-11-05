# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation pathattr could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `message.decode()` | RFC 4271 | `[ ]` | `tests/test_obligations.py::decode` |
| `message.encode()` | RFC 4271 | `[ ]` | `tests/test_obligations.py::encode` |
| `attribute.decode_attributes()` | RFC 4271 | `[ ]` | `tests/test_obligations.py::decode_attributes` |
| `aspath.parse_as_path()` | RFC 6793 | `[ ]` | `tests/test_obligations.py::parse_as_path` |
| `nlri.parse_nlri()` | RFC 7911 | `[ ]` | `tests/test_obligations.py::parse_nlri` |
| `communities.decode_communities()` | RFC 8092 | `[ ]` | `tests/test_obligations.py::decode_communities` |
| `communities.decode_extended()` | RFC 4360 | `[ ]` | `tests/test_obligations.py::decode_extended` |
| `roles.peer_role()` | RFC 9234 | `[ ]` | `tests/test_obligations.py::peer_role` |
| `limits.check()` | design | `[ ]` | `tests/test_obligations.py::check` |

## 2. Milestones

- M1 message framing and NOTIFICATION and KEEPALIVE handling
- M2 OPEN with the capability registry, including ADD-PATH and role
- M3 path attributes with 4-octet AS and AS4 fallback
- M4 multiprotocol NLRI, withdrawn and announce paths
- M5 community decoding against the registries, unknown types preserved
- M6 publication: 0.1.0 with captures from a live RIB as fixtures

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 4271 carries 9 verified errata and is updated by RFC 4724, RFC 6286, RFC 6608, RFC 6793, RFC 7606, RFC 7607, RFC 7705, RFC 8212, RFC 8654, RFC 9072, RFC 9687 and RFC 9774. Several of those change the wire: 6793 is 4-octet AS, 7606 is error handling, 9072 is extended message lengths.
- RFC 4360 carries 2 verified errata and is updated by RFC 7153 and RFC 7606.
- RFC 7911 and RFC 9234 report no errata as of 2026-10-29.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a BGP speaker: no sessions, no timers, no announcement; ExaBGP, FRR and BIRD do that | `[no]` | a named document requires it |
| best path selection or any policy engine | `[no]` | a named document requires it |
| RIB storage and indexing, which is asnkit | `[no]` | a named document requires it |

## 5. Open questions

- none recorded yet

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
