# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation pathattr could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `message.decode()` | RFC 4271 sections 4.1 to 4.5 and 6.1; RFC 8654 sections 4 and 5; RFC 5492 section 4; RFC 9072 section 2; RFC 7606 | `[ok]` | `tests/test_message.py::test_decode_keepalive`, `tests/test_message.py::test_decode_bad_marker_raises_subcode_1`, `tests/test_message.py::test_decode_update_figure_16_corrected`, `tests/test_message.py::test_decode_open_extended_optional_parameters`, `tests/test_message.py::test_extended_max_length_65535_only_when_enabled` | M1 |
| `message.encode()` | RFC 4271 sections 4.1 to 4.5; RFC 9072 section 2; encoding is exact for decoded input except attributes discarded by RFC 7606 and trailing prefix bits, which are cleared | `[ok]` | `tests/test_message.py::test_roundtrip_keepalive_notification`, `tests/test_message.py::test_encode_open_switches_to_extended_encoding_over_255_octets`, `tests/test_message.py::test_encode_notification_data_over_limit_raises` | M1 |
| `message.decode_header()` | RFC 4271 section 6.1 | `[ok]` | `tests/test_message.py::test_decode_length_out_of_range_raises_subcode_2_with_length_in_data`, `tests/test_message.py::test_decode_unknown_type_raises_subcode_3_with_type_in_data` | M1 |
| `message.decode_stream()` | RFC 4271 sections 4.1 and 6.1 (no resynchronisation) | `[ok]` | `tests/test_message.py::test_decode_stream_returns_partial_tail`, `tests/test_message.py::test_decode_stream_resyncs_never`, `tests/test_message.py::test_many_small_messages_linear_time` | M1 |
| `attribute.walk()` | RFC 4271 section 4.3; RFC 7606 sections 2 to 4 and 7 | `[ok]` | `tests/test_walk.py::test_walk_figure16_attributes`, `tests/test_walk.py::test_walk_extended_length_attribute`, `tests/test_walk.py::test_walk_length_overrun_is_treat_as_withdraw`, `tests/test_walk.py::test_walk_strongest_action_wins`, `tests/test_walk.py::test_walk_never_raises_index_error` | M3 |
| `attribute.missing_mandatory()` | RFC 7606 section 3 (d) | `[ok]` | `tests/test_walk.py::test_missing_mandatory_needs_reachable_nlri` | M3 |
| `nlri.parse_prefix_list()` | RFC 4271 section 4.3; RFC 7606 section 5.3 | `[ok]` | `tests/test_message.py::test_decode_update_invalid_network_field`, `tests/test_message.py::test_decode_update_withdrawn_routes_only` | M4 |
| `attribute.decode_attributes()` | RFC 4271 section 5 and the per-attribute RFCs: decoding attribute values; `walk` only frames and judges | `[ ]` | `tests/test_obligations.py::test_decode_attributes` (to be written) | M3 |
| `aspath.parse_as_path()` | RFC 6793 sections 3 and 4.2.3 (AS4_PATH merge, AS_TRANS); RFC 5065 segment types 3 and 4; RFC 9774 AS_SET deprecation (parse still) | `[ ]` | `tests/test_obligations.py::test_parse_as_path` (to be written) | M3 |
| `nlri.parse_nlri()` | RFC 4760 (MP_REACH and MP_UNREACH contents, AFI/SAFI) and RFC 7911 (ADD-PATH); the Spec cell cited only 7911 | `[ ]` | `tests/test_obligations.py::test_parse_nlri` (to be written) | M4 |
| `communities.decode_communities()` | RFC 1997 plain communities, RFC 8092 large communities | `[ ]` | `tests/test_obligations.py::test_decode_communities` (to be written) | M5 |
| `communities.decode_extended()` | RFC 4360; RFC 7153 registry changes | `[ ]` | `tests/test_obligations.py::test_decode_extended` (to be written) | M5 |
| `roles.peer_role()` | RFC 9234 section 4 (Role capability) and the OTC attribute (type 35) | `[ ]` | `tests/test_obligations.py::test_peer_role` (to be written) | M2 |
| `limits.check()` | design: the hostile-input budget (attribute count, AS_PATH segments, NLRI count); the message-size constants exist in limits.py and are RFC text | `[ ]` | `tests/test_obligations.py::test_check` (to be written) | M1 |
| open.validate | RFC 4271 section 6.2 policy on a decoded OPEN: version, hold time 1 or 2 MUST be rejected, BGP Identifier, unsupported parameters; the decoder frames but does not judge | `[ ]` | `tests/test_obligations.py::test_open_validate` (to be written) | M2 |
| route-refresh | RFC 2918 (and RFC 7313): message type 5 is reported as Bad Message Type today | `[ ]` | `tests/test_obligations.py::test_route_refresh` (to be written) | M2 |
| update.mp-and-escalation | RFC 7606 section 3 (j) and 5.2 needs MP_REACH/MP_UNREACH contents parsed; until then MP_REACH presence counts as reachable | `[ ]` | `tests/test_obligations.py::test_mp_escalation` (to be written) | M4 |
| update.as4-attributes | RFC 6793 section 4.1: AS4_PATH and AS4_AGGREGATOR between NEW speakers are discarded; RFC 7606 section 8 for their error handling; not yet judged by the walker | `[ ]` | `tests/test_obligations.py::test_as4_attributes` (to be written) | M3 |
| corpus | decode every UPDATE of a real RouteViews or RIS MRT dump with no unexplained residue, hash recorded; also interop against a non-Python decoder | `[ ]` | `tests/test_obligations.py::test_corpus` (to be written) | M6 |
| pathattr as a dependency of asnkit, bmpkit, bgpfeed and routevalid | portfolio edge: PORTFOLIO.md section 9 item 14 already states it; those four projects' docs/plan.md do not list it. Owner decision to record the edge in the portfolio plan and regenerate the plans | `[ ]` | `tests/test_obligations.py::test_dependency_edge` (to be written) | - |

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
- RFC 4271 verified erratum 4493: subcode 0 (Unspecific) exists for every Error Code; the decoder accepts it and `errors.py` has it. Verified erratum 1633 (section 6.3: no "discard" of an attribute when the session is reset) is superseded in practice by RFC 7606.
- RFC 7606 has one erratum on file, held, editorial (hyphenation, eid 5941). RFC 5492 one rejected, RFC 1997 two held editorial and one rejected, RFC 4456 one held editorial and one rejected, RFC 9072 and RFC 8654 none (rfclib, 2026-11-13).
- RFC 6396 Appendix A carries verified errata 5511 (Figure 16 Total Path Attribute Length 0x23, NEXT_HOP c63364bc) and 6640 (Figure 19). The tests use the corrected bytes and prove the uncorrected Figure 16 is refused.
- The research review said an attribute length overrunning the field is a session reset. RFC 7606 section 4 says treat-as-withdraw, and `walk` follows the RFC.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a BGP speaker: no sessions, no timers, no announcement; ExaBGP, FRR and BIRD do that | `[no]` | a named document requires it |
| best path selection or any policy engine | `[no]` | a named document requires it |
| RIB storage and indexing, which is asnkit | `[no]` | a named document requires it |

## 5. Open questions

- RFC 9774 deprecates AS_SET and AS_CONFED_SET: the parser must still accept them, with a policy flag. Not yet read.
- Scope of "every attribute": the core set is judged by `walk`; every other attribute is framed and preserved raw with its flags, never dropped.
- Decisions the RFC leaves open and the code makes: `walk` returns attribute-discard attributes only inside `Issue`; MP_REACH/MP_UNREACH flag faults are AFI/SAFI disable; `decode` defaults `four_octet_as=True, internal=False`.
- nlri.parse_nlri is placed on M4 (multiprotocol NLRI) but its Spec cell cites RFC 7911 (ADD-PATH) only: add RFC 4760 to the cell, or split the ADD-PATH handling into its own row

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
