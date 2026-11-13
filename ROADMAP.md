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
| `attribute.decode_attributes()` | RFC 4271 section 5 and the per-attribute RFCs: typed values for ORIGIN, AS_PATH, AS4_PATH, NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, AS4_AGGREGATOR, COMMUNITIES, EXTENDED COMMUNITIES, LARGE_COMMUNITY, ORIGINATOR_ID, CLUSTER_LIST, MP_REACH, MP_UNREACH; every other attribute is returned raw in `unknown`, every bad value in `undecodable` with its RFC 7606 approach | `[ok]` | `tests/test_values.py::test_decode_attributes_scalar_values`, `tests/test_values.py::test_decode_attributes_bad_values_are_kept_with_the_rfc_7606_approach`, `tests/test_values.py::test_decode_attributes_effective_path_rebuilds_from_as4_only_on_two_octet_sessions` | M3 |
| `aspath.parse_as_path()` | RFC 6793 sections 3, 4.2.2, 4.2.3 and 6 (AS4_PATH merge, AS_TRANS), RFC 5065 segment types 3 and 4, RFC 7607 AS 0, RFC 9774 AS_SET (parsed, flagged by `has_as_set`, never refused here) | `[ok]` | `tests/test_values.py::test_parse_as_path_four_octet_and_two_octet`, `tests/test_values.py::test_parse_as_path_malformed_is_malformed_as_path`, `tests/test_values.py::test_merge_as4_path_prepends_the_leading_surplus`, `tests/test_values.py::test_merge_as4_path_confed_adjacent_to_a_taken_segment_is_taken`, `tests/test_values.py::test_split_for_old_speaker_uses_as_trans_and_omits_as4_when_all_mappable` | M3 |
| `nlri.parse_nlri()` | RFC 7911 section 3 (Path Identifier prefix) for AFI 1 and 2 with SAFI 1 and 2, the only families whose encoding RFC 4760 section 5 states; other families raise `UnsupportedFamilyError` and `parse_mp_reach` keeps their octets | `[ok]` | `tests/test_values.py::test_mp_reach_add_path_applies_only_to_negotiated_families`, `tests/test_values.py::test_parse_nlri_unsupported_family_and_path_id_cut_short` | M4 |
| `communities.decode_communities()` | RFC 1997 plain communities with the IANA well-known names (extract dated 2026-09-22) | `[ok]` | `tests/test_values.py::test_communities_rfc_1997_and_well_known_names` | M5 |
| `communities.decode_large_communities()` | RFC 8092 sections 3 and 6: 12-octet values, duplicates removed on receipt | `[ok]` | `tests/test_values.py::test_large_communities_dedupe_keeps_first_and_checks_length` | M5 |
| `communities.decode_extended()` | RFC 4360 sections 2 and 3, RFC 5668 four-octet AS family, RFC 7153: typed views for the four families, every other type kept whole; transitive bit is 0x40 clear | `[ok]` | `tests/test_values.py::test_extended_communities_types_and_transitive_bit` | M5 |
| `roles.peer_role()` | RFC 9234 section 4 (Role capability, code 9, Table 1) with `role_from_open` (identical duplicates collapse, differing ones are Role Mismatch 2/11), `check_roles` (Table 2 and strict mode) and `role_capability`; an unassigned value (5 to 255) raises `ValueError` because the RFC gives it no meaning | `[ok]` | `tests/test_roles.py::test_peer_role_table_1_values_and_refusals`, `tests/test_roles.py::test_table_2_every_pair_in_both_directions`, `tests/test_roles.py::test_absent_remote_role_is_ignored_unless_strict_and_no_local_role_checks_nothing`, `tests/test_roles.py::test_multiple_role_capabilities_identical_collapse_differing_mismatch`, `tests/test_roles.py::test_malformed_role_capability_length_is_open_unspecific` | M2 |
| `limits.check()` | design: the hostile-input budget over `Counts` measured by `message.measure`; names the first count over its bound, never truncates. The defaults are a library choice, to be tuned on a corpus | `[ok]` | `tests/test_values.py::test_limits_check_names_the_first_exceeded_count_and_allows_equality`, `tests/test_values.py::test_measure_counts_framed_discarded_and_decoded_items` | M1 |
| `nlri.parse_mp_reach()` | RFC 4760 sections 3 and 4, RFC 2545 section 3, RFC 8950 section 3, RFC 7606 sections 5.3 and 7.11: next hop lengths per family, ADD-PATH per family, unknown families kept raw | `[ok]` | `tests/test_values.py::test_mp_reach_ipv6_with_link_local_next_hop`, `tests/test_values.py::test_mp_reach_faults_are_afi_safi_disable`, `tests/test_values.py::test_mp_unreach_and_end_of_rib_form` | M4 |
| `addpath.receive_families()` | RFC 7911 sections 4 and 5: capability 69 tuples; Path Identifiers are decoded where local Receive meets peer Send | `[ok]` | `tests/test_values.py::test_add_path_capability_negotiation_rfc_7911_section_5` | M2 |
| `registry.attribute_name()` | IANA BGP Path Attributes, extract dated 2026-09-09 (primarysource `iana` `bgp-parameters`) | `[ok]` | `tests/test_values.py::test_attr_type_names_agree_with_the_iana_extract` | M3 |
| attr.otc-and-roles | OTC (type 35, RFC 9234 section 5): optional transitive, length 4 else treat-as-withdraw, decoded into `Attributes.otc`; ingress and egress procedures as decisions in `roles.otc_ingress` and `roles.otc_egress`, applicable to AFI 1 and 2 SAFI 1 only (`roles.otc_applies`) | `[ok]` | `tests/test_roles.py::test_otc_walk_flags_and_length_follow_section_5`, `tests/test_roles.py::test_decode_attributes_reads_otc_and_keeps_a_bad_one`, `tests/test_roles.py::test_otc_ingress_rules_one_to_three`, `tests/test_roles.py::test_otc_egress_rules_one_and_two`, `tests/test_roles.py::test_a_leak_through_a_peer_is_seen_by_a_customer_link_three_hops_on` | M2 |
| attr.ipv6-extended-communities | attribute 25 (RFC 5701 section 2, 20-octet entries; RFC 7606 section 7.15 length rule is treat-as-withdraw; unrecognised types kept whole) decoded into `Attributes.ipv6_extended_communities`; Route Target and Route Origin named from RFC 5701 section 3 | `[ok]` | `tests/test_roles.py::test_ipv6_extended_community_fields_and_names`, `tests/test_roles.py::test_ipv6_extended_communities_bad_length_is_treat_as_withdraw`, `tests/test_roles.py::test_decode_attributes_reads_attribute_25_and_it_is_no_longer_unknown` | M5 |
| nlri.other-families | VPN, labeled, EVPN, flowspec and BGP-LS NLRI (their own RFCs; RFC 7606 section 5.4 leaves the discarding of unrecognised typed NLRI to the consumer) are kept raw: `nlri` None, `nlri_raw` and the next hop octets intact, and `encode_mp_reach` reproduces the attribute. No decoder, by decision: add one family at a time when a consumer needs it | `[ok]` | `tests/test_roles.py::test_other_families_are_kept_raw_with_nlri_none_and_round_trip` | M4 |
| roles.open-integration | `message.validate_open` does not call `roles.role_from_open` and `roles.check_roles`: the local Role and the strict-mode choice are configuration it has no field for. Decide whether `OpenPolicy` gains `local_role` and `strict_role`, or the caller composes the two calls | `[ ]` | `tests/test_obligations.py::test_validate_open_role (to be written)` | M2 |
| roles.otc-confederation-and-private-as | RFC 9234 section 5: the OTC value rules for an AS Confederation (the Confederation Identifier, never a Member-AS number) and for private AS numbers behind an Internet-facing ASN are the caller's to apply; `otc_ingress` and `otc_egress` take the AS numbers they are given, and `roles.otc_boundary_violation` checks the egress value rule against AS sets the caller supplies (the literal "other than the Internet-facing ASN" reading is the opt-in `only_boundary`) | `[ok]` | `tests/test_roles.py::test_otc_confederation_egress_carries_the_identifier_never_a_member_as`, `tests/test_roles.py::test_otc_private_as_behind_an_internet_facing_asn` | M2 |
| roles.otc-as-zero | RFC 9234 section 5 says nothing about an OTC value of 0 (RFC 7607 section 2 covers AS_PATH and AGGREGATOR, not OTC), so `walk` accepts it; decision pinned by the named test; the library shows no erratum and no update for RFC 9234, revisit if one appears | `[ok]` | `tests/test_roles.py::test_otc_as_zero_is_accepted_and_handled_as_any_other_value` | M3 |
| addpath.legacy-fields-only-ipv4 | ADD-PATH on the plain Withdrawn Routes and NLRI fields is applied for (1,1) only, as RFC 7911 section 5 leaves the plain fields to IPv4 unicast; verify against a capture | `[ ]` | `tests/test_obligations.py::test_addpath_capture (to be written)` | M6 |
| attr.as-set-policy | RFC 9774 section 3 makes AS_SET and AS_CONFED_SET treat-as-withdraw by default; `walk` does not apply it because the RFC allows operator configuration, `aspath.has_as_set` exposes it. Decide where the policy lives | `[ ]` | `tests/test_obligations.py::test_as_set_policy (to be written)` | M3 |
| `limits.defaults-on-corpus` | the `DEFAULT_BUDGET` numbers are a library choice; tune against a real RIB corpus | `[ ]` | `tests/test_obligations.py::test_budget_on_corpus (to be written)` | M6 |
| open.validate | RFC 4271 section 6.2 via `message.validate_open`: version (Data is the suggested version), Bad Peer AS (AS 0 per RFC 7607 section 2; the four-octet capability replaces My AS per RFC 6793 section 4.1), hold time 1 or 2 rejected, BGP Identifier must be a unicast host address, unknown optional parameters. RFC 6286 (AS-wide unique identifier) is not applied | `[ok]` | `tests/test_values.py::test_validate_open_accepts_and_returns_the_peer_as`, `tests/test_values.py::test_validate_open_version_data_is_the_suggested_version`, `tests/test_values.py::test_validate_open_rejects_hold_time_one_and_two`, `tests/test_values.py::test_validate_open_bad_bgp_identifier` | M2 |
| route-refresh | RFC 2918 section 3 and RFC 7313 sections 3.2 and 5: type 5, subtype octet, BoRR and EoRR, ROUTE-REFRESH Message Error (code 7) only with the Enhanced capability, ORF octets carried raw (RFC 5291 not decoded) | `[ok]` | `tests/test_values.py::test_route_refresh_roundtrip_and_subtypes`, `tests/test_values.py::test_route_refresh_enhanced_length_error_carries_the_message` | M2 |
| update.mp-and-escalation | RFC 7606 sections 3 (j), 5.2, 5.3 and 7.11: MP_REACH and MP_UNREACH contents are parsed; an MP_REACH that announces nothing no longer counts as reachable, and an unparseable one is AFI/SAFI disable | `[ok]` | `tests/test_values.py::test_update_mp_reach_that_announces_nothing_escalates_other_errors_to_session_reset`, `tests/test_values.py::test_update_unparseable_mp_reach_is_afi_safi_disable` | M4 |
| update.as4-attributes | RFC 6793 sections 4.1 and 6, RFC 7607 section 2: AS4_PATH and AS4_AGGREGATOR between NEW speakers or malformed or naming AS 0 are attribute discard; AS 0 in AS_PATH is treat-as-withdraw, in AGGREGATOR attribute discard; confederation segments in AS4_PATH are dropped at decode | `[ok]` | `tests/test_values.py::test_walk_as4_attributes_between_new_speakers_are_discarded`, `tests/test_values.py::test_walk_as0_in_as_path_is_treat_as_withdraw_and_in_aggregator_is_discard` | M3 |
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
