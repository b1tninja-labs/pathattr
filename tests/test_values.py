# ruff: noqa: PT011, PT018, B008, S104
"""Attribute values, AS_PATH merge, communities, MP_REACH with ADD-PATH, OPEN policy, route refresh.

Vectors are built by hand from the sections cited in each test; none comes from a router, so
they pin the reading of the RFC, not interoperability (ROADMAP row ``corpus``).
"""

from __future__ import annotations

import ipaddress

import pytest

from pathattr import addpath, communities, limits, nlri, registry
from pathattr.aspath import (
    AS_TRANS,
    Segment,
    SegmentType,
    contains_as0,
    encode_as_path,
    merge_as4_path,
    parse_as_path,
    path_length,
    split_for_old_speaker,
)
from pathattr.attribute import Action, AttrType, RawAttribute, decode_attributes, walk
from pathattr.errors import BgpError, ErrorCode, OpenSubcode, RouteRefreshSubcode
from pathattr.message import (
    Open,
    OpenPolicy,
    OptionalParameter,
    RouteRefresh,
    Update,
    decode,
    encode,
    four_octet_as_capability,
    measure,
    validate_open,
)

SEQ, SET = SegmentType.AS_SEQUENCE, SegmentType.AS_SET
CSEQ, CSET = SegmentType.AS_CONFED_SEQUENCE, SegmentType.AS_CONFED_SET


def seq(*asns):
    return Segment(SEQ, tuple(asns))


def h(text):
    return bytes.fromhex(text)


def raw(code, value, flags=0xC0):
    return RawAttribute(flags, code, bytes(value))


# ---- AS_PATH (RFC 4271 4.3, RFC 6793, RFC 5065) --------------------------------------------


def test_parse_as_path_four_octet_and_two_octet():
    assert parse_as_path(h("0202 0000fde8 0000fde9"), True) == (seq(65000, 65001),)
    assert parse_as_path(h("0202 fde8 fde9"), False) == (seq(65000, 65001),)
    assert parse_as_path(b"", True) == ()


@pytest.mark.parametrize(
    "value",
    ["09 01 fde8", "0200", "0202 fde8", "0201 fde8 00", "02"],
    ids=["bad-type", "zero-count", "overrun", "trailing-octet", "one-octet"],
)
def test_parse_as_path_malformed_is_malformed_as_path(value):
    with pytest.raises(BgpError) as info:
        parse_as_path(h(value.replace(" ", "")), False)
    assert (info.value.code, info.value.subcode) == (3, 11)


def test_as_path_roundtrip_and_two_octet_refuses_wide_numbers():
    path = (Segment(CSEQ, (64512,)), seq(1, 2), Segment(SET, (3, 4)))
    assert parse_as_path(encode_as_path(path, False), False) == path
    with pytest.raises(ValueError):
        encode_as_path((seq(196618),), False)


def test_path_length_counts_set_as_one_and_not_confed():
    path = (Segment(CSEQ, (1, 2, 3)), seq(4, 5), Segment(SET, (6, 7, 8)), Segment(CSET, (9,)))
    assert path_length(path) == 3


def test_merge_as4_path_prepends_the_leading_surplus():
    # OLD speaker 65001 prepended itself to AS_PATH only; AS4_PATH is unchanged since the NEW one.
    as_path = (seq(65001, AS_TRANS, 65002),)
    as4 = (seq(196618, 65002),)
    assert merge_as4_path(as_path, as4) == (seq(65001, 196618, 65002),)


def test_merge_as4_path_ignored_when_longer_than_as_path():
    as_path = (seq(1, 2),)
    assert merge_as4_path(as_path, (seq(9, 8, 7),)) == as_path


def test_merge_as4_path_set_counts_one_and_is_not_split():
    as_path = (seq(1, 2), Segment(SET, (3, 4)))
    as4 = (Segment(SET, (3, 4)),)
    assert merge_as4_path(as_path, as4) == (seq(1, 2), Segment(SET, (3, 4)))
    # A surplus of one against an AS_SEQUENCE leading, partly taken.
    assert merge_as4_path((seq(1, 2, 3),), (seq(30),)) == (seq(1, 2, 30),)


def test_merge_as4_path_takes_leading_confed_and_drops_confed_from_as4():
    as_path = (Segment(CSEQ, (64512,)), seq(1, 2))
    as4 = (Segment(CSEQ, (64999,)), seq(2))
    assert merge_as4_path(as_path, as4) == (Segment(CSEQ, (64512,)), seq(1, 2))


def test_merge_as4_path_confed_adjacent_to_a_taken_segment_is_taken():
    as_path = (seq(1), Segment(CSEQ, (64512,)), seq(2, 3))
    assert merge_as4_path(as_path, (seq(2, 3),)) == as_path
    # A confed segment that neither leads nor touches a taken segment stays behind.
    as_path = (seq(1), seq(2), Segment(CSET, (7,)), seq(3))
    assert merge_as4_path(as_path, (seq(2, 3),)) == (seq(1, 2, 3),)


def test_split_for_old_speaker_uses_as_trans_and_omits_as4_when_all_mappable():
    two, four = split_for_old_speaker((Segment(CSEQ, (64512,)), seq(65001, 196618)))
    assert two == (Segment(CSEQ, (64512,)), seq(65001, AS_TRANS))
    assert four == (seq(65001, 196618),)  # confederation segment excluded (RFC 6793 4.2.2)
    assert split_for_old_speaker((seq(1, 2),)) == ((seq(1, 2),), None)


def test_contains_as0():
    assert contains_as0((seq(1, 0),)) and not contains_as0((seq(1, 2),))


# ---- decode_attributes ---------------------------------------------------------------------


def test_decode_attributes_scalar_values():
    attrs = [
        raw(AttrType.ORIGIN, h("02"), 0x40),
        raw(AttrType.AS_PATH, h("0201 0000fde8"), 0x40),
        raw(AttrType.NEXT_HOP, h("c0000201"), 0x40),
        raw(AttrType.MULTI_EXIT_DISC, h("0000000a"), 0x80),
        raw(AttrType.LOCAL_PREF, h("00000064"), 0x40),
        raw(AttrType.ATOMIC_AGGREGATE, b"", 0x40),
        raw(AttrType.AGGREGATOR, h("0000fde8 c0000202")),
        raw(AttrType.ORIGINATOR_ID, h("0a000001"), 0x80),
        raw(AttrType.CLUSTER_LIST, h("0a000002 0a000003"), 0x80),
        raw(99, h("abcd")),
    ]
    got = decode_attributes(attrs)
    assert int(got.origin) == 2
    assert got.as_path == (seq(65000),)
    assert got.next_hop == ipaddress.IPv4Address("192.0.2.1")
    assert (got.med, got.local_pref, got.atomic_aggregate) == (10, 100, True)
    assert got.aggregator.asn == 65000
    assert str(got.aggregator.address) == "192.0.2.2"
    assert str(got.originator_id) == "10.0.0.1"
    assert [str(a) for a in got.cluster_list] == ["10.0.0.2", "10.0.0.3"]
    assert got.unknown == (attrs[-1],)
    assert got.undecodable == ()


def test_decode_attributes_bad_values_are_kept_with_the_rfc_7606_approach():
    got = decode_attributes(
        [
            raw(AttrType.ORIGIN, h("07"), 0x40),
            raw(AttrType.AGGREGATOR, h("00")),
            raw(AttrType.MP_REACH_NLRI, h("0001 01 0f") + bytes(15) + h("00"), 0x80),
        ]
    )
    actions = {u.attribute.type_code: u.action for u in got.undecodable}
    assert actions == {
        AttrType.ORIGIN: Action.TREAT_AS_WITHDRAW,
        AttrType.AGGREGATOR: Action.ATTRIBUTE_DISCARD,
        AttrType.MP_REACH_NLRI: Action.AFI_SAFI_DISABLE,
    }
    assert got.origin is None and got.mp_reach is None


def test_decode_attributes_effective_path_rebuilds_from_as4_only_on_two_octet_sessions():
    attrs = [
        raw(AttrType.AS_PATH, h("0203 fde9 5ba0 fdea"), 0x40),
        raw(AttrType.AS4_PATH, h("0202 0003000a 0000fdea")),
    ]
    got = decode_attributes(attrs, four_octet_as=False)
    assert got.effective_as_path == (seq(65001, 196618, 65002),)
    # Between 4-octet speakers a present AS4_PATH is not merged (RFC 6793 4.1).
    four = decode_attributes(
        [raw(AttrType.AS_PATH, h("0201 0000fde9"), 0x40), attrs[1]], four_octet_as=True
    )
    assert four.effective_as_path == (seq(65001),)


def test_effective_aggregator_prefers_as4_aggregator_only_for_as_trans():
    attrs = [
        raw(AttrType.AGGREGATOR, h("5ba0 c0000202")),
        raw(AttrType.AS4_AGGREGATOR, h("0003000a c0000202")),
    ]
    got = decode_attributes(attrs, four_octet_as=False)
    assert got.effective_aggregator.asn == 196618
    other = decode_attributes(
        [raw(AttrType.AGGREGATOR, h("fde8 c0000202")), attrs[1]], four_octet_as=False
    )
    assert other.effective_aggregator.asn == 65000


# ---- walk: AS 0, AS4 and large communities -------------------------------------------------


def framed(code, value, flags=0xC0):
    return RawAttribute(flags, code, bytes(value)).encode()


def test_walk_as0_in_as_path_is_treat_as_withdraw_and_in_aggregator_is_discard():
    path = walk(framed(2, h("0201 00000000"), 0x40), four_octet_as=True, internal=False)
    assert path.action is Action.TREAT_AS_WITHDRAW
    agg = walk(framed(7, h("00000000 c0000202")), four_octet_as=True, internal=False)
    assert agg.action is Action.ATTRIBUTE_DISCARD


def test_walk_as4_attributes_between_new_speakers_are_discarded():
    good = framed(17, h("0201 0003000a"))
    assert walk(good, four_octet_as=True, internal=False).action is Action.ATTRIBUTE_DISCARD
    assert walk(good, four_octet_as=False, internal=False).action is Action.NONE
    bad = framed(17, h("0201 0003"))
    assert walk(bad, four_octet_as=False, internal=False).action is Action.ATTRIBUTE_DISCARD
    zero = framed(17, h("0201 00000000"))
    assert walk(zero, four_octet_as=False, internal=False).action is Action.ATTRIBUTE_DISCARD
    agg = framed(18, h("0003000a c0000202"))
    assert walk(agg, four_octet_as=False, internal=False).action is Action.NONE
    assert walk(agg, four_octet_as=True, internal=False).action is Action.ATTRIBUTE_DISCARD


def test_walk_large_community_length_and_flags():
    ok = framed(32, bytes(12))
    assert walk(ok, four_octet_as=True, internal=False).action is Action.NONE
    short = framed(32, bytes(11))
    assert walk(short, four_octet_as=True, internal=False).action is Action.TREAT_AS_WITHDRAW
    flags = framed(32, bytes(12), 0x80)
    assert walk(flags, four_octet_as=True, internal=False).action is Action.TREAT_AS_WITHDRAW


# ---- communities ---------------------------------------------------------------------------


def test_communities_rfc_1997_and_well_known_names():
    got = communities.decode_communities(h("ffffff01 fde80064 ffff029a"))
    assert [str(c) for c in got] == ["NO_EXPORT", "65000:100", "BLACKHOLE"]
    assert got[1].asn == 65000 and got[1].local == 100 and got[1].well_known is None
    for bad in (b"", h("010203")):
        with pytest.raises(ValueError):
            communities.decode_communities(bad)


def test_large_communities_dedupe_keeps_first_and_checks_length():
    one = h("0000fde8 00000001 00000002")
    two = h("0000fde8 00000003 00000004")
    got = communities.decode_large_communities(one + two + one)
    assert [str(c) for c in got] == ["65000:1:2", "65000:3:4"]
    with pytest.raises(ValueError):
        communities.decode_large_communities(one[:11])


def test_extended_communities_types_and_transitive_bit():
    rt = communities.decode_extended(h("0002 fde8 00000064"))[0]
    assert rt.transitive and rt.family == "two-octet-as" and str(rt) == "rt:65000:100"
    nt = communities.decode_extended(h("4003 fde8 00000064"))[0]
    assert not nt.transitive and str(nt) == "ro:65000:100"  # bit 0x40 set: non-transitive
    v4 = communities.decode_extended(h("0102 c0000201 0005"))[0]
    assert v4.administrator() == (ipaddress.IPv4Address("192.0.2.1"), 5)
    four = communities.decode_extended(h("0202 0003000a 0007"))[0]
    assert four.administrator() == (196618, 7)
    unknown = communities.decode_extended(h("8001 0102030405 06"))[0]
    assert unknown.family is None and unknown.iana_authority
    assert unknown.raw == h("8001 0102030405 06")
    with pytest.raises(ValueError):
        communities.decode_extended(bytes(9))


# ---- MP_REACH / MP_UNREACH and ADD-PATH ----------------------------------------------------

V6_NH = ipaddress.IPv6Address("2001:db8::1").packed


def test_mp_reach_ipv6_with_link_local_next_hop():
    link = ipaddress.IPv6Address("fe80::1").packed
    value = h("0002 01 20") + V6_NH + link + h("00") + h("20 20010db8")
    got = nlri.parse_mp_reach(value)
    assert got.next_hops == (ipaddress.IPv6Address("2001:db8::1"), ipaddress.IPv6Address("fe80::1"))
    assert got.nlri == (nlri.Nlri(ipaddress.IPv6Network("2001:db8::/32")),)
    assert nlri.encode_mp_reach(got) == value


def test_mp_reach_add_path_applies_only_to_negotiated_families():
    entry = h("00000007 18 c00002")
    value = h("0001 01 04 c0000201 00") + entry
    got = nlri.parse_mp_reach(value, frozenset({(1, 1)}))
    assert got.nlri == (nlri.Nlri(ipaddress.IPv4Network("192.0.2.0/24"), 7),)
    assert nlri.encode_mp_reach(got) == value
    with pytest.raises(nlri.MpError):  # the same octets read without ADD-PATH are garbage
        nlri.parse_mp_reach(value)


def test_mp_reach_ipv4_nlri_with_ipv6_next_hop_rfc_8950():
    value = h("0001 01 10") + V6_NH + h("00 18 c00002")
    assert nlri.parse_mp_reach(value).next_hops == (ipaddress.IPv6Address("2001:db8::1"),)


@pytest.mark.parametrize(
    "value",
    ["0002 01 0f" + "00" * 15 + "00", "0002 01 10 00", "0001 01"],
    ids=["bad-next-hop-length", "next-hop-overruns", "too-short"],
)
def test_mp_reach_faults_are_afi_safi_disable(value):
    with pytest.raises(nlri.MpError) as info:
        nlri.parse_mp_reach(h(value.replace(" ", "")))
    assert info.value.afi_safi_disable


def test_mp_reach_unknown_family_keeps_its_octets():
    value = h("0019 46 04 c0000201 00 deadbeef")
    got = nlri.parse_mp_reach(value)
    assert got.nlri is None and got.nlri_raw == h("deadbeef")
    assert nlri.encode_mp_reach(got) == value


def test_mp_unreach_and_end_of_rib_form():
    got = nlri.parse_mp_unreach(h("0002 01 30 20010db80001"))
    assert got.nlri == (nlri.Nlri(ipaddress.IPv6Network("2001:db8:1::/48")),)
    assert nlri.parse_mp_unreach(h("0002 01")).nlri == ()
    with pytest.raises(nlri.MpError):
        nlri.parse_mp_unreach(h("0002"))
    with pytest.raises(nlri.MpError):
        nlri.parse_mp_unreach(h("0002 01 81 00"))


def test_parse_nlri_unsupported_family_and_path_id_cut_short():
    with pytest.raises(nlri.UnsupportedFamilyError):
        nlri.parse_nlri(b"", 25, 70, False)
    with pytest.raises(BgpError):
        nlri.parse_nlri(h("000000"), 1, 1, True)


def test_add_path_capability_negotiation_rfc_7911_section_5():
    both = addpath.AddPathFamily(1, 1, addpath.SendReceive.BOTH)
    send = addpath.AddPathFamily(2, 1, addpath.SendReceive.SEND)
    recv = addpath.AddPathFamily(2, 1, addpath.SendReceive.RECEIVE)
    cap = addpath.encode_capability([both, send])
    assert cap.code == 69 and addpath.parse_capability(cap.value) == (both, send)
    # We receive family (2,1) only if we say Receive and the peer says Send.
    assert addpath.receive_families([both, recv], [both, send]) == {(1, 1), (2, 1)}
    assert addpath.receive_families([send], [both, send]) == frozenset()
    assert addpath.send_families([send], [recv]) == {(2, 1)}
    assert addpath.parse_capability(h("0001 01 09")) == ()  # undefined Send/Receive: ignored
    with pytest.raises(ValueError):
        addpath.parse_capability(h("000101"))


def test_update_with_add_path_on_ipv4_unicast_roundtrips_path_ids():
    withdrawn = h("00000001 18 c00002")
    announced = h("00000002 10 c000")
    attrs = framed(1, h("00"), 0x40) + framed(2, b"", 0x40) + framed(3, h("c0000201"), 0x40)
    body = (
        len(withdrawn).to_bytes(2, "big")
        + withdrawn
        + len(attrs).to_bytes(2, "big")
        + attrs
        + announced
    )
    wire = h("ff" * 16) + (19 + len(body)).to_bytes(2, "big") + h("02") + body
    update = decode(wire, add_path=frozenset({(1, 1)}))
    assert isinstance(update, Update)
    assert update.withdrawn_path_ids == (1,) and update.nlri_path_ids == (2,)
    assert str(update.nlri[0]) == "192.0.0.0/16"
    assert encode(update) == wire


def test_update_mp_reach_that_announces_nothing_escalates_other_errors_to_session_reset():
    # RFC 7606 5.2: an MP_REACH with no NLRI is not a reachable announcement, so a treat-as-withdraw
    # error elsewhere cannot be applied and the session must be reset.
    mp = framed(14, h("0002 01 10") + V6_NH + h("00"), 0x80)
    bad_origin = framed(1, h("09"), 0x40)
    attrs = mp + bad_origin
    body = h("0000") + len(attrs).to_bytes(2, "big") + attrs
    wire = h("ff" * 16) + (19 + len(body)).to_bytes(2, "big") + h("02") + body
    assert decode(wire).action is Action.SESSION_RESET
    # With one prefix in the MP_REACH the UPDATE is a real announcement: treat-as-withdraw stands.
    mp2 = framed(14, h("0002 01 10") + V6_NH + h("00 20 20010db8"), 0x80)
    attrs = mp2 + bad_origin
    body = h("0000") + len(attrs).to_bytes(2, "big") + attrs
    wire = h("ff" * 16) + (19 + len(body)).to_bytes(2, "big") + h("02") + body
    assert decode(wire).action is Action.TREAT_AS_WITHDRAW


def test_update_unparseable_mp_reach_is_afi_safi_disable():
    mp = framed(14, h("0002 01 0f") + bytes(16), 0x80)
    body = h("0000") + len(mp).to_bytes(2, "big") + mp
    wire = h("ff" * 16) + (19 + len(body)).to_bytes(2, "big") + h("02") + body
    assert decode(wire).action is Action.AFI_SAFI_DISABLE


# ---- OPEN policy (RFC 4271 6.2, RFC 6793 4.1, RFC 7607 2) ----------------------------------


def make_open(**kw):
    base = {
        "version": 4,
        "my_as": 65000,
        "hold_time": 90,
        "bgp_id": ipaddress.IPv4Address("192.0.2.1"),
    }
    base.update(kw)
    return Open(**base)


def refusal(opened, policy=OpenPolicy()):
    with pytest.raises(BgpError) as info:
        validate_open(opened, policy)
    assert info.value.code == ErrorCode.OPEN_MESSAGE
    return info.value


def test_validate_open_accepts_and_returns_the_peer_as():
    assert validate_open(make_open()) == 65000
    cap = OptionalParameter(2, h("4104 0003000a"))
    opened = make_open(my_as=AS_TRANS, parameters=(cap,))
    assert four_octet_as_capability(opened) == 196618
    assert validate_open(opened) == 196618  # the capability value replaces My AS (RFC 6793 4.1)


def test_validate_open_version_data_is_the_suggested_version():
    error = refusal(make_open(version=3))
    assert error.subcode == OpenSubcode.UNSUPPORTED_VERSION_NUMBER and error.data == h("0004")
    error = refusal(make_open(version=5), OpenPolicy(supported_versions=(3, 4)))
    assert error.data == h("0004")
    error = refusal(make_open(version=2), OpenPolicy(supported_versions=(3, 4)))
    assert error.data == h("0003")  # the smallest supported, none being lower


@pytest.mark.parametrize("hold", [1, 2])
def test_validate_open_rejects_hold_time_one_and_two(hold):
    assert refusal(make_open(hold_time=hold)).subcode == OpenSubcode.UNACCEPTABLE_HOLD_TIME


def test_validate_open_hold_time_zero_and_policy_minimum():
    assert validate_open(make_open(hold_time=0)) == 65000
    assert refusal(make_open(hold_time=0), OpenPolicy(allow_zero_hold_time=False))
    assert refusal(make_open(hold_time=9), OpenPolicy(min_hold_time=10)).data == b""


def test_validate_open_bad_peer_as():
    assert refusal(make_open(my_as=0)).subcode == OpenSubcode.BAD_PEER_AS  # RFC 7607 section 2
    assert refusal(make_open(), OpenPolicy(expected_peer_as=65001)).subcode == 2


@pytest.mark.parametrize("ident", ["0.0.0.0", "224.0.0.1", "255.255.255.255"])
def test_validate_open_bad_bgp_identifier(ident):
    opened = make_open(bgp_id=ipaddress.IPv4Address(ident))
    assert refusal(opened).subcode == OpenSubcode.BAD_BGP_IDENTIFIER


def test_validate_open_unsupported_optional_parameter_and_malformed_capability():
    assert refusal(make_open(parameters=(OptionalParameter(1, b"x"),))).subcode == 4
    bad = make_open(parameters=(OptionalParameter(2, h("4103 000000")),))
    assert refusal(bad).subcode == OpenSubcode.UNSPECIFIC


# ---- ROUTE-REFRESH (RFC 2918, RFC 7313) ----------------------------------------------------


def test_route_refresh_roundtrip_and_subtypes():
    wire = encode(RouteRefresh(1, 1))
    assert wire[16:] == h("0017 05 0001 00 01")
    assert decode(wire) == RouteRefresh(1, 1, 0)
    borr = encode(RouteRefresh(2, 1, 1))
    assert decode(borr, enhanced_route_refresh=True).subtype == 1
    assert not RouteRefresh(1, 1, 7).defined_subtype


def test_route_refresh_enhanced_length_error_carries_the_message():
    wire = encode(RouteRefresh(1, 1, 2, b"\x01"))
    with pytest.raises(BgpError) as info:
        decode(wire, enhanced_route_refresh=True)
    assert (info.value.code, info.value.subcode) == (7, RouteRefreshSubcode.INVALID_MESSAGE_LENGTH)
    assert info.value.data == wire
    # Without the capability, or with subtype 0, trailing ORF octets are carried, not refused.
    assert decode(wire).orf == b"\x01"
    assert (
        decode(encode(RouteRefresh(1, 1, 0, b"\x01")), enhanced_route_refresh=True).orf == b"\x01"
    )


def test_route_refresh_shorter_than_23_is_bad_message_length():
    wire = h("ff" * 16) + h("0016 05 0001 00")
    with pytest.raises(BgpError) as info:
        decode(wire)
    assert (info.value.code, info.value.subcode) == (1, 2)


# ---- limits.check --------------------------------------------------------------------------


def test_limits_check_names_the_first_exceeded_count_and_allows_equality():
    budget = limits.Budget(attributes=2, nlri=3)
    limits.check(limits.Counts(attributes=2, nlri=3), budget)
    with pytest.raises(limits.BudgetExceeded) as info:
        limits.check(limits.Counts(attributes=2, nlri=4, withdrawn=10**9), budget)
    assert (info.value.name, info.value.limit, info.value.actual) == ("nlri", 3, 4)


def test_limits_default_budget_accepts_an_ordinary_update_and_refuses_a_flood():
    limits.check(limits.Counts(attributes=12, as_path_asns=8, nlri=40))
    with pytest.raises(limits.BudgetExceeded):
        limits.check(limits.Counts(as_path_asns=100000))
    with pytest.raises(ValueError):
        limits.Budget(nlri=-1)


def test_measure_counts_framed_discarded_and_decoded_items():
    attrs = (
        framed(1, h("00"), 0x40)
        + framed(2, h("0203 0000fde8 0000fde9 0000fdea"), 0x40)
        + framed(6, h("01"), 0x40)  # malformed ATOMIC_AGGREGATE: discarded but still counted
        + framed(8, h("fde80064 fde80065"))
    )
    body = h("0000") + len(attrs).to_bytes(2, "big") + attrs + h("18 c00002 10 c001")
    wire = h("ff" * 16) + (19 + len(body)).to_bytes(2, "big") + h("02") + body
    update = decode(wire)
    decoded = decode_attributes(update.attributes)
    counts = measure(update, decoded)
    assert counts.attributes == 4 and counts.nlri == 2
    assert (counts.as_path_segments, counts.as_path_asns, counts.communities) == (1, 3, 2)


# ---- registry provenance -------------------------------------------------------------------


def test_attr_type_names_agree_with_the_iana_extract():
    for member in AttrType:
        iana = registry.ATTRIBUTE_NAMES[int(member)].replace(" ", "_").upper()
        assert member.name == iana, member
    assert registry.attribute_name(35) == "Only to Customer (OTC)"
    assert registry.attribute_name(0) == "reserved" and registry.attribute_name(99) == "unassigned"
    assert registry.IANA_UPDATED == "2026-09-09"
