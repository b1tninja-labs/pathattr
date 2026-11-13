# ruff: noqa: PT011, PT018
"""BGP Role (RFC 9234 section 4), OTC (section 5), attribute 25 (RFC 5701) and raw families.

RFC 9234 and RFC 5701 print no wire vectors, so the byte strings here are built by hand from the
sections cited in each test: they pin the reading of the RFC, not interoperability.
"""

from __future__ import annotations

import ipaddress
import itertools

import pytest

from pathattr import communities, nlri, roles
from pathattr.attribute import Action, AttrType, RawAttribute, decode_attributes, walk
from pathattr.errors import BgpError, ErrorCode, OpenSubcode
from pathattr.message import Capability, Open, OptionalParameter, decode, encode
from pathattr.roles import Role


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


def open_with(*capabilities: Capability) -> Open:
    value = b"".join(bytes([c.code, len(c.value)]) + c.value for c in capabilities)
    return Open(4, 65000, 90, ipaddress.IPv4Address("192.0.2.1"), (OptionalParameter(2, value),))


# ---- the capability (section 4) -------------------------------------------------------------


def test_peer_role_table_1_values_and_refusals():
    # Table 1: 0 Provider, 1 RS, 2 RS-Client, 3 Customer, 4 Peer; 5 to 255 unassigned.
    names = ["PROVIDER", "RS", "RS_CLIENT", "CUSTOMER", "PEER"]
    assert [roles.peer_role(bytes([n])).name for n in range(5)] == names
    for bad in (b"", b"\x00\x00", b"\x05", b"\xff"):
        with pytest.raises(ValueError):
            roles.peer_role(bad)


def test_role_capability_is_code_9_length_1():
    cap = roles.role_capability(Role.CUSTOMER)
    assert (cap.code, cap.value) == (9, b"\x03")
    assert roles.peer_role(cap.value) is Role.CUSTOMER


def test_role_survives_an_open_round_trip():
    wire = encode(open_with(roles.role_capability(Role.RS_CLIENT)))
    assert roles.role_from_open(decode(wire)) is Role.RS_CLIENT
    assert roles.role_from_open(open_with(Capability(65, h("0000fde8")))) is None


def test_table_2_every_pair_in_both_directions():
    allowed = {
        (Role.PROVIDER, Role.CUSTOMER),
        (Role.CUSTOMER, Role.PROVIDER),
        (Role.RS, Role.RS_CLIENT),
        (Role.RS_CLIENT, Role.RS),
        (Role.PEER, Role.PEER),
    }
    for local, remote in itertools.product(Role, Role):
        if (local, remote) in allowed:
            roles.check_roles(local, remote)
            assert roles.expected_remote_role(local) is remote
        else:
            with pytest.raises(BgpError) as info:
                roles.check_roles(local, remote)
            assert (info.value.code, info.value.subcode) == (
                ErrorCode.OPEN_MESSAGE,
                OpenSubcode.ROLE_MISMATCH,
            )
            assert (info.value.code, info.value.subcode) == (2, 11)


def test_absent_remote_role_is_ignored_unless_strict_and_no_local_role_checks_nothing():
    roles.check_roles(Role.PEER, None)  # section 4.2: backward compatibility
    with pytest.raises(BgpError) as info:
        roles.check_roles(Role.PEER, None, strict=True)
    assert (info.value.code, info.value.subcode) == (2, 11)
    roles.check_roles(None, Role.PEER, strict=True)  # nothing was advertised


def test_multiple_role_capabilities_identical_collapse_differing_mismatch():
    same = open_with(roles.role_capability(Role.PEER), roles.role_capability(Role.PEER))
    assert roles.role_from_open(same) is Role.PEER
    differ = open_with(roles.role_capability(Role.PEER), roles.role_capability(Role.CUSTOMER))
    with pytest.raises(BgpError) as info:
        roles.role_from_open(differ)
    assert (info.value.code, info.value.subcode) == (2, 11)


def test_malformed_role_capability_length_is_open_unspecific():
    with pytest.raises(BgpError) as info:
        roles.role_from_open(open_with(Capability(9, b"\x00\x01")))
    assert (info.value.code, info.value.subcode) == (2, 0)


# ---- the OTC attribute (section 5) ----------------------------------------------------------


def test_decode_and_encode_otc():
    assert roles.decode_otc(h("0000fde8")) == 65000
    assert roles.encode_otc(65000) == h("0000fde8")
    for bad in (b"", h("fde8"), h("0000fde800")):
        with pytest.raises(ValueError):
            roles.decode_otc(bad)


def test_otc_walk_flags_and_length_follow_section_5():
    ok = RawAttribute(0xC0, AttrType.OTC, h("0000fde8"))
    assert walk(b"\xc0\x23\x04" + ok.value, four_octet_as=True, internal=False).issues == ()
    # section 5: a length other than 4 is treat-as-withdraw
    short = walk(b"\xc0\x23\x03\x00\xfd\xe8", four_octet_as=True, internal=False)
    assert [issue.action for issue in short.issues] == [Action.TREAT_AS_WITHDRAW]
    # optional transitive: a well-known (non-optional) flag set is a flags conflict (RFC 7606 3 (c))
    flags = walk(b"\x40\x23\x04\x00\x00\xfd\xe8", four_octet_as=True, internal=False)
    assert [issue.action for issue in flags.issues] == [Action.TREAT_AS_WITHDRAW]


def test_decode_attributes_reads_otc_and_keeps_a_bad_one():
    good = decode_attributes([RawAttribute(0xC0, 35, h("0000fde8"))])
    assert good.otc == 65000 and not good.unknown and not good.undecodable
    bad = decode_attributes([RawAttribute(0xC0, 35, h("fde8"))])
    assert bad.otc is None
    assert [u.action for u in bad.undecodable] == [Action.TREAT_AS_WITHDRAW]


def test_otc_ingress_rules_one_to_three():
    ing = roles.otc_ingress
    # 1: from a Customer or RS-Client, OTC present is a leak
    for remote in (Role.CUSTOMER, Role.RS_CLIENT):
        assert ing(remote, 64500, 1).ineligible
        assert ing(remote, 64500, None) == roles.OtcIngress(False)
    # 2: from a Peer, OTC must equal the peer's AS
    assert ing(Role.PEER, 64500, 64501).ineligible
    assert ing(Role.PEER, 64500, 64500) == roles.OtcIngress(False)
    # 3: from a Provider, Peer or RS without OTC, add the remote AS
    for remote in (Role.PROVIDER, Role.PEER, Role.RS):
        assert ing(remote, 64500, None) == roles.OtcIngress(False, 64500)
    # a Provider or RS that set OTC itself is accepted whatever the value: rule 2 is Peer only
    assert ing(Role.PROVIDER, 64500, 999) == roles.OtcIngress(False)
    assert ing(Role.RS, 64500, 999) == roles.OtcIngress(False)


def test_otc_egress_rules_one_and_two():
    egr = roles.otc_egress
    # 1: to a Customer, Peer or RS-Client, an absent OTC is added with the local AS
    for remote in (Role.CUSTOMER, Role.PEER, Role.RS_CLIENT):
        assert egr(remote, 65000, None) == roles.OtcEgress(True, 65000)
    # 2: with OTC already set it never goes to a Provider, Peer or RS
    for remote in (Role.PROVIDER, Role.PEER, Role.RS):
        assert egr(remote, 65000, 64500).advertise is False
    # to a Customer or RS-Client it goes unchanged: once set, OTC is preserved
    for remote in (Role.CUSTOMER, Role.RS_CLIENT):
        assert egr(remote, 65000, 64500) == roles.OtcEgress(True, 64500)
    # to a Provider or RS without OTC nothing is added
    for remote in (Role.PROVIDER, Role.RS):
        assert egr(remote, 65000, None) == roles.OtcEgress(True, None)


def test_a_leak_through_a_peer_is_seen_by_a_customer_link_three_hops_on():
    # section 5 paragraph 6: AS 64500 sends a route to a Peer, so OTC = 64500 is set on egress;
    # the route is leaked and received by a compliant AS from a Customer: it is a leak.
    sent = roles.otc_egress(Role.PEER, 64500, None)
    assert sent.otc == 64500
    assert roles.otc_ingress(Role.CUSTOMER, 64496, sent.otc).ineligible


def test_otc_applies_only_to_ipv4_ipv6_unicast():
    assert roles.otc_applies(1, 1) and roles.otc_applies(2, 1)
    assert not roles.otc_applies(1, 2) and not roles.otc_applies(25, 70)


# ---- attribute 25 (RFC 5701, RFC 7606 section 7.15) ----------------------------------------


V6 = "20010db8000000000000000000000001"


def test_ipv6_extended_community_fields_and_names():
    value = h("0002" + V6 + "0007") + h("4003" + V6 + "0009") + h("8001" + V6 + "0000")
    rt, ro, odd = communities.decode_ipv6_extended(value)
    assert rt.transitive and rt.subtype_name == "Route Target"
    assert rt.global_administrator == ipaddress.IPv6Address("2001:db8::1")
    assert rt.local_administrator == 7 and str(rt) == "rt:2001:db8::1:7"
    assert not ro.transitive and ro.subtype_name == "Route Origin"
    # an unrecognised type is kept whole and is not an error (RFC 7606 section 7.15)
    assert odd.subtype_name is None and str(odd) == "0x8001" + V6 + "0000"


@pytest.mark.parametrize("length", [0, 8, 19, 21, 39])
def test_ipv6_extended_communities_bad_length_is_treat_as_withdraw(length):
    with pytest.raises(ValueError):
        communities.decode_ipv6_extended(bytes(length))
    framed = bytes([0xC0, 25, length]) + bytes(length)
    walked = walk(framed, four_octet_as=True, internal=False)
    assert [issue.action for issue in walked.issues] == [Action.TREAT_AS_WITHDRAW]
    decoded = decode_attributes(walked.attributes)
    assert [u.action for u in decoded.undecodable] == [Action.TREAT_AS_WITHDRAW]


def test_decode_attributes_reads_attribute_25_and_it_is_no_longer_unknown():
    value = h("0002" + V6 + "0007")
    decoded = decode_attributes([RawAttribute(0xC0, 25, value)])
    assert len(decoded.ipv6_extended_communities) == 1
    assert decoded.unknown == () and decoded.undecodable == ()
    flagless = walk(bytes([0x40, 25, 20]) + value, four_octet_as=True, internal=False)
    assert [issue.action for issue in flagless.issues] == [Action.TREAT_AS_WITHDRAW]


# ---- other address families stay raw (row nlri.other-families) ------------------------------


@pytest.mark.parametrize(
    ("afi", "safi", "next_hop", "nlri_octets"),
    [
        (1, 128, bytes(12) + h("c0000201"), h("38 000641 0000fde800000064 0a0000")),  # VPN IPv4
        (1, 4, h("c0000201"), h("20 000641 c0000200")),  # labeled unicast
        (25, 70, h("c0000201"), h("02 15 0001")),  # EVPN
        (1, 133, h("c0000201"), h("03 810a00")),  # flowspec
        (16388, 71, h("c0000201"), h("0001")),  # BGP-LS
    ],
    ids=["vpnv4", "labeled", "evpn", "flowspec", "bgp-ls"],
)
def test_other_families_are_kept_raw_with_nlri_none_and_round_trip(
    afi, safi, next_hop, nlri_octets
):
    value = afi.to_bytes(2, "big") + bytes([safi, len(next_hop)]) + next_hop + b"\x00" + nlri_octets
    reach = nlri.parse_mp_reach(value)
    assert reach.nlri is None and reach.nlri_raw == nlri_octets
    assert (reach.afi, reach.safi, reach.next_hop) == (afi, safi, next_hop)
    assert nlri.encode_mp_reach(reach) == value
    unreach = nlri.parse_mp_unreach(afi.to_bytes(2, "big") + bytes([safi]) + nlri_octets)
    assert unreach.nlri is None and unreach.nlri_raw == nlri_octets
    # a whole UPDATE attribute carrying such a family is decoded without loss or fault
    decoded = decode_attributes([RawAttribute(0x80, 14, value)])
    assert decoded.mp_reach is not None and decoded.mp_reach.nlri_raw == nlri_octets
    assert decoded.undecodable == ()
