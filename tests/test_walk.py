"""Path attribute walker and RFC 7606 verdicts (RFC 4271 section 4.3, RFC 7606 sections 2 to 7).

Provenance: RFC 4271 and RFC 7606 publish no byte vectors. Attribute bytes are built from the
section 4.3 layout (flags octet, type code, one- or two-octet length, value). The two published
samples are RFC 6396 Appendix A Figure 16 and Figure 19 as corrected by verified erratum 5511 and
6640; Figure 19 is the MRT RIB form, so only its attribute framing (including an Extended Length
attribute, flags 0x50) is used, not its MP_REACH_NLRI contents.
"""

from __future__ import annotations

import random

from pathattr import Action, RawAttribute, walk
from pathattr.attribute import missing_mandatory, strongest

KW = {"four_octet_as": True, "internal": False}


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


def attr(flags: int, code: int, value: bytes) -> bytes:
    return bytes([flags, code, len(value)]) + value


ORIGIN = h("40 01 01 00")
AS_PATH = h("40 02 06 02 01 0000fbf0")
NEXT_HOP = h("40 03 04 c0000201")


def test_walk_figure16_attributes():
    raw = h("40010102 40020e02030000fbf00000fbff0000fbf6 400304c63364bc c008 04fbf0000e")
    walked = walk(raw, **KW)
    assert [a.type_code for a in walked.attributes] == [1, 2, 3, 8]
    assert [a.offset for a in walked.attributes] == [0, 4, 21, 28]
    assert walked.issues == ()
    assert b"".join(a.encode() for a in walked.attributes) == raw


def test_walk_extended_length_attribute():
    # RFC 6396 Appendix A Figure 19 (erratum 6640): AS_PATH carries flags 0x50, length 00 0e.
    raw = h(
        "40 01 01 00 50 02 00 0e 02 03 00 00 fb f0 00 00 fb ff 00 00 fb f6"
        " 80 0e 21 20 20 01 0d b8 00 0d 00 ff 00 00 00 00 00 00 01 87"
        " fe 80 00 00 00 00 00 00 02 12 f2 ff fe 9f 1b 00"
    )
    walked = walk(raw, **KW)
    assert [a.type_code for a in walked.attributes] == [1, 2, 14]
    assert walked.attributes[1].extended_length
    assert len(walked.attributes[1].value) == 14
    assert walked.issues == ()
    assert b"".join(a.encode() for a in walked.attributes) == raw


def test_walk_length_overrun_is_treat_as_withdraw():
    # RFC 7606 section 4, first case: not a session reset (the research review had this wrong).
    walked = walk(ORIGIN + h("40 02 09 02"), **KW)
    assert [a.type_code for a in walked.attributes] == [1]
    assert walked.action is Action.TREAT_AS_WITHDRAW
    assert walked.issues[0].type_code == 2


def test_walk_truncated_header():
    # RFC 7606 section 4, second case: fewer than three octets (four with Extended Length).
    for tail in (h("40"), h("40 02"), h("50 02 00")):
        walked = walk(ORIGIN + tail, **KW)
        assert walked.action is Action.TREAT_AS_WITHDRAW, tail.hex()
        assert len(walked.attributes) == 1


def test_walk_zero_attributes():
    walked = walk(b"", **KW)
    assert walked.attributes == ()
    assert walked.action is Action.NONE


def test_walk_duplicate_nonmp_attribute_keeps_first():
    # RFC 7606 section 3 (g)
    walked = walk(ORIGIN + h("40 01 01 02") + AS_PATH, **KW)
    assert [a.type_code for a in walked.attributes] == [1, 2]
    assert walked.get(1).value == b"\x00"
    assert walked.action is Action.ATTRIBUTE_DISCARD
    assert walked.issues[0].attribute.value == b"\x02"


def test_walk_duplicate_unknown_attribute_keeps_first():
    one = h("c0 63 01 aa")
    walked = walk(one + h("c0 63 01 bb"), **KW)
    assert walked.attributes == (RawAttribute(0xC0, 0x63, b"\xaa", 0),)


def test_walk_duplicate_mp_reach_is_session_reset():
    mp = h("80 0e 05 00 02 01 00 00")
    walked = walk(mp + mp, **KW)
    assert walked.action is Action.SESSION_RESET
    unreach = h("80 0f 03 00 02 01")
    assert walk(unreach + unreach, **KW).action is Action.SESSION_RESET


def test_walk_wellknown_with_optional_bit_is_treat_as_withdraw():
    # RFC 7606 section 3 (c): flags in conflict with the type.
    walked = walk(h("c0 01 01 00"), **KW)
    assert walked.action is Action.TREAT_AS_WITHDRAW
    assert walk(h("40 04 04 00000000"), **KW).action is Action.TREAT_AS_WITHDRAW  # MED transitive


def test_walk_mp_flags_conflict_is_afi_safi_disable():
    walked = walk(h("c0 0e 05 00 02 01 00 00"), **KW)
    assert walked.action is Action.AFI_SAFI_DISABLE


def test_walk_aggregator_bad_length_is_discard():
    # AS 0 is a different fault (RFC 7607), so the well-formed ones name AS 1.
    six = attr(0xC0, 7, b"\x00\x01" + bytes(4))
    assert walk(six, four_octet_as=False, internal=False).action is Action.NONE
    assert walk(six, four_octet_as=True, internal=False).action is Action.ATTRIBUTE_DISCARD
    eight_ok = attr(0xC0, 7, b"\x00\x00\x00\x01" + bytes(4))
    assert walk(eight_ok, **KW).action is Action.NONE
    eight = walk(eight_ok, four_octet_as=False, internal=False)
    assert eight.action is Action.ATTRIBUTE_DISCARD


def test_walk_discarded_attribute_is_removed_but_kept_in_the_issue():
    walked = walk(attr(0x40, 6, b"\x00"), **KW)
    assert walked.attributes == ()
    assert walked.issues[0].attribute.value == b"\x00"


def test_walk_unused_flag_bits_ignored():
    walked = walk(h("4f 01 01 00"), **KW)
    assert walked.action is Action.NONE
    assert walked.attributes[0].flags == 0x4F  # kept as received


def test_walk_unknown_attribute_preserved_raw():
    raw = h("e0 63 03 010203")  # optional, transitive, partial, unknown code 99
    walked = walk(raw, **KW)
    assert walked.action is Action.NONE
    attribute = walked.attributes[0]
    assert (attribute.flags, attribute.type_code, attribute.value) == (0xE0, 99, h("010203"))
    assert attribute.partial
    assert attribute.encode() == raw


def test_walk_origin_checks():
    assert walk(h("40 01 01 03"), **KW).action is Action.TREAT_AS_WITHDRAW
    assert walk(h("40 01 02 00 00"), **KW).action is Action.TREAT_AS_WITHDRAW
    assert walk(h("40 01 00"), **KW).action is Action.TREAT_AS_WITHDRAW  # zero length, section 4


def test_walk_as_path_malformed_cases():
    # RFC 7606 section 7.2: unknown type, overrun, one-octet underrun, zero segment length.
    for value in ("05 01 0000fbf0", "02 02 0000fbf0", "02 01 0000fbf0 02", "02 00"):
        assert walk(attr(0x40, 2, h(value)), **KW).action is Action.TREAT_AS_WITHDRAW, value
    assert walk(attr(0x40, 2, b""), **KW).action is Action.NONE  # an empty AS_PATH is valid
    assert walk(attr(0x40, 2, h("03 01 0000fbf0")), **KW).action is Action.NONE  # RFC 5065 type
    two = walk(attr(0x40, 2, h("02 01 fbf0")), four_octet_as=False, internal=False)
    assert two.action is Action.NONE


def test_walk_fixed_length_attributes():
    assert walk(attr(0x40, 3, bytes(5)), **KW).action is Action.TREAT_AS_WITHDRAW
    assert walk(attr(0x80, 4, bytes(3)), **KW).action is Action.TREAT_AS_WITHDRAW
    assert walk(attr(0x40, 6, b""), **KW).action is Action.NONE


def test_walk_community_lengths():
    assert walk(attr(0xC0, 8, bytes(8)), **KW).action is Action.NONE
    assert walk(attr(0xC0, 8, bytes(6)), **KW).action is Action.TREAT_AS_WITHDRAW
    assert walk(attr(0xC0, 8, b""), **KW).action is Action.TREAT_AS_WITHDRAW
    assert walk(attr(0xC0, 16, bytes(16)), **KW).action is Action.NONE
    assert walk(attr(0xC0, 16, bytes(12)), **KW).action is Action.TREAT_AS_WITHDRAW


def test_walk_local_pref_originator_cluster_by_session_kind():
    # RFC 7606 sections 7.5, 7.9, 7.10: discarded from an external neighbour, length-checked from
    # an internal one.
    for flags, code, good, bad in (
        (0x40, 5, bytes(4), bytes(3)),
        (0x80, 9, bytes(4), bytes(3)),
        (0x80, 10, bytes(8), bytes(6)),
    ):
        ext = walk(attr(flags, code, good), four_octet_as=True, internal=False)
        assert ext.action is Action.ATTRIBUTE_DISCARD
        assert ext.attributes == ()
        ibgp = walk(attr(flags, code, good), four_octet_as=True, internal=True)
        assert ibgp.action is Action.NONE
        broken = walk(attr(flags, code, bad), four_octet_as=True, internal=True)
        assert broken.action is Action.TREAT_AS_WITHDRAW


def test_walk_mp_minimum_lengths():
    assert walk(attr(0x80, 14, bytes(4)), **KW).action is Action.AFI_SAFI_DISABLE
    assert walk(attr(0x80, 14, bytes(5)), **KW).action is Action.NONE
    assert walk(attr(0x80, 15, bytes(2)), **KW).action is Action.AFI_SAFI_DISABLE
    assert walk(attr(0x80, 15, bytes(3)), **KW).action is Action.NONE


def test_walk_strongest_action_wins():
    walked = walk(ORIGIN + attr(0x40, 6, b"\x00") + attr(0x40, 3, bytes(5)), **KW)
    assert {i.action for i in walked.issues} == {
        Action.ATTRIBUTE_DISCARD,
        Action.TREAT_AS_WITHDRAW,
    }
    assert walked.action is Action.TREAT_AS_WITHDRAW
    assert strongest(()) is Action.NONE
    assert Action.SESSION_RESET > Action.AFI_SAFI_DISABLE > Action.TREAT_AS_WITHDRAW
    assert Action.TREAT_AS_WITHDRAW > Action.ATTRIBUTE_DISCARD > Action.NONE


def test_walk_attribute_count_cap():
    # 21845 minimum-size attributes are the most a 65535-octet field holds; the walk stays linear.
    raw = h("c0 63 00") * 21845
    walked = walk(raw, **KW)
    assert len(walked.attributes) == 1  # all the same type: later ones are duplicates
    assert len(walked.issues) == 21844
    distinct = b"".join(bytes([0xC0, code, 0]) for code in range(100, 256)) * 80
    assert len(walk(distinct, **KW).attributes) == 156


def test_walk_never_raises_index_error():
    rng = random.Random(7606)
    for _ in range(5000):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        walked = walk(raw, four_octet_as=rng.random() < 0.5, internal=rng.random() < 0.5)
        for attribute in walked.attributes:
            assert 0 <= attribute.offset < max(len(raw), 1)


def test_missing_mandatory_needs_reachable_nlri():
    empty = walk(b"", **KW)
    assert missing_mandatory(empty, has_nlri=False, has_mp_reach=False) == ()
    both = missing_mandatory(empty, has_nlri=True, has_mp_reach=False)
    assert {i.type_code for i in both} == {1, 2, 3}
    mp_only = missing_mandatory(empty, has_nlri=False, has_mp_reach=True)
    assert {i.type_code for i in mp_only} == {1, 2}  # NEXT_HOP is discretionary with MP_REACH
    full = walk(ORIGIN + AS_PATH + NEXT_HOP, **KW)
    assert missing_mandatory(full, has_nlri=True, has_mp_reach=False) == ()


def test_raw_attribute_build_sets_extended_length_only_when_needed():
    short = RawAttribute.build(99, bytes(255), optional=True, transitive=True)
    assert not short.extended_length
    assert len(short.encode()) == 258
    long = RawAttribute.build(99, bytes(256), optional=True, transitive=True)
    assert long.extended_length
    assert walk(long.encode(), **KW).attributes[0].value == bytes(256)
