"""BGP message framing and decoding (RFC 4271 sections 4 and 6, RFC 5492, RFC 8654, RFC 9072).

Provenance of every byte string. RFC 4271 publishes no byte-level examples, so each message below
is built by hand from the field layout of its section (the section is named at the vector).
The one published vector is the UPDATE of RFC 6396 Appendix A Figure 16, used with the bytes of
its verified erratum 5511 (Total Path Attribute Length 0x23, NEXT_HOP c63364bc). Nothing here was
produced by this library's encoder or captured from a real speaker; interop evidence against a
non-Python implementation is a ROADMAP row.
"""

from __future__ import annotations

import ipaddress
import random
import time

import pytest

from pathattr import (
    Action,
    BgpError,
    Keepalive,
    Notification,
    Open,
    Update,
    decode,
    decode_header,
    decode_stream,
    encode,
)
from pathattr.message import Capability, OptionalParameter

MARKER = b"\xff" * 16


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


def msg(kind: int, body: bytes = b"") -> bytes:
    return MARKER + (19 + len(body)).to_bytes(2, "big") + bytes([kind]) + body


def update(withdrawn: bytes = b"", attrs: bytes = b"", nlri: bytes = b"") -> bytes:
    body = (
        len(withdrawn).to_bytes(2, "big") + withdrawn + len(attrs).to_bytes(2, "big") + attrs + nlri
    )
    return msg(2, body)


# RFC 4271 section 4.4: header only, Length 19, type 4.
KEEPALIVE = MARKER + h("0013 04")
# Section 4.5: code 6 (Cease), subcode 2, data "bye": Length = 21 + 3 = 24.
NOTIFICATION = MARKER + h("0018 03 06 02") + b"bye"
# RFC 6396 Appendix A Figure 16 with erratum 5511 applied (see the module docstring).
FIGURE_16 = h(
    "ffffffffffffffffffffffffffffffff 003e 02 0000 0023"
    " 40010102 40020e02030000fbf00000fbff0000fbf6 400304c63364bc c008 04fbf0000e"
    " 18cb0071"
)
# The same UPDATE exactly as printed before the erratum: Total Path Attribute Length 0x1f.
FIGURE_16_UNCORRECTED = FIGURE_16[:21] + h("001f") + FIGURE_16[23:]
# Section 4.2 plus RFC 5492 section 4: version 4, AS 64496, hold 90, id 192.0.2.1, one
# Capabilities parameter (type 2, length 2) holding capability code 6, length 0 (RFC 8654 s.3).
OPEN = msg(1, h("04 fbf0 005a c0000201 04 02 02 06 00"))
# RFC 9072 section 2 figure: Non-Ext OP Len 255, Non-Ext OP Type 255, extended length 5, then a
# parameter with a two-octet length (type 2, length 2, value 06 00).
OPEN_EXTENDED = msg(1, h("04 fbf0 005a c0000201 ff ff 0005 02 0002 0600"))


def test_decode_keepalive():
    assert decode(KEEPALIVE) == Keepalive()
    assert encode(Keepalive()) == KEEPALIVE
    assert len(KEEPALIVE) == 19


def test_decode_notification_cease_with_data():
    assert decode(NOTIFICATION) == Notification(6, 2, b"bye")
    assert encode(Notification(6, 2, b"bye")) == NOTIFICATION


def test_decode_notification_subcode_zero_accepted():
    # RFC 4271 verified erratum 4493: subcode 0 (Unspecific) is defined for every code.
    raw = MARKER + h("0015 03 06 00")
    assert decode(raw) == Notification(6, 0, b"")
    for code in range(1, 7):
        assert decode(msg(3, bytes([code, 0]))) == Notification(code, 0, b"")


def test_roundtrip_keepalive_notification():
    for message in (Keepalive(), Notification(3, 1), Notification(1, 2, b"\x00\x13")):
        assert decode(encode(message)) == message


def test_decode_bad_marker_raises_subcode_1():
    bad = bytearray(KEEPALIVE)
    bad[0] = 0
    with pytest.raises(BgpError) as caught:
        decode(bytes(bad))
    assert (caught.value.code, caught.value.subcode) == (1, 1)


def test_marker_with_single_zero_bit():
    bad = bytearray(KEEPALIVE)
    bad[15] = 0xFE
    with pytest.raises(BgpError) as caught:
        decode(bytes(bad))
    assert caught.value.subcode == 1


@pytest.mark.parametrize("length", [0, 18, 4097, 65535])
def test_decode_length_out_of_range_raises_subcode_2_with_length_in_data(length):
    raw = MARKER + length.to_bytes(2, "big") + b"\x04"
    with pytest.raises(BgpError) as caught:
        decode(raw)
    assert (caught.value.code, caught.value.subcode) == (1, 2)
    assert caught.value.data == length.to_bytes(2, "big")


def test_decode_keepalive_length_20_raises_bad_length():
    raw = MARKER + h("0014 04 00")
    with pytest.raises(BgpError) as caught:
        decode(raw)
    assert (caught.value.subcode, caught.value.data) == (2, h("0014"))


def test_decode_notification_length_20_raises_bad_length():
    raw = MARKER + h("0014 03 06")
    with pytest.raises(BgpError) as caught:
        decode(raw)
    assert (caught.value.subcode, caught.value.data) == (2, h("0014"))


def test_open_and_update_below_their_minimum_raise_bad_length():
    with pytest.raises(BgpError) as caught:
        decode(msg(1, bytes(9)))  # 28 octets, OPEN needs 29
    assert caught.value.subcode == 2
    with pytest.raises(BgpError) as other:
        decode(msg(2, bytes(3)))  # 22 octets, UPDATE needs 23
    assert other.value.subcode == 2


@pytest.mark.parametrize("kind", [0, 6, 255])
def test_decode_unknown_type_raises_subcode_3_with_type_in_data(kind):
    raw = MARKER + h("0013") + bytes([kind])
    with pytest.raises(BgpError) as caught:
        decode(raw)
    assert (caught.value.code, caught.value.subcode) == (1, 3)
    assert caught.value.data == bytes([kind])


def test_decode_length_field_vs_buffer_mismatch():
    for raw in (NOTIFICATION[:-1], NOTIFICATION + b"\x00"):
        with pytest.raises(BgpError) as caught:
            decode(raw)
        assert caught.value.subcode == 2
    with pytest.raises(BgpError):
        decode(KEEPALIVE[:10])


def test_decode_header_reads_only_the_header():
    assert decode_header(NOTIFICATION).length == 24
    assert decode_header(NOTIFICATION).type == 3


def test_decode_stream_returns_partial_tail():
    stream = KEEPALIVE + NOTIFICATION + KEEPALIVE[:10]
    messages, used = decode_stream(stream)
    assert messages == [Keepalive(), Notification(6, 2, b"bye")]
    assert used == len(KEEPALIVE) + len(NOTIFICATION)
    messages, used = decode_stream(KEEPALIVE + NOTIFICATION[:20])
    assert (messages, used) == ([Keepalive()], 19)
    assert decode_stream(b"") == ([], 0)


def test_decode_stream_resyncs_never():
    # A bad Marker mid-stream raises; the codec does not scan for the next Marker.
    bad = bytearray(KEEPALIVE)
    bad[3] = 0
    with pytest.raises(BgpError) as caught:
        decode_stream(KEEPALIVE + bytes(bad) + KEEPALIVE)
    assert caught.value.subcode == 1
    # ... and a bad Marker is caught as soon as the bytes that show it have arrived.
    with pytest.raises(BgpError):
        decode_stream(b"\xff\xff\x00")


def test_decode_accepts_bytearray_memoryview():
    assert decode(bytearray(KEEPALIVE)) == Keepalive()
    assert decode(memoryview(KEEPALIVE)) == Keepalive()
    messages, used = decode_stream(memoryview(bytearray(KEEPALIVE * 2)))
    assert (len(messages), used) == (2, 38)


def test_extended_max_length_65535_only_when_enabled():
    # RFC 8654 section 4: up to 65,535 octets once the capability is in use; section 5: never
    # accept more than 4096 without it.
    big = update(attrs=h("c0 ff") + b"\x00", nlri=b"")  # small, to learn the framing
    assert decode(big)
    nlri = b"".join(bytes([32]) + bytes([10, i >> 8, i & 255]) + b"\x01" for i in range(1500))
    raw = update(attrs=b"", nlri=nlri)  # 23 + 7500 octets of NLRI: 7523
    assert len(raw) > 4096
    with pytest.raises(BgpError) as caught:
        decode(raw)
    assert caught.value.subcode == 2
    assert len(decode(raw, max_length=65535).nlri) == 1500
    with pytest.raises(ValueError, match="exceeds"):
        encode(decode(raw, max_length=65535))
    assert encode(decode(raw, max_length=65535), max_length=65535) == raw


def test_open_is_never_extended_length():
    # RFC 8654 section 4: OPEN and KEEPALIVE are exempt from extended messages.
    params = h("02 00fa") + bytes(250)
    body = h("04 fbf0 005a c0000201 ff ff") + (len(params)).to_bytes(2, "big") + params
    assert len(msg(1, body)) < 4096
    padding = bytes(4100)
    huge = msg(1, h("04 fbf0 005a c0000201 ff ff") + len(padding).to_bytes(2, "big") + padding)
    with pytest.raises(BgpError) as caught:
        decode(huge, max_length=65535)
    assert caught.value.subcode == 2


def test_length_zero_and_65535_without_extended():
    for length in (0, 65535):
        with pytest.raises(BgpError):
            decode_header(MARKER + length.to_bytes(2, "big") + b"\x02")


def test_encode_notification_data_over_limit_raises():
    with pytest.raises(ValueError, match="exceeds"):
        encode(Notification(6, 0, bytes(4096 - 21 + 1)))
    assert len(encode(Notification(6, 0, bytes(4096 - 21)))) == 4096
    with pytest.raises(ValueError, match="one octet"):
        encode(Notification(256, 0))


def test_many_small_messages_linear_time():
    count = 20000
    started = time.perf_counter()
    messages, used = decode_stream(KEEPALIVE * count)
    elapsed = time.perf_counter() - started
    assert len(messages) == count
    assert used == 19 * count
    assert elapsed < 5.0


def test_decode_open_with_capability():
    opened = decode(OPEN)
    assert isinstance(opened, Open)
    assert (opened.version, opened.my_as, opened.hold_time) == (4, 64496, 90)
    assert opened.bgp_id == ipaddress.IPv4Address("192.0.2.1")
    assert opened.parameters == (OptionalParameter(2, h("0600")),)
    assert opened.capabilities == (Capability(6, b""),)
    assert opened.extended_parameters is False
    assert encode(opened) == OPEN


def test_decode_open_returns_values_unjudged():
    # RFC 4271 section 6.2 policy (version, hold time 1 or 2, bad identifier) is a speaker's job.
    raw = msg(1, h("05 0001 0001 00000000 00"))
    opened = decode(raw)
    assert (opened.version, opened.hold_time) == (5, 1)


def test_decode_open_extended_optional_parameters():
    # RFC 9072 section 2: the extended encoding is accepted even for a short parameter list.
    opened = decode(OPEN_EXTENDED)
    assert opened.extended_parameters is True
    assert opened.capabilities == (Capability(6, b""),)
    assert encode(opened) == OPEN_EXTENDED


def test_encode_open_switches_to_extended_encoding_over_255_octets():
    caps = b"".join(bytes([99, 1, i % 256]) for i in range(100))  # 300 octets of TLVs
    opened = Open(4, 64496, 90, ipaddress.IPv4Address("192.0.2.1"), (OptionalParameter(2, caps),))
    raw = encode(opened)
    assert raw[19 + 9 : 19 + 11] == b"\xff\xff"  # Non-Ext OP Len 255, Non-Ext OP Type 255
    back = decode(raw)
    assert back.extended_parameters is True
    assert len(back.capabilities) == 100


def test_decode_open_merges_multiple_capability_parameters():
    # RFC 5492 section 4: several Capabilities parameters are processed as one list.
    body = h("04 fbf0 005a c0000201 08 02 02 06 00 02 02 63 00")
    opened = decode(msg(1, body))
    assert opened.capabilities == (Capability(6, b""), Capability(0x63, b""))


def test_decode_open_keeps_unknown_optional_parameters():
    body = h("04 fbf0 005a c0000201 03 07 01 aa")
    opened = decode(msg(1, body))
    assert opened.parameters == (OptionalParameter(7, h("aa")),)


def test_decode_open_malformed_parameters_are_open_error_unspecific():
    cases = {
        "capability overruns": h("04 fbf0 005a c0000201 04 02 02 06 05"),
        "parameter overruns": h("04 fbf0 005a c0000201 03 02 09 00"),
        "lone parameter octet": h("04 fbf0 005a c0000201 01 02"),
    }
    for name, body in cases.items():
        with pytest.raises(BgpError) as caught:
            decode(msg(1, body))
        assert (caught.value.code, caught.value.subcode) == (2, 0), name


def test_decode_open_optional_parameters_length_must_match_the_message():
    with pytest.raises(BgpError) as caught:
        decode(msg(1, h("04 fbf0 005a c0000201 02 02 02 06 00")))  # claims 2, carries 4
    assert caught.value.code == 1
    assert caught.value.subcode == 2


def test_decode_update_figure_16_corrected():
    update_message = decode(FIGURE_16)
    assert isinstance(update_message, Update)
    assert update_message.withdrawn == ()
    assert update_message.nlri == (ipaddress.IPv4Network("203.0.113.0/24"),)
    assert [a.type_code for a in update_message.attributes] == [1, 2, 3, 8]
    assert update_message.issues == ()
    assert update_message.action is Action.NONE
    assert encode(update_message) == FIGURE_16


def test_figure_16_uncorrected_is_refused_not_misread():
    # With the printed length 0x1f the attributes end three octets early and the NLRI field
    # starts at 0xfb: a prefix length of 251, which RFC 7606 section 5.3 calls syntactically wrong.
    with pytest.raises(BgpError) as caught:
        decode(FIGURE_16_UNCORRECTED)
    assert (caught.value.code, caught.value.subcode) == (3, 10)


def test_decode_empty_update_is_the_legacy_end_of_rib():
    raw = update()
    assert len(raw) == 23
    assert decode(raw) == Update()


def test_decode_update_withdrawn_routes_only():
    # 198.51.100.0/24 -> 18 c6 33 64; 10.0.0.0/8 -> 08 0a; default route -> 00
    raw = update(withdrawn=h("18c63364 080a 00"))
    parsed = decode(raw)
    assert parsed.withdrawn == (
        ipaddress.IPv4Network("198.51.100.0/24"),
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("0.0.0.0/0"),
    )
    assert parsed.action is Action.NONE
    assert encode(parsed) == raw


def test_decode_update_lengths_too_large_is_malformed_attribute_list():
    # RFC 4271 section 6.3 / RFC 7606 section 3 (b)
    too_big_attrs = msg(2, h("0000 0010") + h("400101 02"))
    too_big_withdrawn = msg(2, h("0009 0000") + b"\x00")
    no_room = msg(2, h("0001 00 00"))  # withdrawn length leaves no room for the attribute length
    for raw in (too_big_attrs, too_big_withdrawn, no_room):
        with pytest.raises(BgpError) as caught:
            decode(raw)
        assert (caught.value.code, caught.value.subcode) == (3, 1), raw.hex()


def test_decode_update_invalid_network_field():
    for nlri in (h("21 01020304 05"), h("18 c633"), h("ff")):
        with pytest.raises(BgpError) as caught:
            decode(update(nlri=nlri))
        assert (caught.value.code, caught.value.subcode) == (3, 10)
    with pytest.raises(BgpError):
        decode(update(withdrawn=h("18 c633")))


def test_update_nlri_missing_mandatory_attributes_is_treat_as_withdraw():
    # RFC 7606 section 3 (d): NLRI but no ORIGIN, AS_PATH or NEXT_HOP.
    parsed = decode(update(nlri=h("08 0a")))
    assert parsed.action is Action.TREAT_AS_WITHDRAW
    assert {i.type_code for i in parsed.issues} == {1, 2, 3}


def test_update_attribute_error_without_nlri_escalates_to_session_reset():
    # RFC 7606 section 5.2: a bad ORIGIN (treat-as-withdraw) in an UPDATE with no reachable NLRI.
    attrs = h("40 01 02 00 00")
    parsed = decode(update(attrs=attrs))
    assert parsed.action is Action.SESSION_RESET
    with_nlri = decode(update(attrs=attrs, nlri=h("08 0a")))
    assert with_nlri.action is Action.TREAT_AS_WITHDRAW


def test_update_discard_only_errors_do_not_escalate():
    # ATOMIC_AGGREGATE of length 1 is attribute discard (RFC 7606 section 7.6); with no NLRI
    # section 5.2 only escalates approaches stronger than discard.
    parsed = decode(update(attrs=h("40 06 01 00")))
    assert parsed.action is Action.ATTRIBUTE_DISCARD
    assert parsed.attributes == ()


def test_update_framing_fault_without_nlri_is_session_reset():
    # RFC 7606 section 4 gives treat-as-withdraw, section 5.2 then requires a reset: there is
    # no reachable NLRI to withdraw by.
    parsed = decode(update(attrs=h("40 01 05 00")))
    assert parsed.action is Action.SESSION_RESET


def test_update_with_only_mp_unreach_and_a_bad_origin_is_not_special_cased():
    parsed = decode(update(attrs=h("80 0f 03 00 02 01")))
    assert parsed.action is Action.NONE


def test_hostile_random_bytes_only_raise_bgp_error():
    rng = random.Random(4271)
    for _ in range(3000):
        kind = rng.choice([1, 2, 3, 4])
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        raw = msg(kind, body)
        try:
            decode(raw)
        except BgpError:
            continue
    for _ in range(500):
        junk = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        try:
            decode_stream(junk)
        except BgpError:
            continue


def test_package_code_has_no_assert_statements():
    # Validation is done with explicit raises: nothing here relies on assert in package code.
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "pathattr"
    offenders = [p.name for p in root.glob("*.py") if "\n    assert " in p.read_text("utf-8")]
    assert not offenders
