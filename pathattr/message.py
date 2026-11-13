"""the four message types with header and length discipline (RFC 4271).

``decode`` takes exactly one complete BGP message and returns a typed value or raises
:class:`~pathattr.errors.BgpError` carrying the NOTIFICATION the speaker must send (RFC 4271
section 6.1 for the header, 6.2 for OPEN, 6.3 and RFC 7606 for UPDATE). It never returns a
partial message and never reads past the Length field. ``decode_stream`` frames a TCP-style byte
stream and leaves an incomplete tail alone; it does not resynchronise after a bad Marker.

What is decoded:

* KEEPALIVE (section 4.4) and NOTIFICATION (section 4.5, any subcode including 0 per verified
  erratum 4493);
* OPEN (section 4.2) with the Optional Parameters, the Capabilities parameter of RFC 5492 and the
  extended optional parameters length of RFC 9072. The OPEN is *framed*, not *judged*: version,
  hold time and BGP Identifier values are returned as received, and unknown optional parameters
  are kept, because rejecting them is a speaker's policy under section 6.2, not a codec's;
* UPDATE (section 4.3): withdrawn routes, path attributes (walked per RFC 7606, see
  :mod:`pathattr.attribute`) and NLRI, both IPv4 prefix lists.

ROUTE-REFRESH (type 5, RFC 2918) is not decoded yet: it is reported as a Bad Message Type.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import IntEnum

from . import limits
from .attribute import (
    Action,
    AttrType,
    Issue,
    RawAttribute,
    missing_mandatory,
    strongest,
    walk,
)
from .errors import BgpError, ErrorCode, HeaderSubcode, OpenSubcode, UpdateSubcode
from .nlri import encode_prefix_list, parse_prefix_list

__all__ = [
    "BgpError",
    "Capability",
    "Header",
    "Keepalive",
    "Message",
    "MessageType",
    "Notification",
    "Open",
    "OptionalParameter",
    "Update",
    "decode",
    "decode_header",
    "decode_stream",
    "encode",
]

MARKER = b"\xff" * 16
CAPABILITIES_PARAMETER = 2  # RFC 5492 section 4
EXTENDED_PARAMETERS_TYPE = 255  # RFC 9072 section 2


class MessageType(IntEnum):
    """Message type codes (RFC 4271 section 4.1)."""

    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4


_MIN_LENGTH = {
    MessageType.OPEN: limits.MIN_OPEN_LENGTH,
    MessageType.UPDATE: limits.MIN_UPDATE_LENGTH,
    MessageType.NOTIFICATION: limits.MIN_NOTIFICATION_LENGTH,
    MessageType.KEEPALIVE: limits.HEADER_LENGTH,
}


@dataclass(frozen=True, slots=True)
class Header:
    length: int
    type: int


@dataclass(frozen=True, slots=True)
class Keepalive:
    """A KEEPALIVE: the header and nothing else (RFC 4271 section 4.4)."""


@dataclass(frozen=True, slots=True)
class Notification:
    code: int
    subcode: int
    data: bytes = b""


@dataclass(frozen=True, slots=True)
class Capability:
    """One <code, length, value> capability TLV (RFC 5492 section 4)."""

    code: int
    value: bytes


@dataclass(frozen=True, slots=True)
class OptionalParameter:
    type: int
    value: bytes


@dataclass(frozen=True, slots=True)
class Open:
    version: int
    my_as: int
    hold_time: int
    bgp_id: ipaddress.IPv4Address
    parameters: tuple[OptionalParameter, ...] = ()
    extended_parameters: bool = False
    """True when the RFC 9072 extended encoding was used, or is to be used when encoding."""

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        """Every capability from every Capabilities parameter, in order (RFC 5492 section 4).

        Several Capabilities parameters are processed as one list, as RFC 5492 section 4 says a
        speaker MUST be prepared to receive.
        """
        found: list[Capability] = []
        for parameter in self.parameters:
            if parameter.type != CAPABILITIES_PARAMETER:
                continue
            value, pos = parameter.value, 0
            while pos < len(value):
                if len(value) - pos < 2 or pos + 2 + value[pos + 1] > len(value):
                    raise BgpError(
                        ErrorCode.OPEN_MESSAGE,
                        OpenSubcode.UNSPECIFIC,
                        message="malformed capability in the Capabilities parameter",
                    )
                found.append(Capability(value[pos], value[pos + 2 : pos + 2 + value[pos + 1]]))
                pos += 2 + value[pos + 1]
        return tuple(found)


@dataclass(frozen=True, slots=True)
class Update:
    """An UPDATE with its RFC 7606 verdict.

    ``issues`` and ``action`` are the attribute faults and the strongest approach to take
    (RFC 7606 section 3 (h)); ``action`` is ``Action.NONE`` for a clean UPDATE. When it is
    ``TREAT_AS_WITHDRAW`` the caller withdraws every route the message announces. Attributes
    whose approach is attribute discard are absent from ``attributes`` and present in
    ``issues``, so ``encode(decode(x))`` equals ``x`` only for an UPDATE without discards.
    """

    withdrawn: tuple[ipaddress.IPv4Network, ...] = ()
    attributes: tuple[RawAttribute, ...] = ()
    nlri: tuple[ipaddress.IPv4Network, ...] = ()
    issues: tuple[Issue, ...] = ()
    action: Action = Action.NONE


Message = Keepalive | Notification | Open | Update


def _header_error(subcode: HeaderSubcode, data: bytes, text: str) -> BgpError:
    return BgpError(ErrorCode.MESSAGE_HEADER, subcode, data, text)


def _bad_length(length: int) -> BgpError:
    return _header_error(
        HeaderSubcode.BAD_MESSAGE_LENGTH, length.to_bytes(2, "big"), f"bad message length {length}"
    )


def decode_header(raw: bytes, *, max_length: int = limits.MAX_MESSAGE_LENGTH) -> Header:
    """Validate and return the 19-octet header at the start of ``raw`` (RFC 4271 section 6.1).

    Checks, in this order: the Marker is all ones (Connection Not Synchronized); the Length is
    within 19 and ``max_length`` and not below the minimum for its type, and equals 19 for a
    KEEPALIVE (Bad Message Length, Data = the Length field); the Type is known (Bad Message
    Type, Data = the Type octet). OPEN is also never longer than 4096 whatever ``max_length``
    is, because RFC 8654 section 4 exempts OPEN and KEEPALIVE from extended messages.
    """
    raw = bytes(raw[: limits.HEADER_LENGTH])
    present = min(len(raw), 16)
    if raw[:present] != MARKER[:present]:
        raise _header_error(
            HeaderSubcode.CONNECTION_NOT_SYNCHRONIZED, b"", "marker is not all ones"
        )
    if len(raw) < limits.HEADER_LENGTH:
        raise _bad_length(len(raw))
    length = int.from_bytes(raw[16:18], "big")
    kind = raw[18]
    if length < limits.HEADER_LENGTH or length > max_length:
        raise _bad_length(length)
    if kind not in _MIN_LENGTH:
        raise _header_error(
            HeaderSubcode.BAD_MESSAGE_TYPE, bytes([kind]), f"bad message type {kind}"
        )
    message_type = MessageType(kind)
    if length < _MIN_LENGTH[message_type]:
        raise _bad_length(length)
    if message_type is MessageType.KEEPALIVE and length != limits.HEADER_LENGTH:
        raise _bad_length(length)
    if message_type is MessageType.OPEN and length > limits.MAX_MESSAGE_LENGTH:
        raise _bad_length(length)
    return Header(length, kind)


def decode(
    raw: bytes,
    *,
    max_length: int = limits.MAX_MESSAGE_LENGTH,
    four_octet_as: bool = True,
    internal: bool = False,
) -> Message:
    """Decode exactly one complete BGP message (RFC 4271 section 4, RFC 7606).

    ``raw`` must be the whole message: a buffer whose length differs from the header's Length
    is Bad Message Length. ``max_length`` is 4096, or 65535 once the Extended Message
    capability has been negotiated (RFC 8654 section 4); never raise it for a peer that has not
    advertised the capability (RFC 8654 section 5). ``four_octet_as`` and ``internal`` describe
    the session for the UPDATE checks of RFC 7606 section 7 (see :func:`pathattr.attribute.walk`).
    Raises :class:`BgpError`; never returns a partial message.
    """
    raw = bytes(raw)
    header = decode_header(raw, max_length=max_length)
    if len(raw) != header.length:
        raise _bad_length(header.length)
    body = raw[limits.HEADER_LENGTH :]
    if header.type == MessageType.KEEPALIVE:
        return Keepalive()
    if header.type == MessageType.NOTIFICATION:
        return Notification(body[0], body[1], body[2:])
    if header.type == MessageType.OPEN:
        return _decode_open(body, header.length)
    return _decode_update(body, header.length, four_octet_as=four_octet_as, internal=internal)


def decode_stream(
    buf: bytes | bytearray | memoryview,
    *,
    max_length: int = limits.MAX_MESSAGE_LENGTH,
    four_octet_as: bool = True,
    internal: bool = False,
) -> tuple[list[Message], int]:
    """Decode the complete messages at the front of a byte stream.

    Returns the messages and the number of octets consumed; an incomplete message at the end is
    left unconsumed. A header fault, including a Marker that is not all ones, raises
    :class:`BgpError` immediately: a BGP stream has no resynchronisation (RFC 4271 section 6.1,
    Connection Not Synchronized), so this never scans for the next Marker.
    """
    data = memoryview(buf)
    messages: list[Message] = []
    pos = 0
    while len(data) - pos > 0:
        if len(data) - pos < limits.HEADER_LENGTH:
            decode_header_prefix = bytes(data[pos:])
            present = min(len(decode_header_prefix), 16)
            if decode_header_prefix[:present] != MARKER[:present]:
                raise _header_error(
                    HeaderSubcode.CONNECTION_NOT_SYNCHRONIZED, b"", "marker is not all ones"
                )
            break
        header = decode_header(bytes(data[pos : pos + limits.HEADER_LENGTH]), max_length=max_length)
        if len(data) - pos < header.length:
            break
        messages.append(
            decode(
                bytes(data[pos : pos + header.length]),
                max_length=max_length,
                four_octet_as=four_octet_as,
                internal=internal,
            )
        )
        pos += header.length
    return messages, pos


def _decode_open(body: bytes, length: int) -> Open:
    version = body[0]
    my_as = int.from_bytes(body[1:3], "big")
    hold_time = int.from_bytes(body[3:5], "big")
    bgp_id = ipaddress.IPv4Address(body[5:9])
    opt_len = body[9]
    rest = body[10:]
    extended = opt_len != 0 and len(rest) >= 1 and rest[0] == EXTENDED_PARAMETERS_TYPE
    if extended:
        if len(rest) < 3:
            raise BgpError(
                ErrorCode.OPEN_MESSAGE, OpenSubcode.UNSPECIFIC, message="truncated extended length"
            )
        declared = int.from_bytes(rest[1:3], "big")
        params, width = rest[3:], 2
    else:
        declared, params, width = opt_len, rest, 1
    if declared != len(params):
        # RFC 4271 section 4.1: no padding, so the Length is the smallest the content needs.
        raise _bad_length(length)
    parameters: list[OptionalParameter] = []
    pos = 0
    while pos < len(params):
        if len(params) - pos < 1 + width:
            raise BgpError(
                ErrorCode.OPEN_MESSAGE,
                OpenSubcode.UNSPECIFIC,
                message="truncated optional parameter",
            )
        kind = params[pos]
        size = int.from_bytes(params[pos + 1 : pos + 1 + width], "big")
        start = pos + 1 + width
        if start + size > len(params):
            raise BgpError(
                ErrorCode.OPEN_MESSAGE,
                OpenSubcode.UNSPECIFIC,
                message="optional parameter overruns",
            )
        parameters.append(OptionalParameter(kind, params[start : start + size]))
        pos = start + size
    opened = Open(version, my_as, hold_time, bgp_id, tuple(parameters), extended)
    opened.capabilities  # noqa: B018 - validate the Capabilities TLVs now, not at first use
    return opened


def _decode_update(body: bytes, length: int, *, four_octet_as: bool, internal: bool) -> Update:
    malformed = BgpError(
        ErrorCode.UPDATE_MESSAGE,
        UpdateSubcode.MALFORMED_ATTRIBUTE_LIST,
        message="Withdrawn Routes Length or Total Attribute Length is too large",
    )
    withdrawn_length = int.from_bytes(body[0:2], "big")
    if 2 + withdrawn_length + 2 > len(body):
        raise malformed
    attr_start = 2 + withdrawn_length + 2
    attr_length = int.from_bytes(body[attr_start - 2 : attr_start], "big")
    if withdrawn_length + attr_length + limits.MIN_UPDATE_LENGTH > length:
        raise malformed
    withdrawn = parse_prefix_list(body[2 : 2 + withdrawn_length])
    nlri = parse_prefix_list(body[attr_start + attr_length :])
    walked = walk(
        body[attr_start : attr_start + attr_length], four_octet_as=four_octet_as, internal=internal
    )
    has_mp_reach = walked.get(AttrType.MP_REACH_NLRI) is not None
    issues = list(walked.issues)
    issues += missing_mandatory(walked, has_nlri=bool(nlri), has_mp_reach=has_mp_reach)
    action = strongest(issues)
    carried = {a.type_code for a in walked.attributes} | {
        i.type_code for i in issues if i.type_code is not None
    }
    framing_fault = any(i.type_code is None for i in issues)
    other_than_unreach = bool(carried - {int(AttrType.MP_UNREACH_NLRI)}) or framing_fault
    if (
        not nlri
        and not has_mp_reach
        and other_than_unreach
        and Action.ATTRIBUTE_DISCARD < action < Action.SESSION_RESET
    ):
        # RFC 7606 section 5.2: errors beyond attribute discard in an UPDATE that announces
        # nothing it can recognise as NLRI require a session reset.
        issues.append(
            Issue(
                None,
                Action.SESSION_RESET,
                "attribute errors in an UPDATE with no reachable NLRI (RFC 7606 section 5.2)",
            )
        )
        action = Action.SESSION_RESET
    return Update(withdrawn, walked.attributes, nlri, tuple(issues), action)


def _frame(kind: MessageType, body: bytes, max_length: int) -> bytes:
    length = limits.HEADER_LENGTH + len(body)
    ceiling = limits.MAX_MESSAGE_LENGTH if kind is MessageType.OPEN else max_length
    if length > ceiling:
        raise ValueError(f"message of {length} octets exceeds {ceiling}")
    return MARKER + length.to_bytes(2, "big") + bytes([kind]) + body


def encode(message: Message, *, max_length: int = limits.MAX_MESSAGE_LENGTH) -> bytes:
    """Encode a message with the all-ones Marker and the exact Length (RFC 4271 section 4.1).

    Raises ``ValueError`` when the result would exceed ``max_length`` (OPEN is capped at 4096
    whatever ``max_length`` is, RFC 8654 section 4). An OPEN is written in the RFC 9072 extended
    form when its parameters exceed 255 octets (required) or ``extended_parameters`` is set.
    """
    if isinstance(message, Keepalive):
        return _frame(MessageType.KEEPALIVE, b"", max_length)
    if isinstance(message, Notification):
        for name, value in (("code", message.code), ("subcode", message.subcode)):
            if not 0 <= value <= 255:
                raise ValueError(f"{name} must fit one octet")
        return _frame(
            MessageType.NOTIFICATION,
            bytes([message.code, message.subcode]) + message.data,
            max_length,
        )
    if isinstance(message, Open):
        return _frame(MessageType.OPEN, _encode_open_body(message), max_length)
    if isinstance(message, Update):
        withdrawn = encode_prefix_list(message.withdrawn)
        attributes = b"".join(a.encode() for a in message.attributes)
        body = (
            len(withdrawn).to_bytes(2, "big")
            + withdrawn
            + len(attributes).to_bytes(2, "big")
            + attributes
            + encode_prefix_list(message.nlri)
        )
        return _frame(MessageType.UPDATE, body, max_length)
    raise TypeError(f"not a BGP message: {message!r}")


def _encode_open_body(message: Open) -> bytes:
    for name, value, bits in (
        ("version", message.version, 8),
        ("my_as", message.my_as, 16),
        ("hold_time", message.hold_time, 16),
    ):
        if not 0 <= value < 1 << bits:
            raise ValueError(f"{name} must fit {bits} bits")
    plain = b"".join(
        bytes([p.type, len(p.value)]) + p.value for p in message.parameters if len(p.value) <= 255
    )
    use_extended = (
        message.extended_parameters
        or len(plain) != sum(2 + len(p.value) for p in message.parameters)
        or len(plain) > 255
    )
    head = (
        bytes([message.version])
        + message.my_as.to_bytes(2, "big")
        + message.hold_time.to_bytes(2, "big")
        + message.bgp_id.packed
    )
    if not use_extended:
        return head + bytes([len(plain)]) + plain
    wide = b"".join(
        bytes([p.type]) + len(p.value).to_bytes(2, "big") + p.value for p in message.parameters
    )
    if len(wide) > 0xFFFF:
        raise ValueError("optional parameters exceed 65535 octets")
    # RFC 9072 section 2: Non-Ext OP Len 255 (it MUST NOT be 0), Non-Ext OP Type 255, then the
    # two-octet length.
    return head + bytes([255, EXTENDED_PARAMETERS_TYPE]) + len(wide).to_bytes(2, "big") + wide
