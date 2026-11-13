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

* ROUTE-REFRESH (type 5, RFC 2918, with the message subtypes of RFC 7313 section 3.2).

ADD-PATH (RFC 7911) is applied through ``add_path``, the set of <AFI, SAFI> pairs whose NLRI carry
Path Identifiers (see :mod:`pathattr.addpath`); for IPv4 unicast it changes the Withdrawn Routes
and NLRI fields, which then report their identifiers in ``Update.withdrawn_path_ids`` and
``Update.nlri_path_ids``. ``validate_open`` applies the RFC 4271 section 6.2 policy to a decoded
OPEN, and ``measure`` counts what an UPDATE holds for :func:`pathattr.limits.check`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import IntEnum
from typing import cast

from . import limits
from .attribute import (
    Action,
    Attributes,
    AttrType,
    Issue,
    RawAttribute,
    Walked,
    missing_mandatory,
    strongest,
    walk,
)
from .errors import (
    BgpError,
    ErrorCode,
    HeaderSubcode,
    OpenSubcode,
    RouteRefreshSubcode,
    UpdateSubcode,
)
from .nlri import (
    MpError,
    Nlri,
    encode_nlri,
    encode_prefix_list,
    parse_mp_reach,
    parse_mp_unreach,
    parse_nlri,
    parse_prefix_list,
)

__all__ = [
    "DEFAULT_OPEN_POLICY",
    "BgpError",
    "Capability",
    "Header",
    "Keepalive",
    "Message",
    "MessageType",
    "Notification",
    "Open",
    "OpenPolicy",
    "OptionalParameter",
    "RouteRefresh",
    "Update",
    "decode",
    "decode_header",
    "decode_stream",
    "encode",
    "four_octet_as_capability",
    "measure",
    "validate_open",
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
    ROUTE_REFRESH = 5  # RFC 2918 section 3


_MIN_LENGTH = {
    MessageType.OPEN: limits.MIN_OPEN_LENGTH,
    MessageType.UPDATE: limits.MIN_UPDATE_LENGTH,
    MessageType.NOTIFICATION: limits.MIN_NOTIFICATION_LENGTH,
    MessageType.KEEPALIVE: limits.HEADER_LENGTH,
    MessageType.ROUTE_REFRESH: limits.HEADER_LENGTH + 4,  # RFC 2918 section 3
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
    withdrawn_path_ids: tuple[int, ...] = ()
    nlri_path_ids: tuple[int, ...] = ()
    """RFC 7911 Path Identifiers of ``withdrawn`` and ``nlri``, parallel to them; empty unless
    ADD-PATH applied to IPv4 unicast when the UPDATE was decoded."""


@dataclass(frozen=True, slots=True)
class RouteRefresh:
    """ROUTE-REFRESH (RFC 2918 section 3, RFC 7313 section 3.2).

    ``subtype`` is the octet RFC 2918 calls Reserved and RFC 7313 redefines as the Message Subtype:
    0 a normal request, 1 the beginning (BoRR) and 2 the end (EoRR) of a refresh. It means
    something only when Enhanced Route Refresh was negotiated; ``orf`` holds any octets after the
    four (Outbound Route Filter entries, RFC 5291), uninterpreted.
    """

    afi: int
    safi: int
    subtype: int = 0
    orf: bytes = b""

    @property
    def defined_subtype(self) -> bool:
        """False for a subtype other than 0, 1 or 2, which RFC 7313 section 5 says to ignore."""
        return self.subtype in (0, 1, 2)


Message = Keepalive | Notification | Open | Update | RouteRefresh


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
    add_path: frozenset[tuple[int, int]] = frozenset(),
    enhanced_route_refresh: bool = False,
) -> Message:
    """Decode exactly one complete BGP message (RFC 4271 section 4, RFC 7606).

    ``raw`` must be the whole message: a buffer whose length differs from the header's Length
    is Bad Message Length. ``max_length`` is 4096, or 65535 once the Extended Message
    capability has been negotiated (RFC 8654 section 4); never raise it for a peer that has not
    advertised the capability (RFC 8654 section 5). ``four_octet_as`` and ``internal`` describe
    the session for the UPDATE checks of RFC 7606 section 7 (see :func:`pathattr.attribute.walk`).
    ``add_path`` is the set of <AFI, SAFI> pairs received with Path Identifiers, and
    ``enhanced_route_refresh`` says the peer advertised RFC 7313, which makes a ROUTE-REFRESH
    with subtype 1 or 2 and any length but 23 a ROUTE-REFRESH Message Error (RFC 7313 section 5).
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
    if header.type == MessageType.ROUTE_REFRESH:
        return _decode_route_refresh(raw, enhanced_route_refresh)
    return _decode_update(
        body, header.length, four_octet_as=four_octet_as, internal=internal, add_path=add_path
    )


def _decode_route_refresh(raw: bytes, enhanced: bool) -> RouteRefresh:
    body = raw[limits.HEADER_LENGTH :]
    afi, subtype, safi = int.from_bytes(body[0:2], "big"), body[2], body[3]
    if enhanced and subtype in (1, 2) and len(body) != 4:
        # RFC 7313 section 5: the Data field is the complete ROUTE-REFRESH message.
        raise BgpError(
            ErrorCode.ROUTE_REFRESH,
            RouteRefreshSubcode.INVALID_MESSAGE_LENGTH,
            raw,
            "ROUTE-REFRESH of subtype 1 or 2 is not 4 octets after the header",
        )
    return RouteRefresh(afi, safi, subtype, bytes(body[4:]))


def decode_stream(
    buf: bytes | bytearray | memoryview,
    *,
    max_length: int = limits.MAX_MESSAGE_LENGTH,
    four_octet_as: bool = True,
    internal: bool = False,
    add_path: frozenset[tuple[int, int]] = frozenset(),
    enhanced_route_refresh: bool = False,
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
                add_path=add_path,
                enhanced_route_refresh=enhanced_route_refresh,
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


def _decode_update(
    body: bytes,
    length: int,
    *,
    four_octet_as: bool,
    internal: bool,
    add_path: frozenset[tuple[int, int]] = frozenset(),
) -> Update:
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
    withdrawn_raw, nlri_raw = body[2 : 2 + withdrawn_length], body[attr_start + attr_length :]
    withdrawn: tuple[ipaddress.IPv4Network, ...]
    nlri: tuple[ipaddress.IPv4Network, ...]
    withdrawn_ids: tuple[int, ...] = ()
    nlri_ids: tuple[int, ...] = ()
    if (1, 1) in add_path:  # RFC 7911 section 3: the extended encoding applies to both fields
        withdrawn_entries = parse_nlri(withdrawn_raw, 1, 1, True)
        nlri_entries = parse_nlri(nlri_raw, 1, 1, True)
        withdrawn = tuple(cast(ipaddress.IPv4Network, e.prefix) for e in withdrawn_entries)
        nlri = tuple(cast(ipaddress.IPv4Network, e.prefix) for e in nlri_entries)
        withdrawn_ids = tuple(e.path_id for e in withdrawn_entries if e.path_id is not None)
        nlri_ids = tuple(e.path_id for e in nlri_entries if e.path_id is not None)
    else:
        withdrawn = parse_prefix_list(withdrawn_raw)
        nlri = parse_prefix_list(nlri_raw)
    walked = walk(
        body[attr_start : attr_start + attr_length], four_octet_as=four_octet_as, internal=internal
    )
    issues = list(walked.issues)
    has_mp_reach = _mp_attributes(walked, add_path, issues)
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
    return Update(
        withdrawn, walked.attributes, nlri, tuple(issues), action, withdrawn_ids, nlri_ids
    )


def _mp_attributes(
    walked: Walked, add_path: frozenset[tuple[int, int]], issues: list[Issue]
) -> bool:
    """Parse MP_REACH_NLRI and MP_UNREACH_NLRI; return whether the UPDATE announces anything.

    A value that cannot be parsed adds an AFI/SAFI disable issue (RFC 7606 sections 3 (j) and
    7.11) and still counts as reachable: if the NLRI cannot be located nothing says it is empty,
    and RFC 7606 section 5.2 escalates only an UPDATE known to announce nothing.
    """
    reach = walked.get(AttrType.MP_REACH_NLRI)
    unreach = walked.get(AttrType.MP_UNREACH_NLRI)
    if unreach is not None:
        try:
            parse_mp_unreach(unreach.value, add_path)
        except MpError as error:
            issues.append(Issue(unreach.type_code, Action.AFI_SAFI_DISABLE, str(error), unreach))
    if reach is None:
        return False
    try:
        parsed = parse_mp_reach(reach.value, add_path)
    except MpError as error:
        issues.append(Issue(reach.type_code, Action.AFI_SAFI_DISABLE, str(error), reach))
        return True
    return bool(parsed.nlri) if parsed.nlri is not None else bool(parsed.nlri_raw)


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
        withdrawn = _encode_fields(message.withdrawn, message.withdrawn_path_ids)
        attributes = b"".join(a.encode() for a in message.attributes)
        body = (
            len(withdrawn).to_bytes(2, "big")
            + withdrawn
            + len(attributes).to_bytes(2, "big")
            + attributes
            + _encode_fields(message.nlri, message.nlri_path_ids)
        )
        return _frame(MessageType.UPDATE, body, max_length)
    if isinstance(message, RouteRefresh):
        if not 0 <= message.subtype <= 255:
            raise ValueError("subtype must fit one octet")
        body = message.afi.to_bytes(2, "big") + bytes([message.subtype, message.safi]) + message.orf
        return _frame(MessageType.ROUTE_REFRESH, body, max_length)
    raise TypeError(f"not a BGP message: {message!r}")


def _encode_fields(prefixes: tuple[ipaddress.IPv4Network, ...], path_ids: tuple[int, ...]) -> bytes:
    """A Withdrawn Routes or NLRI field: plain, or with RFC 7911 Path Identifiers when given."""
    if not path_ids:
        return encode_prefix_list(prefixes)
    if len(path_ids) != len(prefixes):
        raise ValueError("path ids must be parallel to the prefixes")
    return encode_nlri([Nlri(p, i) for p, i in zip(prefixes, path_ids, strict=True)], True)


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


FOUR_OCTET_AS_CAPABILITY = 65  # RFC 6793 section 3


def four_octet_as_capability(opened: Open) -> int | None:
    """The AS number in the four-octet AS capability (code 65), or None when it is absent.

    RFC 6793 section 3: the Capability Length is 4 and the value is the speaker's AS number.
    Raises :class:`BgpError` (OPEN Message Error, Unspecific) for any other length, a recognized
    capability that is malformed (RFC 4271 section 6.2).
    """
    for capability in opened.capabilities:
        if capability.code == FOUR_OCTET_AS_CAPABILITY:
            if len(capability.value) != 4:
                raise BgpError(
                    ErrorCode.OPEN_MESSAGE,
                    OpenSubcode.UNSPECIFIC,
                    message="four-octet AS capability length is not 4",
                )
            return int.from_bytes(capability.value, "big")
    return None


@dataclass(frozen=True, slots=True)
class OpenPolicy:
    """The local choices RFC 4271 section 6.2 leaves to the speaker.

    ``expected_peer_as`` is the configured neighbour AS, or None to accept any (the RFC calls the
    determination of acceptable AS numbers outside its scope). ``min_hold_time`` rejects a
    proposed non-zero Hold Time below it (RFC 4271 section 6.2: a speaker MAY reject any
    proposed Hold Time); one and two seconds are always rejected. ``supported_versions`` are the
    BGP versions spoken, 4 only by default.
    """

    expected_peer_as: int | None = None
    min_hold_time: int = 3
    supported_versions: tuple[int, ...] = (4,)
    allow_zero_hold_time: bool = True


DEFAULT_OPEN_POLICY = OpenPolicy()


def validate_open(opened: Open, policy: OpenPolicy = DEFAULT_OPEN_POLICY) -> int:
    """Apply RFC 4271 section 6.2 to a decoded OPEN; return the peer's AS number.

    Raises :class:`BgpError` (OPEN Message Error) for the first fault, in the order of section
    6.2: Unsupported Version Number (Data is the 2-octet number section 6.2 describes), Bad Peer
    AS (AS 0, RFC 7607 section 2, or not ``policy.expected_peer_as``), Unacceptable Hold Time (1
    or 2 always; MUST), Bad BGP Identifier (not a valid unicast host address: 0.0.0.0, a
    multicast address and the limited broadcast address are refused), Unsupported Optional
    Parameter (any parameter type other than Capabilities; the RFC 9072 extended form is already
    unwrapped by ``decode``). A malformed recognized parameter was already refused by ``decode``
    with subcode 0. The peer AS is the four-octet capability's value when the OPEN carries one
    (RFC 6793 section 4.1), otherwise My Autonomous System.
    """
    if opened.version not in policy.supported_versions:
        lower = [v for v in policy.supported_versions if v < opened.version]
        suggested = max(lower) if lower else min(policy.supported_versions)
        raise BgpError(
            ErrorCode.OPEN_MESSAGE,
            OpenSubcode.UNSUPPORTED_VERSION_NUMBER,
            suggested.to_bytes(2, "big"),
            f"BGP version {opened.version} is not supported",
        )
    capability_as = four_octet_as_capability(opened)
    peer_as = capability_as if capability_as is not None else opened.my_as
    if peer_as == 0 or (policy.expected_peer_as is not None and peer_as != policy.expected_peer_as):
        raise BgpError(
            ErrorCode.OPEN_MESSAGE,
            OpenSubcode.BAD_PEER_AS,
            message=f"unacceptable peer AS {peer_as}",
        )
    hold = opened.hold_time
    if (
        hold in (1, 2)
        or (hold == 0 and not policy.allow_zero_hold_time)
        or 3 <= hold < policy.min_hold_time
    ):
        raise BgpError(
            ErrorCode.OPEN_MESSAGE,
            OpenSubcode.UNACCEPTABLE_HOLD_TIME,
            message=f"unacceptable hold time {hold}",
        )
    ident = opened.bgp_id
    if (
        ident.is_unspecified
        or ident.is_multicast
        or ident == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise BgpError(
            ErrorCode.OPEN_MESSAGE,
            OpenSubcode.BAD_BGP_IDENTIFIER,
            message=f"{ident} is not a unicast host address",
        )
    for parameter in opened.parameters:
        if parameter.type != CAPABILITIES_PARAMETER:
            raise BgpError(
                ErrorCode.OPEN_MESSAGE,
                OpenSubcode.UNSUPPORTED_OPTIONAL_PARAMETER,
                message=f"optional parameter type {parameter.type} is not supported",
            )
    return peer_as


def measure(update: Update, decoded: Attributes | None = None) -> limits.Counts:
    """Count what ``update`` holds, for :func:`pathattr.limits.check`.

    Counts framed attributes (including ones discarded by RFC 7606, which still cost parse work)
    and the Withdrawn Routes and NLRI fields. ``decoded`` adds the AS path, community and
    multiprotocol counts when the caller has run :func:`pathattr.attribute.decode_attributes`.
    """
    counts = {
        "attributes": len(update.attributes)
        + sum(1 for i in update.issues if i.attribute and i.attribute not in update.attributes),
        "nlri": len(update.nlri),
        "withdrawn": len(update.withdrawn),
    }
    if decoded is not None:
        for path in (decoded.as_path, decoded.as4_path):
            counts["as_path_segments"] = counts.get("as_path_segments", 0) + len(path or ())
            counts["as_path_asns"] = counts.get("as_path_asns", 0) + sum(
                len(s.asns) for s in path or ()
            )
        counts["communities"] = len(decoded.communities)
        counts["extended_communities"] = len(decoded.extended_communities)
        counts["large_communities"] = len(decoded.large_communities)
        for mp in (decoded.mp_reach, decoded.mp_unreach):
            if mp is not None and mp.nlri is not None:
                key = "nlri" if mp is decoded.mp_reach else "withdrawn"
                counts[key] += len(mp.nlri)
    return limits.Counts(**counts)
