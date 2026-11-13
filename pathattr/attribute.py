"""attribute flags, type registry, the attribute walker and RFC 7606 verdicts (RFC 4271).

``walk`` frames the Path Attributes field of an UPDATE (RFC 4271 section 4.3) and applies the
error handling of RFC 7606: it never raises on malformed attributes. Each fault becomes an
:class:`Issue` carrying the RFC 7606 approach (:class:`Action`) to use, and a malformed
attribute list is reported rather than guessed at. Contents of attributes are not decoded
here; every framed attribute is returned raw, flags and bytes intact, so an attribute this
library does not know survives a round trip.

The attribute-specific checks are those of RFC 7606 section 7 (ORIGIN, AS_PATH, NEXT_HOP,
MULTI_EXIT_DISC, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES, ORIGINATOR_ID,
CLUSTER_LIST, MP_REACH_NLRI, MP_UNREACH_NLRI, EXTENDED COMMUNITIES). Anything else is framed and
kept, never judged.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from .aspath import (
    AS_TRANS,
    AsPath,
    contains_as0,
    merge_as4_path,
    parse_as_path,
    strip_confed,
)
from .communities import (
    Community,
    ExtendedCommunity,
    LargeCommunity,
    decode_communities,
    decode_extended,
    decode_large_communities,
)
from .errors import BgpError
from .nlri import MpReach, MpUnreach, parse_mp_reach, parse_mp_unreach

__all__ = [
    "Action",
    "Aggregator",
    "AttrType",
    "Attributes",
    "Issue",
    "Origin",
    "RawAttribute",
    "Undecodable",
    "Walked",
    "decode_attributes",
    "missing_mandatory",
    "strongest",
    "walk",
]

OPTIONAL = 0x80
TRANSITIVE = 0x40
PARTIAL = 0x20
EXTENDED_LENGTH = 0x10


class AttrType(IntEnum):
    """Path attribute type codes this module judges. Type codes come from the sections noted."""

    ORIGIN = 1  # RFC 4271 section 4.3
    AS_PATH = 2
    NEXT_HOP = 3
    MULTI_EXIT_DISC = 4
    LOCAL_PREF = 5
    ATOMIC_AGGREGATE = 6
    AGGREGATOR = 7
    COMMUNITIES = 8  # RFC 1997
    ORIGINATOR_ID = 9  # RFC 4456 (type code 9, per its section 8 text)
    CLUSTER_LIST = 10  # RFC 4456 (type code 10)
    MP_REACH_NLRI = 14  # RFC 4760 section 3
    MP_UNREACH_NLRI = 15  # RFC 4760 section 4
    EXTENDED_COMMUNITIES = 16  # RFC 4360 section 2
    AS4_PATH = 17  # RFC 6793 section 3
    AS4_AGGREGATOR = 18
    LARGE_COMMUNITY = 32  # RFC 8092 section 3


class Action(IntEnum):
    """The four error-handling approaches of RFC 7606 section 2, in order of strength.

    ``NONE`` is no error. The numeric order is the order of strength, so ``max`` of several
    actions is the one RFC 7606 section 3 (h) says to use when approaches differ.
    """

    NONE = 0
    ATTRIBUTE_DISCARD = 1
    TREAT_AS_WITHDRAW = 2
    AFI_SAFI_DISABLE = 3
    SESSION_RESET = 4


# (optional, transitive) as RFC 4271 section 4.3 and the defining document give them.
_FLAGS: dict[int, tuple[bool, bool]] = {
    AttrType.ORIGIN: (False, True),
    AttrType.AS_PATH: (False, True),
    AttrType.NEXT_HOP: (False, True),
    AttrType.MULTI_EXIT_DISC: (True, False),
    AttrType.LOCAL_PREF: (False, True),
    AttrType.ATOMIC_AGGREGATE: (False, True),
    AttrType.AGGREGATOR: (True, True),
    AttrType.COMMUNITIES: (True, True),
    AttrType.ORIGINATOR_ID: (True, False),
    AttrType.CLUSTER_LIST: (True, False),
    AttrType.MP_REACH_NLRI: (True, False),
    AttrType.MP_UNREACH_NLRI: (True, False),
    AttrType.EXTENDED_COMMUNITIES: (True, True),
    AttrType.LARGE_COMMUNITY: (True, True),
}
_MP = (AttrType.MP_REACH_NLRI, AttrType.MP_UNREACH_NLRI)
_SEGMENT_TYPES = {1, 2, 3, 4}  # AS_SET, AS_SEQUENCE (RFC 4271); AS_CONFED_SEQUENCE, _SET (RFC 5065)


@dataclass(frozen=True, slots=True)
class RawAttribute:
    """One framed path attribute: the flags octet as received, the type code and the value."""

    flags: int
    type_code: int
    value: bytes
    offset: int = 0

    @property
    def optional(self) -> bool:
        return bool(self.flags & OPTIONAL)

    @property
    def transitive(self) -> bool:
        return bool(self.flags & TRANSITIVE)

    @property
    def partial(self) -> bool:
        return bool(self.flags & PARTIAL)

    @property
    def extended_length(self) -> bool:
        return bool(self.flags & EXTENDED_LENGTH)

    @classmethod
    def build(
        cls,
        type_code: int,
        value: bytes,
        *,
        optional: bool,
        transitive: bool,
        partial: bool = False,
    ) -> RawAttribute:
        """Make an attribute whose Extended Length bit is set exactly when the value needs it."""
        flags = (
            (OPTIONAL if optional else 0)
            | (TRANSITIVE if transitive else 0)
            | (PARTIAL if partial else 0)
            | (EXTENDED_LENGTH if len(value) > 255 else 0)
        )
        return cls(flags, type_code, bytes(value))

    def encode(self) -> bytes:
        """The attribute as it goes on the wire, honouring the Extended Length bit it carries."""
        if self.extended_length:
            if len(self.value) > 0xFFFF:
                raise ValueError("attribute value longer than 65535 octets")
            return (
                bytes([self.flags, self.type_code])
                + len(self.value).to_bytes(2, "big")
                + self.value
            )
        if len(self.value) > 255:
            raise ValueError("value needs the Extended Length bit")
        return bytes([self.flags, self.type_code, len(self.value)]) + self.value


@dataclass(frozen=True, slots=True)
class Issue:
    """One fault found while walking attributes, and the RFC 7606 approach it calls for.

    ``attribute`` is the offending attribute where one could be framed, so a discarded
    attribute's bytes are never lost.
    """

    type_code: int | None
    action: Action
    reason: str
    attribute: RawAttribute | None = None


@dataclass(frozen=True, slots=True)
class Walked:
    """Result of walking a Path Attributes field.

    ``attributes`` holds every framed attribute in order except those RFC 7606 says to discard
    (later duplicates, and attributes whose approach is attribute discard); those are in
    ``issues``. ``action`` is the strongest approach among the issues (RFC 7606 section 3 (h)).
    """

    attributes: tuple[RawAttribute, ...]
    issues: tuple[Issue, ...]

    @property
    def action(self) -> Action:
        return strongest(self.issues)

    def get(self, type_code: int) -> RawAttribute | None:
        for attribute in self.attributes:
            if attribute.type_code == type_code:
                return attribute
        return None


def strongest(issues: tuple[Issue, ...] | list[Issue]) -> Action:
    """The strongest approach in ``issues``, or ``Action.NONE`` for none (RFC 7606 3 (h))."""
    return max((issue.action for issue in issues), default=Action.NONE)


def _as_path_fault(value: bytes, asn_size: int) -> str | None:
    """Why an AS_PATH value is malformed per RFC 7606 section 7.2, or None."""
    pos, end = 0, len(value)
    while pos < end:
        if end - pos < 2:
            return "underrun: a single octet is left after the last segment"
        seg_type, count = value[pos], value[pos + 1]
        if seg_type not in _SEGMENT_TYPES:
            return f"unrecognized segment type {seg_type}"
        if count == 0:
            return "segment with a Path Segment Length of zero"
        pos += 2 + count * asn_size
        if pos > end:
            return "overrun: the last segment runs past the attribute"
    return None


def _as4_path_fault(attr: RawAttribute, four_octet_as: bool) -> tuple[Action, str] | None:
    """RFC 6793 sections 4.1 and 6 and RFC 7607 section 2 for AS4_PATH: always attribute discard."""
    if four_octet_as:
        return Action.ATTRIBUTE_DISCARD, "AS4_PATH between 4-octet speakers (RFC 6793 section 4.1)"
    if len(attr.value) < 6:
        return Action.ATTRIBUTE_DISCARD, "AS4_PATH is too small to carry an AS number"
    fault = _as_path_fault(attr.value, 4)
    if fault:
        return Action.ATTRIBUTE_DISCARD, "AS4_PATH " + fault
    if contains_as0(parse_as_path(attr.value, True)):
        return Action.ATTRIBUTE_DISCARD, "AS4_PATH contains AS 0 (RFC 7607 section 2)"
    return None


def _as4_aggregator_fault(attr: RawAttribute, four_octet_as: bool) -> tuple[Action, str] | None:
    if four_octet_as:
        return (
            Action.ATTRIBUTE_DISCARD,
            "AS4_AGGREGATOR between 4-octet speakers (RFC 6793 section 4.1)",
        )
    if len(attr.value) != 8:
        return Action.ATTRIBUTE_DISCARD, "AS4_AGGREGATOR length is not 8"
    if int.from_bytes(attr.value[:4], "big") == 0:
        return Action.ATTRIBUTE_DISCARD, "AS4_AGGREGATOR names AS 0 (RFC 7607 section 2)"
    return None


def _value_fault(attr: RawAttribute, *, four_octet_as: bool) -> tuple[Action, str] | None:
    """Apply RFC 7606 section 7 to one attribute; None when it is well formed or not judged."""
    code, n = attr.type_code, len(attr.value)
    if code == AttrType.ORIGIN:
        if n != 1:
            return Action.TREAT_AS_WITHDRAW, "ORIGIN length is not 1"
        if attr.value[0] > 2:
            return Action.TREAT_AS_WITHDRAW, f"ORIGIN has undefined value {attr.value[0]}"
    elif code == AttrType.AS_PATH:
        fault = _as_path_fault(attr.value, 4 if four_octet_as else 2)
        if fault:
            return Action.TREAT_AS_WITHDRAW, "AS_PATH " + fault
        if contains_as0(parse_as_path(attr.value, four_octet_as)):
            return Action.TREAT_AS_WITHDRAW, "AS_PATH contains AS 0 (RFC 7607 section 2)"
    elif code == AttrType.AS4_PATH:
        return _as4_path_fault(attr, four_octet_as)
    elif code == AttrType.AS4_AGGREGATOR:
        return _as4_aggregator_fault(attr, four_octet_as)
    elif code in (
        AttrType.NEXT_HOP,
        AttrType.MULTI_EXIT_DISC,
        AttrType.LOCAL_PREF,
        AttrType.ORIGINATOR_ID,
    ):
        if n != 4:
            return Action.TREAT_AS_WITHDRAW, f"{AttrType(code).name} length is not 4"
    elif code == AttrType.ATOMIC_AGGREGATE:
        if n != 0:
            return Action.ATTRIBUTE_DISCARD, "ATOMIC_AGGREGATE length is not 0"
    elif code == AttrType.AGGREGATOR:
        want = 8 if four_octet_as else 6
        if n != want:
            return Action.ATTRIBUTE_DISCARD, f"AGGREGATOR length is not {want}"
        if int.from_bytes(attr.value[: want - 4], "big") == 0:
            return Action.ATTRIBUTE_DISCARD, "AGGREGATOR names AS 0 (RFC 7607 section 2)"
    elif code == AttrType.COMMUNITIES:
        if n == 0 or n % 4:
            return Action.TREAT_AS_WITHDRAW, "COMMUNITIES length is not a non-zero multiple of 4"
    elif code == AttrType.CLUSTER_LIST:
        if n == 0 or n % 4:
            return Action.TREAT_AS_WITHDRAW, "CLUSTER_LIST length is not a non-zero multiple of 4"
    elif code == AttrType.LARGE_COMMUNITY:
        if n == 0 or n % 12:
            return (
                Action.TREAT_AS_WITHDRAW,
                "LARGE_COMMUNITY length is not a non-zero multiple of 12 (RFC 8092 section 6)",
            )
    elif code == AttrType.EXTENDED_COMMUNITIES:
        if n == 0 or n % 8:
            return (
                Action.TREAT_AS_WITHDRAW,
                "EXTENDED COMMUNITIES length is not a non-zero multiple of 8",
            )
    elif code == AttrType.MP_REACH_NLRI:
        if n < 5:
            return Action.AFI_SAFI_DISABLE, "MP_REACH_NLRI is shorter than 5 octets"
    elif code == AttrType.MP_UNREACH_NLRI and n < 3:
        return Action.AFI_SAFI_DISABLE, "MP_UNREACH_NLRI is shorter than 3 octets"
    return None


def walk(raw: bytes, *, four_octet_as: bool, internal: bool) -> Walked:
    """Frame the Path Attributes field and judge it by RFC 4271 section 4.3 and RFC 7606.

    ``raw`` is exactly the Total Path Attribute Length octets. ``four_octet_as`` says whether
    AS numbers in AS_PATH and AGGREGATOR are four octets (RFC 6793 section 4.1: both ends
    advertised the capability); ``internal`` says whether the session is IBGP, which RFC 7606
    sections 7.5, 7.9 and 7.10 need to tell LOCAL_PREF, ORIGINATOR_ID and CLUSTER_LIST that are
    discarded (EBGP) from those that are length-checked (IBGP).

    Never raises on malformed attributes and never reads past ``raw``. When the attribute list
    itself cannot be framed (a length overruns the field, or too few octets remain for even a
    minimum attribute header), RFC 7606 section 4 requires treat-as-withdraw and the walk stops,
    keeping what it framed; this is reported as an Issue whose ``type_code`` is None unless the
    overrunning attribute's type code was readable.
    """
    attributes: list[RawAttribute] = []
    issues: list[Issue] = []
    seen: set[int] = set()
    pos, end = 0, len(raw)
    while pos < end:
        extended = end - pos >= 1 and bool(raw[pos] & EXTENDED_LENGTH)
        header = 4 if extended else 3
        if end - pos < header:
            issues.append(
                Issue(
                    None,
                    Action.TREAT_AS_WITHDRAW,
                    "fewer octets remain than the smallest attribute header (RFC 7606 section 4)",
                )
            )
            break
        flags, code = raw[pos], raw[pos + 1]
        length = int.from_bytes(raw[pos + 2 : pos + header], "big")
        if pos + header + length > end:
            issues.append(
                Issue(
                    code,
                    Action.TREAT_AS_WITHDRAW,
                    "attribute length overruns the Total Path Attribute Length (RFC 7606 section 4)",
                )
            )
            break
        attr = RawAttribute(flags, code, bytes(raw[pos + header : pos + header + length]), pos)
        pos += header + length
        if code in seen:
            if code in _MP:
                issues.append(
                    Issue(
                        code,
                        Action.SESSION_RESET,
                        "MP_REACH_NLRI or MP_UNREACH_NLRI appears more than once "
                        "(RFC 7606 section 3 (g): NOTIFICATION, Malformed Attribute List)",
                        attr,
                    )
                )
            else:
                issues.append(
                    Issue(
                        code,
                        Action.ATTRIBUTE_DISCARD,
                        "duplicate attribute: later occurrences discarded (RFC 7606 section 3 (g))",
                        attr,
                    )
                )
            continue
        seen.add(code)
        verdict = _judge(attr, four_octet_as=four_octet_as, internal=internal)
        if verdict is None:
            attributes.append(attr)
        elif verdict[0] == Action.ATTRIBUTE_DISCARD:
            issues.append(Issue(code, verdict[0], verdict[1], attr))
        else:
            attributes.append(attr)
            issues.append(Issue(code, verdict[0], verdict[1], attr))
    return Walked(tuple(attributes), tuple(issues))


def _judge(attr: RawAttribute, *, four_octet_as: bool, internal: bool) -> tuple[Action, str] | None:
    code = attr.type_code
    # RFC 7606 sections 7.5, 7.9, 7.10: from an external neighbour these are simply discarded.
    if not internal and code in (
        AttrType.LOCAL_PREF,
        AttrType.ORIGINATOR_ID,
        AttrType.CLUSTER_LIST,
    ):
        return (
            Action.ATTRIBUTE_DISCARD,
            f"{AttrType(code).name} received from an external neighbour",
        )
    expected = _FLAGS.get(code)
    if expected is not None and (attr.optional, attr.transitive) != expected:
        # RFC 7606 section 3 (c); the MP attributes cannot be located without their flags
        # being right (section 5.3), so they take the AFI/SAFI disable approach (section 3 (j)).
        action = Action.AFI_SAFI_DISABLE if code in _MP else Action.TREAT_AS_WITHDRAW
        return action, "Optional or Transitive flag conflicts with the attribute type"
    return _value_fault(attr, four_octet_as=four_octet_as)


def missing_mandatory(walked: Walked, *, has_nlri: bool, has_mp_reach: bool) -> tuple[Issue, ...]:
    """Issues for well-known mandatory attributes that are absent (RFC 7606 section 3 (d)).

    ORIGIN and AS_PATH are mandatory when the UPDATE carries reachable NLRI, in the NLRI field
    or in MP_REACH_NLRI; NEXT_HOP only for the NLRI field, because RFC 4760 reclassified it as
    effectively discretionary (RFC 7606 section 3 (d)). Their absence is treat-as-withdraw.
    """
    if not (has_nlri or has_mp_reach):
        return ()
    needed = [AttrType.ORIGIN, AttrType.AS_PATH]
    if has_nlri:
        needed.append(AttrType.NEXT_HOP)
    return tuple(
        Issue(int(code), Action.TREAT_AS_WITHDRAW, f"missing well-known mandatory {code.name}")
        for code in needed
        if walked.get(int(code)) is None
    )


class Origin(IntEnum):
    """ORIGIN values (RFC 4271 section 5.1.1)."""

    IGP = 0
    EGP = 1
    INCOMPLETE = 2


@dataclass(frozen=True, slots=True)
class Aggregator:
    """AGGREGATOR or AS4_AGGREGATOR: the AS and the router that formed the aggregate."""

    asn: int
    address: ipaddress.IPv4Address


@dataclass(frozen=True, slots=True)
class Undecodable:
    """An attribute whose value could not be decoded, and what RFC 7606 says to do about it.

    Never dropped: the framed attribute is kept so the caller can log or forward it.
    """

    attribute: RawAttribute
    action: Action
    reason: str


@dataclass(frozen=True, slots=True)
class Attributes:
    """Decoded path attribute values. A field is None (or empty) when the attribute is absent.

    ``unknown`` holds every attribute this module does not decode (a type with no decoder here, or
    unassigned), raw and in order. ``undecodable`` holds those it tried and could not decode.
    ``four_octet_as`` records the AS number width the AS_PATH and AGGREGATOR were read with.
    """

    four_octet_as: bool = True
    origin: Origin | None = None
    as_path: AsPath | None = None
    as4_path: AsPath | None = None
    next_hop: ipaddress.IPv4Address | None = None
    med: int | None = None
    local_pref: int | None = None
    atomic_aggregate: bool = False
    aggregator: Aggregator | None = None
    as4_aggregator: Aggregator | None = None
    communities: tuple[Community, ...] = ()
    extended_communities: tuple[ExtendedCommunity, ...] = ()
    large_communities: tuple[LargeCommunity, ...] = ()
    originator_id: ipaddress.IPv4Address | None = None
    cluster_list: tuple[ipaddress.IPv4Address, ...] = ()
    mp_reach: MpReach | None = None
    mp_unreach: MpUnreach | None = None
    unknown: tuple[RawAttribute, ...] = ()
    undecodable: tuple[Undecodable, ...] = ()

    @property
    def effective_as_path(self) -> AsPath | None:
        """The AS path to use for policy: AS_PATH, rebuilt with AS4_PATH when the session is 2-octet.

        Between 4-octet speakers AS_PATH is complete and AS4_PATH must not be present (RFC 6793
        section 4.1); otherwise the two are merged by RFC 6793 section 4.2.3. ``None`` when there
        is no AS_PATH.
        """
        if self.as_path is None:
            return None
        if self.four_octet_as or self.as4_path is None:
            return self.as_path
        return merge_as4_path(self.as_path, self.as4_path)

    @property
    def effective_aggregator(self) -> Aggregator | None:
        """AGGREGATOR, replaced by AS4_AGGREGATOR when the former holds AS_TRANS (RFC 6793 4.2.3)."""
        if (
            not self.four_octet_as
            and self.aggregator is not None
            and self.aggregator.asn == AS_TRANS
            and self.as4_aggregator is not None
        ):
            return self.as4_aggregator
        return self.aggregator


def _address(value: bytes) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(bytes(value))


def _aggregator(value: bytes, width: int, name: str) -> Aggregator:
    if len(value) != width + 4:
        raise ValueError(f"{name} length is not {width + 4}")
    return Aggregator(int.from_bytes(value[:width], "big"), _address(value[width:]))


def _u32(value: bytes, name: str) -> int:
    if len(value) != 4:
        raise ValueError(f"{name} length is not 4")
    return int.from_bytes(value, "big")


def _decode_one(
    attr: RawAttribute,
    fields: dict[str, Any],
    four_octet_as: bool,
    add_path: frozenset[tuple[int, int]],
) -> bool:
    """Decode one attribute into ``fields``; False when the type has no decoder here.

    Raises ``ValueError`` (or ``BgpError`` for a malformed AS_PATH) when the value is malformed. A
    repeated attribute keeps the first occurrence.
    """
    code, value = attr.type_code, attr.value
    if code == AttrType.ORIGIN:
        if len(value) != 1 or value[0] > 2:
            raise ValueError("ORIGIN is not one octet 0, 1 or 2")
        fields.setdefault("origin", Origin(value[0]))
    elif code == AttrType.AS_PATH:
        fields.setdefault("as_path", parse_as_path(value, four_octet_as))
    elif code == AttrType.AS4_PATH:
        fields.setdefault("as4_path", strip_confed(parse_as_path(value, True)))
    elif code == AttrType.NEXT_HOP:
        if len(value) != 4:
            raise ValueError("NEXT_HOP length is not 4")
        fields.setdefault("next_hop", _address(value))
    elif code == AttrType.MULTI_EXIT_DISC:
        fields.setdefault("med", _u32(value, "MULTI_EXIT_DISC"))
    elif code == AttrType.LOCAL_PREF:
        fields.setdefault("local_pref", _u32(value, "LOCAL_PREF"))
    elif code == AttrType.ATOMIC_AGGREGATE:
        if value:
            raise ValueError("ATOMIC_AGGREGATE length is not 0")
        fields["atomic_aggregate"] = True
    elif code == AttrType.AGGREGATOR:
        fields.setdefault("aggregator", _aggregator(value, 4 if four_octet_as else 2, "AGGREGATOR"))
    elif code == AttrType.AS4_AGGREGATOR:
        fields.setdefault("as4_aggregator", _aggregator(value, 4, "AS4_AGGREGATOR"))
    elif code == AttrType.COMMUNITIES:
        fields.setdefault("communities", decode_communities(value))
    elif code == AttrType.EXTENDED_COMMUNITIES:
        fields.setdefault("extended_communities", decode_extended(value))
    elif code == AttrType.LARGE_COMMUNITY:
        fields.setdefault("large_communities", decode_large_communities(value))
    elif code == AttrType.ORIGINATOR_ID:
        if len(value) != 4:
            raise ValueError("ORIGINATOR_ID length is not 4")
        fields.setdefault("originator_id", _address(value))
    elif code == AttrType.CLUSTER_LIST:
        if not value or len(value) % 4:
            raise ValueError("CLUSTER_LIST length is not a non-zero multiple of 4")
        fields.setdefault(
            "cluster_list", tuple(_address(value[i : i + 4]) for i in range(0, len(value), 4))
        )
    elif code == AttrType.MP_REACH_NLRI:
        fields.setdefault("mp_reach", parse_mp_reach(value, add_path))
    elif code == AttrType.MP_UNREACH_NLRI:
        fields.setdefault("mp_unreach", parse_mp_unreach(value, add_path))
    else:
        return False
    return True


# RFC 7606 section 7 and the defining documents: what a malformed value of each attribute costs.
_FAULT_ACTION: dict[int, Action] = {
    AttrType.ATOMIC_AGGREGATE: Action.ATTRIBUTE_DISCARD,
    AttrType.AGGREGATOR: Action.ATTRIBUTE_DISCARD,
    AttrType.AS4_PATH: Action.ATTRIBUTE_DISCARD,  # RFC 6793 section 6
    AttrType.AS4_AGGREGATOR: Action.ATTRIBUTE_DISCARD,  # RFC 6793 section 6
    AttrType.MP_REACH_NLRI: Action.AFI_SAFI_DISABLE,  # RFC 7606 sections 3 (j) and 7.11
    AttrType.MP_UNREACH_NLRI: Action.AFI_SAFI_DISABLE,
}


def decode_attributes(
    attributes: Iterable[RawAttribute],
    *,
    four_octet_as: bool = True,
    add_path: frozenset[tuple[int, int]] = frozenset(),
) -> Attributes:
    """Decode the values of framed path attributes (RFC 4271 section 5 and the per-attribute RFCs).

    ``attributes`` are the :class:`RawAttribute` records of ``walk`` or ``Update.attributes``;
    ``walk`` frames and judges, this reads values. ORIGIN, AS_PATH, AS4_PATH, NEXT_HOP,
    MULTI_EXIT_DISC, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR, AS4_AGGREGATOR (RFC 4271, RFC
    6793), COMMUNITIES (RFC 1997), EXTENDED COMMUNITIES (RFC 4360), LARGE_COMMUNITY (RFC 8092),
    ORIGINATOR_ID and CLUSTER_LIST (RFC 4456), MP_REACH_NLRI and MP_UNREACH_NLRI (RFC 4760) are
    decoded; every other attribute is returned untouched in ``unknown``.

    ``four_octet_as`` is the AS number width of AS_PATH and AGGREGATOR (RFC 6793 section 4.1);
    ``add_path`` lists the <AFI, SAFI> pairs whose NLRI carries Path Identifiers (RFC 7911, see
    :func:`pathattr.addpath.receive_families`). Never raises for a bad value: the attribute goes to
    ``undecodable`` with the RFC 7606 approach its fault calls for, and a repeated attribute
    contributes only its first occurrence (RFC 7606 section 3 (g)).
    """
    fields: dict[str, Any] = {}
    unknown: list[RawAttribute] = []
    undecodable: list[Undecodable] = []
    for attr in attributes:
        try:
            if not _decode_one(attr, fields, four_octet_as, add_path):
                unknown.append(attr)
        except (ValueError, BgpError) as error:
            action = _FAULT_ACTION.get(attr.type_code, Action.TREAT_AS_WITHDRAW)
            undecodable.append(Undecodable(attr, action, str(error)))
    return Attributes(
        four_octet_as=four_octet_as,
        unknown=tuple(unknown),
        undecodable=tuple(undecodable),
        **fields,
    )
