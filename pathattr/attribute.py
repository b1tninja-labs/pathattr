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

from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "Action",
    "AttrType",
    "Issue",
    "RawAttribute",
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
    elif code == AttrType.COMMUNITIES:
        if n == 0 or n % 4:
            return Action.TREAT_AS_WITHDRAW, "COMMUNITIES length is not a non-zero multiple of 4"
    elif code == AttrType.CLUSTER_LIST:
        if n == 0 or n % 4:
            return Action.TREAT_AS_WITHDRAW, "CLUSTER_LIST length is not a non-zero multiple of 4"
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


def decode_attributes(raw: bytes) -> list:
    """Pending behaviour defined by RFC 4271.

    Not implemented yet. See the ``attribute.decode_attributes()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    Per-attribute value decoding is separate from :func:`walk`, which frames and judges only.
    """
    raise NotImplementedError("decode_attributes() is not implemented: RFC 4271")
