"""AS_PATH and AS4_PATH: segments, 2- and 4-octet encodings, and the AS4_PATH merge (RFC 6793).

An AS_PATH is a sequence of segments, each a type and a list of AS numbers (RFC 4271 section 4.3;
RFC 5065 section 3 adds the two confederation types). ``parse_as_path`` decodes the attribute value
with either 2-octet or 4-octet AS numbers; ``merge_as4_path`` rebuilds the full path that a 4-octet
speaker must use when an OLD (2-octet) speaker sent both AS_PATH and AS4_PATH (RFC 6793 section
4.2.3), and ``split_for_old_speaker`` is the sending half (section 4.2.2).

Faults follow RFC 7606 section 7.2 for AS_PATH: an unrecognized segment type, an empty segment, an
overrun or a one-octet underrun is malformed and raises :class:`~pathattr.errors.BgpError`
(UPDATE Message Error, Malformed AS_PATH, subcode 11) for the caller to map to the RFC 7606
approach. AS number 0 is *not* a parse fault here (RFC 7607 section 2 makes it a different
approach for AS_PATH and for AS4_PATH); :func:`contains_as0` reports it.

Scope of what was read: RFC 6793 sections 4.2.2, 4.2.3 and 6, RFC 5065 sections 3 and 5.3,
RFC 7606 section 7.2, RFC 7607 section 2.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum

from .errors import BgpError, ErrorCode, UpdateSubcode

__all__ = [
    "AS_TRANS",
    "AsPath",
    "Segment",
    "SegmentType",
    "contains_as0",
    "encode_as_path",
    "has_as_set",
    "merge_as4_path",
    "parse_as_path",
    "path_length",
    "split_for_old_speaker",
    "strip_confed",
]

#: RFC 6793 section 3: the reserved two-octet AS number that stands for a four-octet AS number
#: that does not fit in two octets.
AS_TRANS = 23456
_MAX_SEGMENT = 255  # RFC 4271 section 4.3: the Path Segment Length is one octet.


class SegmentType(IntEnum):
    """Path segment types: RFC 4271 section 4.3 (1, 2) and RFC 5065 section 3 (3, 4)."""

    AS_SET = 1
    AS_SEQUENCE = 2
    AS_CONFED_SEQUENCE = 3
    AS_CONFED_SET = 4


_CONFED = (SegmentType.AS_CONFED_SEQUENCE, SegmentType.AS_CONFED_SET)


@dataclass(frozen=True, slots=True)
class Segment:
    """One path segment. ``type`` is the wire value, so an unassigned type is never built."""

    type: SegmentType
    asns: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.asns or len(self.asns) > _MAX_SEGMENT:
            raise ValueError("a segment holds 1 to 255 AS numbers")
        for asn in self.asns:
            if not 0 <= asn <= 0xFFFFFFFF:
                raise ValueError(f"AS number {asn} is outside 0..4294967295")


AsPath = tuple[Segment, ...]


def _malformed(text: str) -> BgpError:
    return BgpError(ErrorCode.UPDATE_MESSAGE, UpdateSubcode.MALFORMED_AS_PATH, message=text)


def parse_as_path(raw: bytes, four_octet: bool) -> AsPath:
    """Decode an AS_PATH or AS4_PATH value into segments (RFC 4271 section 4.3, RFC 6793).

    ``four_octet`` is the AS number width: True for AS4_PATH and for AS_PATH between two 4-octet
    speakers (RFC 6793 section 4.1), False for the 2-octet AS_PATH of an OLD speaker. An empty
    value is the empty path, which a route originated inside the local AS carries over IBGP.
    Raises :class:`BgpError` (Malformed AS_PATH) for each fault of RFC 7606 section 7.2.
    """
    width = 4 if four_octet else 2
    segments: list[Segment] = []
    pos, end = 0, len(raw)
    while pos < end:
        if end - pos < 2:
            raise _malformed("one octet remains after the last segment")
        kind, count = raw[pos], raw[pos + 1]
        if kind not in SegmentType._value2member_map_:
            raise _malformed(f"unrecognized segment type {kind}")
        if count == 0:
            raise _malformed("segment with a Path Segment Length of zero")
        pos += 2
        if pos + count * width > end:
            raise _malformed("the last segment runs past the attribute")
        asns = tuple(
            int.from_bytes(raw[pos + i * width : pos + (i + 1) * width], "big")
            for i in range(count)
        )
        pos += count * width
        segments.append(Segment(SegmentType(kind), asns))
    return tuple(segments)


def encode_as_path(path: Iterable[Segment], four_octet: bool) -> bytes:
    """Encode segments as an AS_PATH (or, with ``four_octet``, AS4_PATH) value.

    A 2-octet encoding refuses an AS number above 65535 with ``ValueError``: substituting AS_TRANS
    is a sending policy that also needs an AS4_PATH, and is :func:`split_for_old_speaker`.
    """
    width = 4 if four_octet else 2
    out = bytearray()
    for segment in path:
        out += bytes([segment.type, len(segment.asns)])
        for asn in segment.asns:
            if asn >= 1 << (8 * width):
                raise ValueError(f"AS number {asn} does not fit {width} octets")
            out += asn.to_bytes(width, "big")
    return bytes(out)


def path_length(path: Iterable[Segment]) -> int:
    """The AS_PATH length used for route selection and for the AS4_PATH merge.

    An AS_SET counts as one (RFC 4271 section 9.1.2.2, which RFC 6793 section 4.2.3 names as the
    method) and confederation segments are not counted (RFC 5065 section 5.3, rule 3).
    """
    total = 0
    for segment in path:
        if segment.type is SegmentType.AS_SEQUENCE:
            total += len(segment.asns)
        elif segment.type is SegmentType.AS_SET:
            total += 1
    return total


def has_as_set(path: Iterable[Segment]) -> bool:
    """True when the path holds an AS_SET or AS_CONFED_SET (deprecated by RFC 9774 section 3)."""
    return any(s.type in (SegmentType.AS_SET, SegmentType.AS_CONFED_SET) for s in path)


def contains_as0(path: Iterable[Segment]) -> bool:
    """True when AS number 0 appears (RFC 7607 section 2: malformed in AS_PATH and AS4_PATH)."""
    return any(0 in segment.asns for segment in path)


def strip_confed(path: Iterable[Segment]) -> AsPath:
    """The path without AS_CONFED_SEQUENCE and AS_CONFED_SET segments (RFC 6793 section 6)."""
    return tuple(s for s in path if s.type not in _CONFED)


def _coalesce(segments: list[Segment]) -> AsPath:
    """Join neighbouring AS_SEQUENCE segments when the result still fits one segment."""
    out: list[Segment] = []
    for segment in segments:
        last = out[-1] if out else None
        if (
            last is not None
            and last.type is SegmentType.AS_SEQUENCE
            and segment.type is SegmentType.AS_SEQUENCE
            and len(last.asns) + len(segment.asns) <= _MAX_SEGMENT
        ):
            out[-1] = Segment(SegmentType.AS_SEQUENCE, last.asns + segment.asns)
        else:
            out.append(segment)
    return tuple(out)


def merge_as4_path(as_path: AsPath, as4_path: AsPath) -> AsPath:
    """Rebuild the AS path from AS_PATH and AS4_PATH (RFC 6793 section 4.2.3).

    Confederation segments in ``as4_path`` are dropped first (section 6). If AS_PATH counts fewer
    AS numbers than AS4_PATH, AS4_PATH is ignored and ``as_path`` is returned. Otherwise the
    leading part of AS_PATH, as many AS numbers as it has beyond AS4_PATH, is prepended to
    AS4_PATH; a confederation segment is taken when it leads the path or is adjacent to a taken
    segment. An AS_SET counts as one number and is never split. Neighbouring AS_SEQUENCE
    segments are joined (the RFC does not say; the two forms mean the same path).
    """
    as4 = strip_confed(as4_path)
    surplus = path_length(as_path) - path_length(as4)
    if surplus < 0:
        return as_path
    lead: list[Segment] = []
    taken_last = False
    for index, segment in enumerate(as_path):
        if segment.type in _CONFED:
            taken_last = index == 0 or taken_last
            if taken_last:
                lead.append(segment)
            continue
        if surplus <= 0:
            break
        if segment.type is SegmentType.AS_SET:
            lead.append(segment)
            surplus -= 1
        else:
            keep = min(surplus, len(segment.asns))
            lead.append(Segment(SegmentType.AS_SEQUENCE, segment.asns[:keep]))
            surplus -= keep
        taken_last = True
    return _coalesce(lead + list(as4))


def split_for_old_speaker(path: AsPath) -> tuple[AsPath, AsPath | None]:
    """The AS_PATH and AS4_PATH a NEW speaker sends to an OLD one (RFC 6793 section 4.2.2).

    AS_PATH carries every AS number that does not fit two octets as AS_TRANS, which keeps the
    path length. AS4_PATH is the path with confederation segments removed and 4-octet numbers
    intact, or ``None`` when every number in the path is 2-octet (the RFC says the speaker MUST
    NOT send it then).
    """
    two = tuple(
        Segment(s.type, tuple(a if a <= 0xFFFF else AS_TRANS for a in s.asns)) for s in path
    )
    if all(a <= 0xFFFF for s in path for a in s.asns):
        return two, None
    return two, strip_confed(path)
