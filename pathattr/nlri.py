"""prefix lists, MP_REACH_NLRI and MP_UNREACH_NLRI, and ADD-PATH path identifiers.

``parse_prefix_list`` and ``encode_prefix_list`` implement the plain <length, prefix> list of RFC
4271 section 4.3, the encoding of the Withdrawn Routes field and the NLRI field.

``parse_nlri`` reads the same list for an <AFI, SAFI>, optionally with the 4-octet Path Identifier
that RFC 7911 section 3 prepends to every entry. Only AFI 1 and 2 with SAFI 1 and 2 are decoded:
RFC 4760 section 5 states the encoding for SAFI 1 and 2 only (held erratum 5120 notes that the
text of section 5 does not say so itself), and every other family has its own NLRI format. An
attribute for another family is *kept*: its NLRI octets stay in ``nlri_raw`` and ``nlri`` is None,
so nothing is guessed and nothing is dropped.

``parse_mp_reach`` and ``parse_mp_unreach`` decode the attribute values of RFC 4760 sections 3 and
4. The next hop length must be what the family allows (RFC 7606 section 7.11): 4, 16 or 32 for
AFI 1 (16 and 32 only with RFC 8950's IPv6 next hop for IPv4 NLRI), 16 or 32 for AFI 2 (RFC 2545
section 3). A fault that stops the NLRI being located is :class:`MpError`, for which RFC 7606
sections 3 (j) and 7.11 require the "AFI/SAFI disable" or session reset approach, never
treat-as-withdraw.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal, overload

from .errors import BgpError, ErrorCode, UpdateSubcode

__all__ = [
    "MpError",
    "MpReach",
    "MpUnreach",
    "Nlri",
    "UnsupportedFamilyError",
    "encode_mp_reach",
    "encode_mp_unreach",
    "encode_nlri",
    "encode_prefix_list",
    "parse_mp_reach",
    "parse_mp_unreach",
    "parse_nlri",
    "parse_prefix_list",
]

AFI_IPV4 = 1
AFI_IPV6 = 2
SAFI_UNICAST = 1
SAFI_MULTICAST = 2
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Prefix = ipaddress.IPv4Network | ipaddress.IPv6Network
Family = tuple[int, int]


@overload
def parse_prefix_list(
    raw: bytes, *, ipv6: Literal[False] = False
) -> tuple[ipaddress.IPv4Network, ...]: ...
@overload
def parse_prefix_list(raw: bytes, *, ipv6: Literal[True]) -> tuple[ipaddress.IPv6Network, ...]: ...
def parse_prefix_list(
    raw: bytes, *, ipv6: bool = False
) -> tuple[ipaddress.IPv4Network, ...] | tuple[ipaddress.IPv6Network, ...]:
    """Parse a list of <length, prefix> pairs (RFC 4271 section 4.3).

    ``length`` is in bits and the prefix occupies ceil(length / 8) octets; the trailing bits in
    the last octet are irrelevant (section 4.3) and are cleared here. The field is syntactically
    incorrect, and ``BgpError`` (UPDATE Message Error, Invalid Network Field) is raised, if any
    length exceeds 32 (128 for IPv6) or the last prefix runs past the end of the field (RFC 7606
    section 5.3). Never returns a partial list.
    """
    bits = 128 if ipv6 else 32
    width = bits // 8
    out: list = []
    pos, end = 0, len(raw)
    while pos < end:
        length = raw[pos]
        pos += 1
        if length > bits:
            raise BgpError(
                ErrorCode.UPDATE_MESSAGE,
                UpdateSubcode.INVALID_NETWORK_FIELD,
                message=f"prefix length {length} exceeds {bits}",
            )
        octets = (length + 7) // 8
        if pos + octets > end:
            raise BgpError(
                ErrorCode.UPDATE_MESSAGE,
                UpdateSubcode.INVALID_NETWORK_FIELD,
                message="prefix runs past the end of the field",
            )
        packed = raw[pos : pos + octets] + bytes(width - octets)
        pos += octets
        if ipv6:
            out.append(ipaddress.IPv6Network((packed, length), strict=False))
        else:
            out.append(ipaddress.IPv4Network((packed, length), strict=False))
    return tuple(out)


def encode_prefix_list(
    prefixes: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    | list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bytes:
    """Encode prefixes as <length, prefix> pairs, each with the minimum number of octets."""
    out = bytearray()
    for net in prefixes:
        out.append(net.prefixlen)
        out += net.network_address.packed[: (net.prefixlen + 7) // 8]
    return bytes(out)


class UnsupportedFamilyError(ValueError):
    """The <AFI, SAFI> has an NLRI format this module does not decode."""


class MpError(ValueError):
    """An MP_REACH_NLRI or MP_UNREACH_NLRI value that cannot be parsed (RFC 7606 5.3, 7.11).

    ``afi_safi_disable`` is always True: when the next hop or the NLRI cannot be located, RFC 7606
    section 3 (j) leaves only the "AFI/SAFI disable" or "session reset" approach.
    """

    afi_safi_disable = True


@dataclass(frozen=True, slots=True)
class Nlri:
    """One prefix and, under ADD-PATH, its Path Identifier (RFC 7911 section 3)."""

    prefix: Prefix
    path_id: int | None = None


def _invalid_network(text: str) -> BgpError:
    return BgpError(ErrorCode.UPDATE_MESSAGE, UpdateSubcode.INVALID_NETWORK_FIELD, message=text)


def _bits_for(afi: int, safi: int) -> int:
    if safi not in (SAFI_UNICAST, SAFI_MULTICAST) or afi not in (AFI_IPV4, AFI_IPV6):
        raise UnsupportedFamilyError(f"NLRI of AFI {afi} SAFI {safi} is not decoded")
    return 32 if afi == AFI_IPV4 else 128


def parse_nlri(raw: bytes, afi: int, safi: int, add_path: bool) -> list[Nlri]:
    """Parse an NLRI list for <AFI, SAFI>, with Path Identifiers when ``add_path`` (RFC 7911).

    ``add_path`` is true only when the ADD-PATH capability was exchanged so that this end receives
    multiple paths for the family (RFC 7911 sections 4 and 5; see :mod:`pathattr.addpath`); the
    extended encoding then applies to every entry (section 3). Prefix bits past the length are
    cleared. A length beyond the family's width or an entry that runs past the end, including a
    path identifier cut short, raises :class:`BgpError` (Invalid Network Field, RFC 7606
    section 5.3). Raises :class:`UnsupportedFamilyError` for a family other than AFI 1 or 2 with SAFI
    1 or 2 (RFC 4760 section 5 defines the encoding for SAFI 1 and 2 only).
    """
    bits = _bits_for(afi, safi)
    width = bits // 8
    out: list[Nlri] = []
    pos, end = 0, len(raw)
    while pos < end:
        path_id = None
        if add_path:
            if end - pos < 5:
                raise _invalid_network("path identifier or length cut short")
            path_id = int.from_bytes(raw[pos : pos + 4], "big")
            pos += 4
        length = raw[pos]
        pos += 1
        if length > bits:
            raise _invalid_network(f"prefix length {length} exceeds {bits}")
        octets = (length + 7) // 8
        if pos + octets > end:
            raise _invalid_network("prefix runs past the end of the field")
        packed = raw[pos : pos + octets] + bytes(width - octets)
        pos += octets
        net: Prefix = (
            ipaddress.IPv4Network((packed, length), strict=False)
            if bits == 32
            else ipaddress.IPv6Network((packed, length), strict=False)
        )
        out.append(Nlri(net, path_id))
    return out


def encode_nlri(entries: list[Nlri] | tuple[Nlri, ...], add_path: bool) -> bytes:
    """Encode NLRI entries, with a Path Identifier each when ``add_path`` (RFC 7911 section 3)."""
    out = bytearray()
    for entry in entries:
        if add_path:
            if entry.path_id is None:
                raise ValueError("ADD-PATH encoding needs a path_id on every entry")
            out += entry.path_id.to_bytes(4, "big")
        elif entry.path_id is not None:
            raise ValueError("a path_id needs the ADD-PATH encoding")
        out.append(entry.prefix.prefixlen)
        out += entry.prefix.network_address.packed[: (entry.prefix.prefixlen + 7) // 8]
    return bytes(out)


@dataclass(frozen=True, slots=True)
class MpReach:
    """MP_REACH_NLRI (RFC 4760 section 3).

    ``nlri`` is None when the family's NLRI is not decoded; ``nlri_raw`` always holds the octets.
    ``next_hop`` is the raw next hop field, ``next_hops`` its reading for AFI 1 and 2.
    """

    afi: int
    safi: int
    next_hop: bytes
    nlri: tuple[Nlri, ...] | None
    nlri_raw: bytes
    add_path: bool = False

    @property
    def next_hops(self) -> tuple[Address, ...]:
        """Global address, then link-local when 32 octets (RFC 2545 section 3, RFC 8950 section 3).

        Empty for a family whose next hop format is not decoded.
        """
        return _next_hops(self.afi, self.safi, self.next_hop) or ()


@dataclass(frozen=True, slots=True)
class MpUnreach:
    """MP_UNREACH_NLRI (RFC 4760 section 4); an empty ``nlri`` is the End-of-RIB marker form."""

    afi: int
    safi: int
    nlri: tuple[Nlri, ...] | None
    nlri_raw: bytes
    add_path: bool = False


def _next_hops(afi: int, safi: int, raw: bytes) -> tuple[Address, ...] | None:
    """The next hop addresses for a decoded family, or None when the family is not decoded.

    Raises :class:`MpError` when the length is not one the family allows (RFC 7606 section 7.11).
    """
    if safi not in (SAFI_UNICAST, SAFI_MULTICAST) or afi not in (AFI_IPV4, AFI_IPV6):
        return None
    allowed = (4, 16, 32) if afi == AFI_IPV4 else (16, 32)
    if len(raw) not in allowed:
        raise MpError(
            f"next hop length {len(raw)} is not one of {allowed} for AFI {afi} SAFI {safi}"
        )
    if len(raw) == 4:
        return (ipaddress.IPv4Address(raw),)
    return tuple(ipaddress.IPv6Address(raw[i : i + 16]) for i in range(0, len(raw), 16))


def parse_mp_reach(value: bytes, add_path: frozenset[Family] = frozenset()) -> MpReach:
    """Decode an MP_REACH_NLRI value (RFC 4760 section 3, RFC 7606 sections 5.3 and 7.11).

    ``add_path`` lists the <AFI, SAFI> pairs for which this end receives ADD-PATH NLRI. Raises
    :class:`MpError` when the value is shorter than 5 octets, the next hop length is wrong for
    the family or overruns, or the NLRI cannot be parsed (a malformed NLRI list is reported as
    :class:`MpError` here because RFC 7606 section 5.3 calls the attribute itself incorrect). The
    Reserved octet is ignored (RFC 4760 section 3).
    """
    if len(value) < 5:
        raise MpError("MP_REACH_NLRI is shorter than 5 octets")
    afi, safi, nh_len = int.from_bytes(value[0:2], "big"), value[2], value[3]
    if 4 + nh_len + 1 > len(value):
        raise MpError("next hop runs past the end of the attribute")
    next_hop = bytes(value[4 : 4 + nh_len])
    _next_hops(afi, safi, next_hop)
    nlri_raw = bytes(value[4 + nh_len + 1 :])
    use_path = (afi, safi) in add_path
    try:
        nlri: tuple[Nlri, ...] | None = tuple(parse_nlri(nlri_raw, afi, safi, use_path))
    except UnsupportedFamilyError:
        nlri = None
    except BgpError as error:
        raise MpError(f"NLRI cannot be parsed: {error}") from error
    return MpReach(afi, safi, next_hop, nlri, nlri_raw, use_path and nlri is not None)


def parse_mp_unreach(value: bytes, add_path: frozenset[Family] = frozenset()) -> MpUnreach:
    """Decode an MP_UNREACH_NLRI value (RFC 4760 section 4, RFC 7606 section 5.3).

    Raises :class:`MpError` when the value is shorter than 3 octets or the withdrawn NLRI cannot
    be parsed.
    """
    if len(value) < 3:
        raise MpError("MP_UNREACH_NLRI is shorter than 3 octets")
    afi, safi = int.from_bytes(value[0:2], "big"), value[2]
    nlri_raw = bytes(value[3:])
    use_path = (afi, safi) in add_path
    try:
        nlri: tuple[Nlri, ...] | None = tuple(parse_nlri(nlri_raw, afi, safi, use_path))
    except UnsupportedFamilyError:
        nlri = None
    except BgpError as error:
        raise MpError(f"withdrawn NLRI cannot be parsed: {error}") from error
    return MpUnreach(afi, safi, nlri, nlri_raw, use_path and nlri is not None)


def encode_mp_reach(reach: MpReach) -> bytes:
    """Encode an MP_REACH_NLRI value with the Reserved octet zero (RFC 4760 section 3)."""
    if len(reach.next_hop) > 255:
        raise ValueError("next hop longer than 255 octets")
    body = (
        reach.afi.to_bytes(2, "big")
        + bytes([reach.safi, len(reach.next_hop)])
        + reach.next_hop
        + b"\x00"
    )
    if reach.nlri is None:
        return body + reach.nlri_raw
    return body + encode_nlri(reach.nlri, reach.add_path)


def encode_mp_unreach(unreach: MpUnreach) -> bytes:
    """Encode an MP_UNREACH_NLRI value (RFC 4760 section 4)."""
    body = unreach.afi.to_bytes(2, "big") + bytes([unreach.safi])
    if unreach.nlri is None:
        return body + unreach.nlri_raw
    return body + encode_nlri(unreach.nlri, unreach.add_path)
