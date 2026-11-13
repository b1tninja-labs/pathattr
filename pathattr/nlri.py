"""prefix, multiprotocol reachability and unreachability (RFC 4271, RFC 4760 lineage).

``parse_prefix_list`` and ``encode_prefix_list`` implement the plain <length, prefix> list of RFC
4271 section 4.3, which is the encoding of the Withdrawn Routes field, the NLRI field and (for the
AFI/SAFI that use it) the NLRI inside MP_REACH_NLRI. ``parse_nlri`` (multiprotocol and ADD-PATH,
RFC 7911) is still a loud stub.
"""

from __future__ import annotations

import ipaddress
from typing import Literal, overload

from .errors import BgpError, ErrorCode, UpdateSubcode

__all__ = [
    "encode_prefix_list",
    "parse_nlri",
    "parse_prefix_list",
]


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


def parse_nlri(raw: bytes, afi: int, safi: int, add_path: bool) -> list:
    """Pending behaviour defined by RFC 7911.

    Not implemented yet. See the ``nlri.parse_nlri()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_nlri() is not implemented: RFC 7911")
