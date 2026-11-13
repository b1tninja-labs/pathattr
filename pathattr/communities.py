"""Communities (RFC 1997), large communities (RFC 8092) and extended communities (RFC 4360).

Three attributes, three decoders, one rule: nothing is lost. A community this module has no name
for is still a value; an extended community of an unassigned type keeps all eight octets
(RFC 7606 section 7.14: an unrecognized type or sub-type is not an error).

* ``decode_communities``: COMMUNITIES (type 8, RFC 1997). Each community is four octets; the
  high half is conventionally an AS number and the low half an operator value. The well-known
  names come from the IANA "BGP Well-known Communities" registry, kept as an extract in
  :data:`WELL_KNOWN` with the registry's ``updated`` date in :data:`IANA_WELL_KNOWN_UPDATED`.
* ``decode_large_communities``: LARGE_COMMUNITY (type 32, RFC 8092 section 3). Twelve octets each;
  duplicates are removed on receipt, first occurrence kept, as section 3 requires.
* ``decode_extended``: EXTENDED COMMUNITIES (type 16, RFC 4360 section 2). Eight octets each.
  The high octet is the Type: bit 0x80 is the IANA-authority bit and bit 0x40 the
  *non-transitive* bit (value 1 means non-transitive; RFC 4360 section 2). The low octet is the
  sub-type for the three families RFC 4360 section 3 defines (two-octet AS, IPv4 address, opaque)
  and for RFC 5668's four-octet AS family; the typed views below exist for those and for no
  other type.

Scope of what was read: RFC 4360 sections 2 and 3, RFC 7153 section 2, RFC 8092 section 3,
RFC 7606 sections 7.8 and 7.14, and the IANA registries named above (read 2026-11-13).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

__all__ = [
    "IANA_EXTENDED_UPDATED",
    "IANA_WELL_KNOWN_UPDATED",
    "WELL_KNOWN",
    "Community",
    "ExtendedCommunity",
    "Ipv6ExtendedCommunity",
    "LargeCommunity",
    "decode_communities",
    "decode_extended",
    "decode_ipv6_extended",
    "decode_large_communities",
]

#: ``updated`` of bgp-well-known-communities.xml when the extract below was taken.
IANA_WELL_KNOWN_UPDATED = "2026-09-22"
#: ``updated`` of bgp-extended-communities.xml when the type names below were taken.
IANA_EXTENDED_UPDATED = "2026-10-23"

#: IANA "BGP Well-known Communities", assigned values only, with the defining document.
WELL_KNOWN: dict[int, tuple[str, str]] = {
    0xFFFF0000: ("GRACEFUL_SHUTDOWN", "RFC 8326"),
    0xFFFF0001: ("ACCEPT_OWN", "RFC 7611"),
    0xFFFF0002: ("ROUTE_FILTER_TRANSLATED_v4", "draft-l3vpn-legacy-rtc-00"),
    0xFFFF0003: ("ROUTE_FILTER_v4", "draft-l3vpn-legacy-rtc-00"),
    0xFFFF0004: ("ROUTE_FILTER_TRANSLATED_v6", "draft-l3vpn-legacy-rtc-00"),
    0xFFFF0005: ("ROUTE_FILTER_v6", "draft-l3vpn-legacy-rtc-00"),
    0xFFFF0006: ("LLGR_STALE", "RFC 9494"),
    0xFFFF0007: ("NO_LLGR", "RFC 9494"),
    0xFFFF0008: ("accept-own-nexthop", "draft-agrewal-idr-accept-own-nexthop-00"),
    0xFFFF0009: ("Standby PE", "RFC 9026"),
    0xFFFF000A: ("DOWNGRADE", "draft-ietf-grow-downgrade-bgp-community-00"),
    0xFFFF029A: ("BLACKHOLE", "RFC 7999"),
    0xFFFFFF01: ("NO_EXPORT", "RFC 1997"),
    0xFFFFFF02: ("NO_ADVERTISE", "RFC 1997"),
    0xFFFFFF03: ("NO_EXPORT_SUBCONFED", "RFC 1997"),
    0xFFFFFF04: ("NOPEER", "RFC 3765"),
}


@dataclass(frozen=True, slots=True)
class Community:
    """A 4-octet community (RFC 1997): the whole value, with the usual AS:value reading."""

    value: int

    @property
    def asn(self) -> int:
        return self.value >> 16

    @property
    def local(self) -> int:
        return self.value & 0xFFFF

    @property
    def well_known(self) -> str | None:
        """The IANA name when the value is an assigned well-known community, else None."""
        entry = WELL_KNOWN.get(self.value)
        return entry[0] if entry else None

    def __str__(self) -> str:
        return self.well_known or f"{self.asn}:{self.local}"


def decode_communities(raw: bytes) -> tuple[Community, ...]:
    """Decode a COMMUNITIES value (RFC 1997): a non-zero multiple of four octets.

    Order and repetition are kept as received. Raises ``ValueError`` for any other length, which
    RFC 7606 section 7.8 makes treat-as-withdraw.
    """
    if not raw or len(raw) % 4:
        raise ValueError("COMMUNITIES length is not a non-zero multiple of 4 (RFC 7606 7.8)")
    return tuple(Community(int.from_bytes(raw[i : i + 4], "big")) for i in range(0, len(raw), 4))


@dataclass(frozen=True, slots=True)
class LargeCommunity:
    """A 12-octet large community (RFC 8092 section 3)."""

    global_admin: int
    local1: int
    local2: int

    def __str__(self) -> str:
        return f"{self.global_admin}:{self.local1}:{self.local2}"


def decode_large_communities(raw: bytes) -> tuple[LargeCommunity, ...]:
    """Decode a LARGE_COMMUNITY value (RFC 8092 section 3): multiples of twelve octets.

    Redundant values are silently removed, the first occurrence kept (RFC 8092 section 3: "A
    receiving speaker MUST silently remove redundant BGP Large Community values"). Raises
    ``ValueError`` when the length is not a non-zero multiple of 12.
    """
    if not raw or len(raw) % 12:
        raise ValueError("LARGE_COMMUNITY length is not a non-zero multiple of 12 (RFC 8092 3)")
    seen: dict[LargeCommunity, None] = {}
    for i in range(0, len(raw), 12):
        item = LargeCommunity(
            int.from_bytes(raw[i : i + 4], "big"),
            int.from_bytes(raw[i + 4 : i + 8], "big"),
            int.from_bytes(raw[i + 8 : i + 12], "big"),
        )
        seen.setdefault(item)
    return tuple(seen)


# IANA "BGP Transitive/Non-Transitive Extended Community Types" family by (type & 0x3F), for the
# four families whose value layout is fixed by RFC 4360 section 3 and RFC 5668.
_FAMILIES = {0x00: "two-octet-as", 0x01: "ipv4", 0x02: "four-octet-as", 0x03: "opaque"}
# Sub-types that every AS-specific and IPv4-specific family shares (IANA sub-type registries).
_SUBTYPES = {0x02: "Route Target", 0x03: "Route Origin"}


@dataclass(frozen=True, slots=True)
class ExtendedCommunity:
    """An 8-octet extended community, kept whole (RFC 4360 section 2)."""

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != 8:
            raise ValueError("an extended community is exactly 8 octets")

    @property
    def type_high(self) -> int:
        return self.raw[0]

    @property
    def subtype(self) -> int:
        """The second octet: the sub-type for the families that have one (RFC 7153 section 2)."""
        return self.raw[1]

    @property
    def transitive(self) -> bool:
        """True when bit 0x40 of the Type is 0 (RFC 4360 section 2: 0 means transitive)."""
        return not self.raw[0] & 0x40

    @property
    def iana_authority(self) -> bool:
        """The I bit (0x80): 1 means the part of the space for Standards Action or experiments."""
        return bool(self.raw[0] & 0x80)

    @property
    def family(self) -> str | None:
        """``two-octet-as``, ``ipv4``, ``four-octet-as`` or ``opaque``; None for any other type."""
        if self.raw[0] & 0x80:
            return None
        return _FAMILIES.get(self.raw[0] & 0x3F)

    @property
    def subtype_name(self) -> str | None:
        """Route Target or Route Origin for the AS and IPv4 families, else None."""
        if self.family in ("two-octet-as", "ipv4", "four-octet-as"):
            return _SUBTYPES.get(self.raw[1])
        return None

    def administrator(self) -> tuple[int | ipaddress.IPv4Address, int] | None:
        """(global administrator, local administrator) for the three AS/IPv4 families, else None."""
        family = self.family
        body = self.raw[2:]
        if family == "two-octet-as":
            return int.from_bytes(body[:2], "big"), int.from_bytes(body[2:], "big")
        if family == "four-octet-as":
            return int.from_bytes(body[:4], "big"), int.from_bytes(body[4:], "big")
        if family == "ipv4":
            return ipaddress.IPv4Address(body[:4]), int.from_bytes(body[4:], "big")
        return None

    def __str__(self) -> str:
        admin = self.administrator()
        if admin is not None and self.subtype_name:
            label = "rt" if self.subtype_name == "Route Target" else "ro"
            return f"{label}:{admin[0]}:{admin[1]}"
        return "0x" + self.raw.hex()


def decode_extended(raw: bytes) -> tuple[ExtendedCommunity, ...]:
    """Decode an EXTENDED COMMUNITIES value (RFC 4360 section 2): multiples of eight octets.

    Every community is returned whole whatever its type, so an unassigned or experimental type
    survives (RFC 7606 section 7.14). Raises ``ValueError`` for a length that is not a non-zero
    multiple of 8, which RFC 7606 section 7.14 makes treat-as-withdraw.
    """
    if not raw or len(raw) % 8:
        raise ValueError("EXTENDED COMMUNITIES length is not a non-zero multiple of 8 (RFC 7606)")
    return tuple(ExtendedCommunity(bytes(raw[i : i + 8])) for i in range(0, len(raw), 8))


@dataclass(frozen=True, slots=True)
class Ipv6ExtendedCommunity:
    """A 20-octet IPv6 Address Specific extended community, kept whole (RFC 5701 section 2).

    Octet 0 is 0x00 (transitive) or 0x40 (non-transitive), octet 1 the sub-type, octets 2 to 17
    the Global Administrator (an IPv6 address) and octets 18 and 19 the Local Administrator. The
    sub-types are those of the IPv4 Address Specific family; RFC 5701 section 3 assigns 0x0002
    Route Target and 0x0003 Route Origin. Any other type or sub-type is kept, not an error
    (RFC 7606 section 7.15).
    """

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != 20:
            raise ValueError("an IPv6 address specific extended community is exactly 20 octets")

    @property
    def type_high(self) -> int:
        return self.raw[0]

    @property
    def subtype(self) -> int:
        return self.raw[1]

    @property
    def transitive(self) -> bool:
        """True for type octet 0x00; the 0x40 bit marks non-transitive (RFC 5701 section 2)."""
        return not self.raw[0] & 0x40

    @property
    def global_administrator(self) -> ipaddress.IPv6Address:
        return ipaddress.IPv6Address(self.raw[2:18])

    @property
    def local_administrator(self) -> int:
        return int.from_bytes(self.raw[18:20], "big")

    @property
    def subtype_name(self) -> str | None:
        """Route Target or Route Origin for the two assigned types (0x00 or 0x40 high octet)."""
        if self.raw[0] & 0xBF:
            return None
        return _SUBTYPES.get(self.raw[1])

    def __str__(self) -> str:
        name = self.subtype_name
        if name is not None:
            label = "rt" if name == "Route Target" else "ro"
            return f"{label}:{self.global_administrator}:{self.local_administrator}"
        return "0x" + self.raw.hex()


def decode_ipv6_extended(raw: bytes) -> tuple[Ipv6ExtendedCommunity, ...]:
    """Decode an IPv6 ADDRESS SPECIFIC EXTENDED COMMUNITY value (RFC 5701 section 2).

    Multiples of twenty octets, every one returned whole. Raises ``ValueError`` for a length that
    is not a non-zero multiple of 20, which RFC 7606 section 7.15 makes treat-as-withdraw.
    """
    if not raw or len(raw) % 20:
        raise ValueError("IPv6 EXTENDED COMMUNITIES length is not a non-zero multiple of 20")
    return tuple(Ipv6ExtendedCommunity(bytes(raw[i : i + 20])) for i in range(0, len(raw), 20))
