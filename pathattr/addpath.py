"""The ADD-PATH capability and what it negotiates (RFC 7911 sections 4 and 5).

Capability code 69 carries zero or more <AFI, SAFI, Send/Receive> tuples (section 4). Multiple
paths flow from A to B for a family only when A advertised Send (2 or 3) and B advertised
Receive (1 or 3) for it (section 5). So the families in which *this* end must decode Path
Identifiers on received NLRI are those where the local side advertised Receive and the peer
advertised Send: :func:`receive_families`. That set is what ``nlri.parse_mp_reach`` and
``message.decode`` take as ``add_path``.

A value other than 1, 2 or 3 in a tuple means the whole capability is "not understood and
ignored" (section 4, citing RFC 5492), so :func:`parse_capability` returns no families for it;
a length that is not a multiple of four is malformed and raises ``ValueError``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum

from .message import Capability, Open

__all__ = [
    "ADD_PATH_CAPABILITY",
    "AddPathFamily",
    "SendReceive",
    "encode_capability",
    "parse_capability",
    "receive_families",
    "send_families",
]

#: RFC 7911 section 4: the ADD-PATH Capability code.
ADD_PATH_CAPABILITY = 69


class SendReceive(IntEnum):
    """The Send/Receive octet (RFC 7911 section 4)."""

    RECEIVE = 1
    SEND = 2
    BOTH = 3


@dataclass(frozen=True, slots=True)
class AddPathFamily:
    afi: int
    safi: int
    send_receive: SendReceive

    @property
    def can_receive(self) -> bool:
        return bool(self.send_receive & SendReceive.RECEIVE)

    @property
    def can_send(self) -> bool:
        return bool(self.send_receive & SendReceive.SEND)


def parse_capability(value: bytes) -> tuple[AddPathFamily, ...]:
    """Decode an ADD-PATH Capability value (RFC 7911 section 4).

    Returns no families when any Send/Receive octet is not 1, 2 or 3 (the capability is ignored).
    Raises ``ValueError`` when the length is not a multiple of four.
    """
    if len(value) % 4:
        raise ValueError("ADD-PATH capability length is not a multiple of 4")
    out: list[AddPathFamily] = []
    for i in range(0, len(value), 4):
        mode = value[i + 3]
        if mode not in (1, 2, 3):
            return ()
        afi = int.from_bytes(value[i : i + 2], "big")
        out.append(AddPathFamily(afi, value[i + 2], SendReceive(mode)))
    return tuple(out)


def encode_capability(families: Iterable[AddPathFamily]) -> Capability:
    """An ADD-PATH Capability for an OPEN. All families go in one instance (RFC 7911 section 4)."""
    value = b"".join(
        f.afi.to_bytes(2, "big") + bytes([f.safi, int(f.send_receive)]) for f in families
    )
    return Capability(ADD_PATH_CAPABILITY, value)


def _families(source: Open | Iterable[AddPathFamily]) -> tuple[AddPathFamily, ...]:
    if isinstance(source, Open):
        found: list[AddPathFamily] = []
        for capability in source.capabilities:
            if capability.code == ADD_PATH_CAPABILITY:
                found.extend(parse_capability(capability.value))
        return tuple(found)
    return tuple(source)


def receive_families(
    local: Open | Iterable[AddPathFamily], peer: Open | Iterable[AddPathFamily]
) -> frozenset[tuple[int, int]]:
    """The <AFI, SAFI> pairs whose NLRI from the peer carries Path Identifiers (RFC 7911 5).

    Local advertised Receive and the peer advertised Send. Arguments are the OPEN messages or
    their parsed families.
    """
    mine = {(f.afi, f.safi) for f in _families(local) if f.can_receive}
    theirs = {(f.afi, f.safi) for f in _families(peer) if f.can_send}
    return frozenset(mine & theirs)


def send_families(
    local: Open | Iterable[AddPathFamily], peer: Open | Iterable[AddPathFamily]
) -> frozenset[tuple[int, int]]:
    """The pairs for which this end may send multiple paths: local Send and peer Receive."""
    mine = {(f.afi, f.safi) for f in _families(local) if f.can_send}
    theirs = {(f.afi, f.safi) for f in _families(peer) if f.can_receive}
    return frozenset(mine & theirs)
