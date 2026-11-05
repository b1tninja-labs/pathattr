"""well-known, extended and large communities against the IANA registries (RFC 4360, RFC
8092).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "decode_communities",
    "decode_extended",
]


def decode_communities(raw: bytes) -> list:
    """Pending behaviour defined by RFC 8092.

    Not implemented yet. See the ``communities.decode_communities()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_communities() is not implemented: RFC 8092")


def decode_extended(raw: bytes) -> list:
    """Pending behaviour defined by RFC 4360.

    Not implemented yet. See the ``communities.decode_extended()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_extended() is not implemented: RFC 4360")
