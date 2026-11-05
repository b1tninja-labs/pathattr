"""prefix, multiprotocol reachability and unreachability (RFC 4271, RFC 4760 lineage).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "parse_nlri",
]


def parse_nlri(raw: bytes, afi: int, safi: int, add_path: bool) -> list:
    """Pending behaviour defined by RFC 7911.

    Not implemented yet. See the ``nlri.parse_nlri()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_nlri() is not implemented: RFC 7911")
