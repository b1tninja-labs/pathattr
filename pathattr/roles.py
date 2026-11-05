"""the BGP_ROLE capability and path attribute (RFC 9234).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Role = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "peer_role",
]


def peer_role(capability: bytes) -> Role:
    """Pending behaviour defined by RFC 9234.

    Not implemented yet. See the ``roles.peer_role()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("peer_role() is not implemented: RFC 9234")
