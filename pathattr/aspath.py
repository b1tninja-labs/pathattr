"""AS_SEQUENCE, AS_SET and the 4-octet variants including confederations (RFC 6793).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    AsPath = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "parse_as_path",
]


def parse_as_path(raw: bytes, four_octet: bool) -> AsPath:
    """Pending behaviour defined by RFC 6793.

    Not implemented yet. See the ``aspath.parse_as_path()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse_as_path() is not implemented: RFC 6793")
