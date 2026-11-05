"""the four message types with header and length discipline (RFC 4271).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Message = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode",
    "encode",
]


def decode(raw: bytes) -> Message:
    """Pending behaviour defined by RFC 4271.

    Not implemented yet. See the ``message.decode()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode() is not implemented: RFC 4271")


def encode(message: Message) -> bytes:
    """Pending behaviour defined by RFC 4271.

    Not implemented yet. See the ``message.encode()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode() is not implemented: RFC 4271")
