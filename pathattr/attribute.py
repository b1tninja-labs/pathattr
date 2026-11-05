"""attribute flags, type registry and per-attribute codecs (RFC 4271).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "decode_attributes",
]


def decode_attributes(raw: bytes) -> list:
    """Pending behaviour defined by RFC 4271.

    Not implemented yet. See the ``attribute.decode_attributes()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_attributes() is not implemented: RFC 4271")
