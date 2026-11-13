"""bounds on attribute count, AS path length and message size.

The message-size bounds are RFC text (the constants below). ``check`` is the still-unwritten
hostile-input budget (design, not an RFC): a place for caps on attribute count, AS_PATH
segments and NLRI count. It stays a loud stub until that budget is decided.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ParsePlan = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "EXTENDED_MESSAGE_LENGTH",
    "HEADER_LENGTH",
    "MAX_MESSAGE_LENGTH",
    "MIN_NOTIFICATION_LENGTH",
    "MIN_OPEN_LENGTH",
    "MIN_UPDATE_LENGTH",
    "check",
]

#: RFC 4271 section 4.1: the 16-octet Marker, 2-octet Length and 1-octet Type; also the
#: whole length of a KEEPALIVE (section 4.4).
HEADER_LENGTH = 19
#: RFC 4271 section 4.1: the Length field is at most 4096.
MAX_MESSAGE_LENGTH = 4096
#: RFC 8654 section 4: with the Extended Message capability, up to 65,535 octets, for every
#: message except OPEN and KEEPALIVE.
EXTENDED_MESSAGE_LENGTH = 65535
#: RFC 4271 section 4.2.
MIN_OPEN_LENGTH = 29
#: RFC 4271 section 4.3.
MIN_UPDATE_LENGTH = 23
#: RFC 4271 section 4.5.
MIN_NOTIFICATION_LENGTH = 21


def check(plan: ParsePlan) -> None:
    """Pending behaviour defined by design.

    Not implemented yet. See the ``limits.check()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check() is not implemented: design")
