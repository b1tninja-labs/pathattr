"""bounds on attribute count, AS path length and message size.

The message-size bounds are RFC text (the constants below). ``check`` is the hostile-input budget:
a design choice, not an RFC, that caps the work one UPDATE can ask of a decoder. RFC 4271 bounds
a message to 4096 octets (RFC 8654: 65535 once negotiated), which already bounds every count, but
the bound is large: 65535 octets hold over 32,000 two-octet NLRI prefixes, or 16,000 large
communities. A collector that decodes untrusted feeds wants its own, smaller, explicit limits,
and wants to know *which* one was hit.

``check(counts, budget)`` compares measured counts (see :func:`pathattr.message.measure`) with a
:class:`Budget` and raises :class:`BudgetExceeded` naming the first limit that is exceeded. It
never truncates and never decides what to do with the message: whether an over-budget UPDATE is
dropped, treated as a withdraw or a session error is the caller's policy. The defaults in
``DEFAULT_BUDGET`` are generous for any real UPDATE (the longest AS_PATH observed on the Internet
is a few hundred hops) and are the library's choice, to be tuned against a real corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

__all__ = [
    "DEFAULT_BUDGET",
    "EXTENDED_MESSAGE_LENGTH",
    "HEADER_LENGTH",
    "MAX_MESSAGE_LENGTH",
    "MIN_NOTIFICATION_LENGTH",
    "MIN_OPEN_LENGTH",
    "MIN_UPDATE_LENGTH",
    "Budget",
    "BudgetExceeded",
    "Counts",
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


@dataclass(frozen=True, slots=True)
class Counts:
    """What one UPDATE contains, measured; every field is a count of items."""

    attributes: int = 0
    as_path_segments: int = 0
    as_path_asns: int = 0
    communities: int = 0
    extended_communities: int = 0
    large_communities: int = 0
    nlri: int = 0
    withdrawn: int = 0


@dataclass(frozen=True, slots=True)
class Budget:
    """Upper bounds, one per :class:`Counts` field. A count equal to its bound is within it."""

    attributes: int = 64
    as_path_segments: int = 64
    as_path_asns: int = 1024
    communities: int = 4096
    extended_communities: int = 2048
    large_communities: int = 2048
    nlri: int = 16384
    withdrawn: int = 16384

    def __post_init__(self) -> None:
        for item in fields(self):
            if getattr(self, item.name) < 0:
                raise ValueError(f"{item.name} must not be negative")


DEFAULT_BUDGET = Budget()


class BudgetExceeded(ValueError):  # noqa: N818 - names the condition, like NeedMore elsewhere
    """A count passed its bound. ``name`` is the Counts field, ``limit`` the bound."""

    def __init__(self, name: str, limit: int, actual: int) -> None:
        super().__init__(f"{name} is {actual}, over the budget of {limit}")
        self.name = name
        self.limit = limit
        self.actual = actual


def check(counts: Counts, budget: Budget = DEFAULT_BUDGET) -> None:
    """Raise :class:`BudgetExceeded` for the first count (in field order) over its bound.

    This is a design choice, not an RFC: see the module text. Returns None when every count
    is within budget.
    """
    for item in fields(counts):
        actual, limit = getattr(counts, item.name), getattr(budget, item.name)
        if actual > limit:
            raise BudgetExceeded(item.name, limit, actual)
