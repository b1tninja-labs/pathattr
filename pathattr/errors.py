"""NOTIFICATION error codes and the exception that carries one (RFC 4271 sections 4.5 and 6).

``BgpError`` is what the codec raises for anything a conforming speaker must answer with a
NOTIFICATION. It carries exactly the Error Code, Error Subcode and Data that RFC 4271 section 6
says to send, so a caller can build the NOTIFICATION without re-deriving anything.

Subcode 0 (Unspecific) is a defined value for every Error Code (RFC 4271 verified erratum 4493,
section 4.5), so ``Unspecific`` is a member of every subcode enumeration below.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = [
    "BgpError",
    "ErrorCode",
    "HeaderSubcode",
    "OpenSubcode",
    "RouteRefreshSubcode",
    "UpdateSubcode",
]


class ErrorCode(IntEnum):
    """Error Code octet (RFC 4271 section 4.5)."""

    MESSAGE_HEADER = 1
    OPEN_MESSAGE = 2
    UPDATE_MESSAGE = 3
    HOLD_TIMER_EXPIRED = 4
    FSM = 5
    CEASE = 6
    ROUTE_REFRESH = 7  # RFC 7313 section 5


class HeaderSubcode(IntEnum):
    """Message Header Error subcodes (RFC 4271 section 4.5, with 0 from erratum 4493)."""

    UNSPECIFIC = 0
    CONNECTION_NOT_SYNCHRONIZED = 1
    BAD_MESSAGE_LENGTH = 2
    BAD_MESSAGE_TYPE = 3


class OpenSubcode(IntEnum):
    """OPEN Message Error subcodes (RFC 4271 section 4.5; 5 is deprecated)."""

    UNSPECIFIC = 0
    UNSUPPORTED_VERSION_NUMBER = 1
    BAD_PEER_AS = 2
    BAD_BGP_IDENTIFIER = 3
    UNSUPPORTED_OPTIONAL_PARAMETER = 4
    UNACCEPTABLE_HOLD_TIME = 6
    ROLE_MISMATCH = 11  # RFC 9234 section 7; 8 to 10 are deprecated


class UpdateSubcode(IntEnum):
    """UPDATE Message Error subcodes (RFC 4271 section 4.5; 7 is deprecated)."""

    UNSPECIFIC = 0
    MALFORMED_ATTRIBUTE_LIST = 1
    UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE = 2
    MISSING_WELL_KNOWN_ATTRIBUTE = 3
    ATTRIBUTE_FLAGS_ERROR = 4
    ATTRIBUTE_LENGTH_ERROR = 5
    INVALID_ORIGIN_ATTRIBUTE = 6
    INVALID_NEXT_HOP_ATTRIBUTE = 8
    OPTIONAL_ATTRIBUTE_ERROR = 9
    INVALID_NETWORK_FIELD = 10
    MALFORMED_AS_PATH = 11


class RouteRefreshSubcode(IntEnum):
    """ROUTE-REFRESH Message Error subcodes (RFC 7313 section 5)."""

    INVALID_MESSAGE_LENGTH = 1


class BgpError(Exception):
    """A message a conforming speaker answers with a NOTIFICATION.

    ``code``, ``subcode`` and ``data`` are the NOTIFICATION fields RFC 4271 section 6 prescribes
    for the fault. ``data`` is empty where section 6 names no Data content.
    """

    def __init__(self, code: int, subcode: int, data: bytes = b"", message: str = "") -> None:
        super().__init__(message or f"BGP error {code}/{subcode}")
        self.code = int(code)
        self.subcode = int(subcode)
        self.data = bytes(data)
