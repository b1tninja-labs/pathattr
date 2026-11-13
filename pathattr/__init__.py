"""pathattr -- the BGP wire codec a looking glass is built on.

Everything a looking glass shows is a BGP UPDATE, and Python has no decoder it can own.
"""

from __future__ import annotations

from . import (
    addpath,
    apps,
    aspath,
    attribute,
    cli,
    communities,
    errors,
    limits,
    message,
    nlri,
    roles,
)
from .aspath import parse_as_path
from .attribute import Action, Issue, RawAttribute, Walked, decode_attributes, walk
from .communities import decode_communities, decode_extended
from .errors import BgpError
from .limits import check
from .message import (
    Keepalive,
    Notification,
    Open,
    Update,
    decode,
    decode_header,
    decode_stream,
    encode,
)
from .nlri import encode_prefix_list, parse_nlri, parse_prefix_list
from .roles import peer_role

__version__ = "0.1.0"

__all__ = [
    "Action",
    "BgpError",
    "Issue",
    "Keepalive",
    "Notification",
    "Open",
    "RawAttribute",
    "Update",
    "Walked",
    "__version__",
    "addpath",
    "apps",
    "aspath",
    "attribute",
    "check",
    "cli",
    "communities",
    "decode",
    "decode_attributes",
    "decode_communities",
    "decode_extended",
    "decode_header",
    "decode_stream",
    "encode",
    "encode_prefix_list",
    "errors",
    "limits",
    "message",
    "nlri",
    "parse_as_path",
    "parse_nlri",
    "parse_prefix_list",
    "peer_role",
    "roles",
    "walk",
]
