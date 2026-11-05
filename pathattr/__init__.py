"""pathattr -- the BGP wire codec a looking glass is built on.

Everything a looking glass shows is a BGP UPDATE, and Python has no decoder it can own.
"""

from __future__ import annotations

from . import addpath, apps, aspath, attribute, cli, communities, limits, message, nlri, roles
from .aspath import parse_as_path
from .attribute import decode_attributes
from .communities import decode_communities, decode_extended
from .limits import check
from .message import decode, encode
from .nlri import parse_nlri
from .roles import peer_role

__version__ = "0.1.0"

__all__ = [
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
    "encode",
    "limits",
    "message",
    "nlri",
    "parse_as_path",
    "parse_nlri",
    "peer_role",
    "roles",
]
