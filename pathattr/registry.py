"""The IANA "BGP Path Attributes" registry, as an extract with its provenance.

Source: the IANA ``bgp-parameters`` registry file (the primarysource ``iana`` collection's
``bgp-parameters``), registry id ``bgp-parameters-2``, whose ``updated`` date was 2026-09-09 when
this extract was taken on 2026-11-13. Names are the registry's ``code`` text, shortened where the
registry's own text carries status notes (the status is kept in :data:`STATUS`). The registry
cites the defining document by RFC number in each record; those are kept in :data:`REFERENCE`.

The extract exists so that an attribute code is never a bare number in a log line or a test, and
so that ``tests/test_registry.py`` can fail when ``AttrType`` and the registry disagree. It
does not drive decoding: a code the registry assigns but this library does not decode is still
returned raw by :func:`pathattr.attribute.decode_attributes`.
"""

from __future__ import annotations

__all__ = [
    "ATTRIBUTE_NAMES",
    "IANA_UPDATED",
    "REFERENCE",
    "STATUS",
    "attribute_name",
]

IANA_UPDATED = "2026-09-09"

ATTRIBUTE_NAMES: dict[int, str] = {
    1: "ORIGIN",
    2: "AS_PATH",
    3: "NEXT_HOP",
    4: "MULTI_EXIT_DISC",
    5: "LOCAL_PREF",
    6: "ATOMIC_AGGREGATE",
    7: "AGGREGATOR",
    8: "COMMUNITIES",
    9: "ORIGINATOR_ID",
    10: "CLUSTER_LIST",
    11: "DPA",
    12: "ADVERTISER",
    13: "RCID_PATH / CLUSTER_ID",
    14: "MP_REACH_NLRI",
    15: "MP_UNREACH_NLRI",
    16: "EXTENDED COMMUNITIES",
    17: "AS4_PATH",
    18: "AS4_AGGREGATOR",
    19: "SAFI Specific Attribute (SSA)",
    20: "Connector Attribute",
    21: "AS_PATHLIMIT",
    22: "PMSI_TUNNEL",
    23: "Tunnel Encapsulation",
    24: "Traffic Engineering",
    25: "IPv6 Address Specific Extended Community",
    26: "AIGP",
    27: "PE Distinguisher Labels",
    28: "BGP Entropy Label Capability Attribute",
    29: "BGP-LS Attribute",
    32: "LARGE_COMMUNITY",
    33: "BGPsec_Path",
    34: "BGP Community Container Attribute",
    35: "Only to Customer (OTC)",
    36: "BGP Domain Path (D-PATH)",
    37: "SFP attribute",
    38: "BFD Discriminator",
    39: "Next Hop Dependent Characteristic (NHC)",
    40: "BGP Prefix-SID",
    41: "BIER",
    42: "Edge Metadata Path Attribute",
    128: "ATTR_SET",
}

#: Codes the registry marks deprecated, historic or temporary, with the registry's word.
STATUS: dict[int, str] = {
    11: "deprecated",
    12: "deprecated",
    13: "deprecated",
    19: "deprecated",
    20: "deprecated",
    21: "deprecated",
    28: "deprecated",
    30: "deprecated",
    31: "deprecated",
    34: "temporary",
    42: "temporary",
    129: "deprecated",
    241: "deprecated",
    242: "deprecated",
    243: "deprecated",
}

#: The defining document of each named code, as the registry's xref gives it (None: a person).
REFERENCE: dict[int, str | None] = {
    1: "RFC 4271",
    2: "RFC 4271",
    3: "RFC 4271",
    4: "RFC 4271",
    5: "RFC 4271",
    6: "RFC 4271",
    7: "RFC 4271",
    8: "RFC 1997",
    9: "RFC 4456",
    10: "RFC 4456",
    14: "RFC 4760",
    15: "RFC 4760",
    16: None,
    17: "RFC 6793",
    18: "RFC 6793",
    32: "RFC 8092",
    35: "RFC 9234",
}


def attribute_name(code: int) -> str:
    """The registry name of a path attribute type code, or ``"unassigned"``/``"reserved"``."""
    if code == 0 or code == 255:
        return "reserved"
    return ATTRIBUTE_NAMES.get(code, "unassigned")
