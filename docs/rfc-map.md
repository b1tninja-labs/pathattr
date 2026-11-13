# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 4271 | Draft Standard | 2006-01 | 2026-11-05 |
| RFC 4360 | Proposed Standard | 2006-02 | 2026-11-05 |
| RFC 8092 | Proposed Standard | 2017-02 | 2026-11-05 |
| RFC 7911 | Proposed Standard | 2016-07 | 2026-11-05 |
| RFC 9234 | Proposed Standard | 2022-05 | 2026-11-05 |
| RFC 6793 | Proposed Standard | 2012-12 | 2026-11-05 |
| RFC 4760 | Draft Standard | 2007-01 | 2026-11-05 |
| RFC 7606 | Proposed Standard | 2015-08 | 2026-11-05 |
| RFC 5492 | Draft Standard, obsoletes RFC 3392, updated by RFC 8810; capabilities in OPEN | 2009-02 | 2026-11-13 |
| RFC 9072 | Proposed Standard, updates RFC 4271; extended optional parameters length | 2021-07 | 2026-11-13 |
| RFC 8654 | Proposed Standard, updates RFC 4271; extended messages up to 65,535 octets, not OPEN or KEEPALIVE | 2019-10 | 2026-11-13 |
| RFC 1997 | Proposed Standard, updated by RFC 7606 and RFC 8642; type code 8 | 1996-08 | 2026-11-13 |
| RFC 4456 | Draft Standard, updated by RFC 7606; ORIGINATOR_ID 9, CLUSTER_LIST 10 | 2006-04 | 2026-11-13 |
| RFC 5065 | Draft Standard, updated by RFC 9774; AS_CONFED segment types 3 and 4 | 2007-08 | 2026-11-13 |
| RFC 6396 | Proposed Standard; Appendix A is the only published UPDATE vector, with errata 5511 and 6640 | 2011-10 | 2026-11-13 |
| RFC 2918 | Proposed Standard, updated by RFC 7313; ROUTE-REFRESH type 5 | 2000-09 | 2026-11-13 |
| RFC 7313 | Proposed Standard; subtypes (section 3.2) and ROUTE-REFRESH Message Error 7/1 (section 5) | 2014-07 | 2026-11-13 |
| RFC 2545 | Proposed Standard; IPv6 next hop of 16 or 32 octets (section 3) | 1999-03 | 2026-11-13 |
| RFC 8950 | Proposed Standard, obsoletes RFC 5549; IPv6 next hop for IPv4 NLRI (section 3) | 2020-11 | 2026-11-13 |
| RFC 7607 | Proposed Standard; AS 0 (section 2: malformed in AS_PATH and AGGREGATOR by RFC 7606, in AS4_* by RFC 6793) | 2015-08 | 2026-11-13 |
| RFC 7153 | Proposed Standard; extended community Type and Sub-Type registries (section 2) | 2014-03 | 2026-11-13 |
| RFC 9774 | Proposed Standard, obsoletes RFC 6472, updates RFC 4271 and RFC 5065; AS_SET and AS_CONFED_SET (section 3) | 2025-05 | 2026-11-13 |
| IANA bgp-parameters | "BGP Path Attributes" registry, `updated` 2026-09-09; extract in `pathattr/registry.py` | - | 2026-11-13 |
| IANA bgp-well-known-communities | `updated` 2026-09-22; extract in `pathattr/communities.py` | - | 2026-11-13 |
| IANA bgp-extended-communities | `updated` 2026-10-23; Route Target and Route Origin sub-types cite RFC-ietf-idr-rfc4360-bis-09, so RFC 4360 is on its way to replacement | - | 2026-11-13 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

Findings of the 2026-11-13 value-decoding pass:

- RFC 4760 errata (rfclib): 1 verified (1573, section 4: the AFI text for MP_UNREACH_NLRI talks about a Next Hop field that attribute lacks, a technical erratum) and 4 held. Held erratum 5120 notes that the NLRI encoding of section 5 is stated for SAFI 1 and 2 only, which is why `nlri.parse_nlri` refuses every other family and `parse_mp_reach` keeps its octets.
- RFC 7911, RFC 2545, RFC 8950, RFC 7313 and RFC 7153 report no errata; RFC 7607, RFC 6793 and RFC 8092 one on file each, none verified; RFC 4360 two verified, neither on sections 2 or 3.
- RFC 6793 section 6 calls an AS4_PATH malformed when its length "is not a multiple of two or is too small (i.e., less than 6)"; AS4_PATH carries four-octet numbers, so a length that is a multiple of two but not four is caught by the segment check, which is what `walk` applies.
- RFC 6793 section 4.2.3 leaves the joining of the prepended AS_PATH part and AS4_PATH open; `merge_as4_path` joins neighbouring AS_SEQUENCE segments, which means the same path.
- RFC 4360 section 2 defines the T bit as 1 = non-transitive (0x40 set). Code that reads 0x40 as "transitive" is a common mistake; `ExtendedCommunity.transitive` follows the RFC.
- RFC 7313 section 5 applies its length rule only when the Enhanced Route Refresh capability was received, so `decode` takes `enhanced_route_refresh`.
