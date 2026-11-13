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

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
