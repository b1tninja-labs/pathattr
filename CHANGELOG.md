# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- Attribute value decoding (`attribute.decode_attributes`), AS_PATH and the RFC 6793 AS4_PATH merge
  (`aspath`), communities, large and extended communities (`communities`), MP_REACH_NLRI and
  MP_UNREACH_NLRI with ADD-PATH (`nlri`, `addpath`), OPEN policy (`message.validate_open`),
  ROUTE-REFRESH with RFC 7313 subtypes, the hostile-input budget (`limits.check`) and an IANA
  attribute-name extract (`registry`).
- `walk` now applies RFC 7607 (AS 0), RFC 6793 section 6 (AS4_PATH and AS4_AGGREGATOR) and RFC 8092
  section 6 (LARGE_COMMUNITY).
- RFC 9234: the BGP Role capability (`roles.peer_role`, `role_from_open`, `check_roles`), Role
  Mismatch (`OpenSubcode.ROLE_MISMATCH`), the OTC attribute (`Attributes.otc`, judged by `walk`)
  and the ingress and egress procedures (`roles.otc_ingress`, `roles.otc_egress`).
- RFC 5701: attribute 25 decoded (`communities.decode_ipv6_extended`,
  `Attributes.ipv6_extended_communities`) and judged by `walk` under RFC 7606 section 7.15.
- Tests pinning that VPN, labeled, EVPN, flowspec and BGP-LS NLRI are kept raw.

### Changed

- Message type 5 is ROUTE-REFRESH, no longer Bad Message Type.
- An MP_REACH_NLRI that announces nothing no longer counts as reachable NLRI for RFC 7606 section 5.2.


## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for pathattr.
- `pathattr.apps` namespace reserved for composition that is not protocol behaviour.
