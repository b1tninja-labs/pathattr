# pathattr

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha.** BGP message framing (OPEN, UPDATE, KEEPALIVE, NOTIFICATION, extended messages and
extended OPEN parameters), IPv4 prefix lists, and the path attribute walker with RFC 7606 error
verdicts are implemented and tested. Attribute value decoding, AS_PATH merging, multiprotocol NLRI,
ADD-PATH, communities and roles still raise `NotImplementedError`. Read [ROADMAP.md](ROADMAP.md)
before depending on any of it.

Dependencies: Python standard library only (the `cryptography` package would be the only
permitted exception, for cryptographic primitives, and nothing here needs it).

pathattr -- the BGP wire codec a looking glass is built on

Everything a looking glass shows is a BGP UPDATE, and Python has no decoder it can own. ExaBGP is a daemon with a pipe protocol, not a library; pybgp3 has not moved in years; and the parsers people copy from blog posts get 4-octet AS numbers, ADD-PATH and the extended community sub-typing wrong. This is the shared dependency for the whole cluster: BMP carries UPDATEs inside its path mapping message, the RIB store indexes what it decodes, leak detection reasons over it, and the router text parsers produce the same objects. It is a codec and a stateless reader, deliberately not a router.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| exabgp | 5.0.15 | 2026-10-17 | a BGP daemon with an external process API, not an importable codec |
| pybgp3 | - | - | stale; absent from PyPI as a maintained project |
| bgpkit, bgpspy, ribkit, pathattr | - | - | all free on PyPI (2026-11-05); bgpkit and bgpspy collide with tool and service brands |

What this project intends to add:

- a codec with no parser bugs: attribute flag semantics, optional and transitive handling, and length discipline on every path
- 4-octet AS in AS_PATH, AS4_PATH, and the two-byte fallback, plus confederation handling
- multiprotocol NLRI with label and SID forms left opaque rather than guessed at
- extended and large communities decoded against the IANA registries, with unknown sub-types preserved
- hostile input refusal, since a looking glass parses what strangers announce

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 4271 | Draft Standard | 2006-01 | BGP-4: messages, the attribute flag octet, NLRI and the finite state machine vocabulary |
| RFC 4360 | Proposed Standard | 2006-02 | extended communities and their sub-type namespaces |
| RFC 8092 | Proposed Standard | 2017-02 | the large community attribute, four-octet safe by construction |
| RFC 7911 | Proposed Standard | 2016-07 | ADD-PATH: a path identifier alongside the prefix |
| RFC 9234 | Proposed Standard | 2022-05 | roles in OPEN and UPDATE for leak prevention and detection |
| RFC 6793 | Proposed Standard | 2012-12 | the four-octet AS number space, updating RFC 4271 |
| RFC 4760 | Draft Standard | 2007-01 | multiprotocol extensions: MP_REACH_NLRI and MP_UNREACH_NLRI |
| RFC 7606 | Proposed Standard | 2015-08 | revised error handling for UPDATE messages, updating RFC 4271, RFC 4360 and RFC 4760 |

### Errata watch

- RFC 4271 carries 9 verified errata and is updated by RFC 4724, RFC 6286, RFC 6608, RFC 6793, RFC 7606, RFC 7607, RFC 7705, RFC 8212, RFC 8654, RFC 9072, RFC 9687 and RFC 9774. Several of those change the wire: 6793 is 4-octet AS, 7606 is error handling, 9072 is extended message lengths.
- RFC 4360 carries 2 verified errata and is updated by RFC 7153 and RFC 7606.
- RFC 7911 and RFC 9234 report no errata as of 2026-10-29.

## Module layout

| Module | Responsibility |
|---|---|
| `message` | the four message types with header and length discipline (RFC 4271) |
| `attribute` | attribute flags, type registry and per-attribute codecs (RFC 4271) |
| `aspath` | AS_SEQUENCE, AS_SET and the 4-octet variants including confederations (RFC 6793) |
| `nlri` | prefix, multiprotocol reachability and unreachability (RFC 4271, RFC 4760 lineage) |
| `communities` | well-known, extended and large communities against the IANA registries (RFC 4360, RFC 8092) |
| `addpath` | path identifier encoding in NLRI and in capabilities (RFC 7911) |
| `roles` | the BGP_ROLE capability and path attribute (RFC 9234) |
| `limits` | bounds on attribute count, AS path length and message size |

## What it does not do

- a BGP speaker: no sessions, no timers, no announcement; ExaBGP, FRR and BIRD do that
- best path selection or any policy engine
- RIB storage and indexing, which is asnkit


## Install

```bash
git clone https://github.com/b1tninja/pathattr.git
cd pathattr
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy pathattr tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
