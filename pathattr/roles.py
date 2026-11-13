"""The BGP Role capability and the Only to Customer attribute (RFC 9234).

Two halves, both pure functions over values already framed by ``message`` and ``attribute``:

* The capability (code 9, one octet, RFC 9234 section 4.1): :func:`peer_role` reads it,
  :func:`role_from_open` finds it in an OPEN (several identical ones are one, differing ones are a
  Role Mismatch, section 4.2), :func:`check_roles` applies Table 2 and the strict mode, and
  :func:`role_capability` builds one.
* The OTC attribute (type 35, four octets, section 5): :func:`decode_otc` reads it, and
  :func:`otc_ingress` and :func:`otc_egress` are the ingress and egress procedures as decisions
  over values. They change nothing in place and never see a route: the caller applies the answer.

The procedures apply to AFI 1 and 2 with SAFI 1 only (section 5), see :func:`otc_applies`. Whether
the operator runs RFC 9234 at all, and the confederation and private-AS cases of section 5, are
the caller's configuration; this module does not guess them, but :func:`otc_boundary_violation`
checks the value rule they impose on egress.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .errors import BgpError, ErrorCode, OpenSubcode
from .message import Capability, Open

__all__ = [
    "ROLE_CAPABILITY",
    "OtcEgress",
    "OtcIngress",
    "Role",
    "check_roles",
    "decode_otc",
    "encode_otc",
    "expected_remote_role",
    "otc_applies",
    "otc_boundary_violation",
    "otc_egress",
    "otc_ingress",
    "peer_role",
    "role_capability",
    "role_from_open",
]

#: RFC 9234 section 4.1 and section 7: the BGP Role capability code.
ROLE_CAPABILITY = 9


class Role(IntEnum):
    """BGP Role values, named for the local AS of the speaker that sends them (Table 1)."""

    PROVIDER = 0
    RS = 1
    RS_CLIENT = 2
    CUSTOMER = 3
    PEER = 4


_EXPECTED_REMOTE = {
    Role.PROVIDER: Role.CUSTOMER,
    Role.CUSTOMER: Role.PROVIDER,
    Role.RS: Role.RS_CLIENT,
    Role.RS_CLIENT: Role.RS,
    Role.PEER: Role.PEER,
}


def expected_remote_role(local: Role) -> Role:
    """The one remote Role that corresponds to ``local`` (RFC 9234 Table 2)."""
    return _EXPECTED_REMOTE[local]


def peer_role(capability: bytes) -> Role:
    """Read the value of a BGP Role capability (RFC 9234 section 4.1: one octet, Table 1).

    ``capability`` is the capability value, without the code and length octets. Raises
    ``ValueError`` when it is not exactly one octet or the value is unassigned (5 to 255): the
    RFC gives an unassigned value no meaning, so none is invented here.
    """
    if len(capability) != 1:
        raise ValueError("BGP Role capability length is not 1 (RFC 9234 section 4.1)")
    try:
        return Role(capability[0])
    except ValueError:
        raise ValueError(f"BGP Role value {capability[0]} is unassigned") from None


def role_capability(role: Role) -> Capability:
    """The capability TLV that advertises ``role`` (RFC 9234 section 4.1)."""
    return Capability(ROLE_CAPABILITY, bytes([int(role)]))


def _mismatch(text: str) -> BgpError:
    return BgpError(ErrorCode.OPEN_MESSAGE, OpenSubcode.ROLE_MISMATCH, message=text)


def role_from_open(opened: Open) -> Role | None:
    """The peer's Role from its OPEN, or None when no BGP Role capability was sent.

    Identical repeated capabilities count as one; repeated ones that differ raise
    :class:`BgpError` with Role Mismatch (code 2, subcode 11), RFC 9234 section 4.2. A capability
    whose length is not 1 is malformed and raises OPEN Message Error, Unspecific. An unassigned
    value raises ``ValueError`` (see :func:`peer_role`).
    """
    values: list[Role] = []
    for capability in opened.capabilities:
        if capability.code != ROLE_CAPABILITY:
            continue
        if len(capability.value) != 1:
            raise BgpError(
                ErrorCode.OPEN_MESSAGE,
                OpenSubcode.UNSPECIFIC,
                message="BGP Role capability length is not 1",
            )
        values.append(peer_role(capability.value))
    if not values:
        return None
    if len(set(values)) > 1:
        raise _mismatch("multiple BGP Role capabilities with different values")
    return values[0]


def check_roles(local: Role | None, remote: Role | None, *, strict: bool = False) -> None:
    """Apply RFC 9234 section 4.2 to the local configuration and the peer's capability.

    ``local`` is the configured Role, None when none is (nothing was advertised, so nothing is
    checked); ``remote`` is :func:`role_from_open`'s answer. When both exist they must be a pair of
    Table 2, else :class:`BgpError` with Role Mismatch. A local Role with no remote one is
    accepted, and rejected only in ``strict`` mode, the operator choice of section 4.2.
    """
    if local is None:
        return
    if remote is None:
        if strict:
            raise _mismatch("strict mode: the peer sent no BGP Role capability")
        return
    if remote != _EXPECTED_REMOTE[local]:
        raise _mismatch(f"local Role {local.name} does not correspond to remote {remote.name}")


def decode_otc(value: bytes) -> int:
    """The AS number in an OTC attribute value (RFC 9234 section 5: four octets).

    Raises ``ValueError`` for any other length, which section 5 makes treat-as-withdraw.
    """
    if len(value) != 4:
        raise ValueError("OTC length is not 4 (RFC 9234 section 5)")
    return int.from_bytes(value, "big")


def encode_otc(asn: int) -> bytes:
    """The four-octet OTC attribute value for ``asn`` (RFC 9234 section 5)."""
    return asn.to_bytes(4, "big")


def otc_applies(afi: int, safi: int) -> bool:
    """True for AFI 1 or 2 with SAFI 1, the only families the procedures cover (section 5)."""
    return afi in (1, 2) and safi == 1


@dataclass(frozen=True, slots=True)
class OtcIngress:
    """The outcome of the ingress procedure.

    ``ineligible`` is a route leak, to be considered ineligible (section 5, steps 1 and 2).
    ``add_otc`` is the value to attach when the route had none (step 3), else None.
    """

    ineligible: bool
    add_otc: int | None = None
    reason: str = ""


def otc_ingress(remote: Role, remote_asn: int, otc: int | None) -> OtcIngress:
    """RFC 9234 section 5 ingress procedure for a route received from the remote AS.

    ``remote`` is the Role the remote AS holds toward us (its capability value, or the one the
    local configuration implies); ``otc`` is the received attribute value or None. A route from
    a Customer or RS-Client carrying OTC is a leak; from a Peer carrying an OTC other than
    ``remote_asn`` is a leak; from a Provider, Peer or RS without OTC it gets ``remote_asn``.
    """
    if remote in (Role.CUSTOMER, Role.RS_CLIENT):
        if otc is not None:
            return OtcIngress(True, None, f"OTC received from a {remote.name}")
        return OtcIngress(False)
    if remote == Role.PEER and otc is not None and otc != remote_asn:
        return OtcIngress(True, None, f"OTC {otc} from a Peer is not its AS {remote_asn}")
    if otc is None:
        return OtcIngress(False, remote_asn)
    return OtcIngress(False)


@dataclass(frozen=True, slots=True)
class OtcEgress:
    """The outcome of the egress procedure: whether to send, and the OTC value to send."""

    advertise: bool
    otc: int | None = None
    reason: str = ""


def otc_egress(remote: Role, local_asn: int, otc: int | None) -> OtcEgress:
    """RFC 9234 section 5 egress procedure for a route about to go to the remote AS.

    ``remote`` is the Role of the neighbour the route is sent to, as it holds toward us. To a
    Customer, Peer or RS-Client an absent OTC is added with ``local_asn``; a route that already
    has OTC is never sent to a Provider, Peer or RS, and to a Customer or RS-Client it goes with
    OTC unchanged (section 5: once set it is preserved).
    """
    if remote in (Role.PROVIDER, Role.PEER, Role.RS) and otc is not None:
        return OtcEgress(False, otc, f"a route with OTC must not go to a {remote.name}")
    if remote in (Role.CUSTOMER, Role.PEER, Role.RS_CLIENT) and otc is None:
        return OtcEgress(True, local_asn)
    return OtcEgress(True, otc)


def otc_boundary_violation(
    otc: int | None,
    boundary_asn: int,
    internal_asns: frozenset[int] | set[int] = frozenset(),
    *,
    only_boundary: bool = False,
) -> str | None:
    """The section 5 rule for an OTC value leaving a confederation or an Internet-facing AS.

    ``boundary_asn`` is the AS Confederation Identifier, or the Internet-facing ASN that has
    private AS numbers behind it; ``internal_asns`` are the Member-AS numbers or the private ASNs
    the caller says sit behind it. Section 5 says an UPDATE leaving a confederation "MUST NOT
    contain an OTC Attribute with a value corresponding to any Member-AS Number other than the
    AS Confederation Identifier", so a value in ``internal_asns`` other than ``boundary_asn`` is
    a violation. For private AS numbers it says the value "MUST NOT" be "other than the
    Internet-facing ASN"; read literally that would also forbid a preserved OTC set by a distant
    AS, so it is applied only with ``only_boundary=True``. Returns the reason, or None when the
    value may leave. The caller supplies the AS sets; this module does not know which ASNs are
    private or which are members.
    """
    if otc is None or otc == boundary_asn:
        return None
    if only_boundary:
        return f"OTC {otc} is not the boundary AS {boundary_asn}"
    if otc in internal_asns:
        return f"OTC {otc} names an AS behind the boundary AS {boundary_asn}"
    return None
