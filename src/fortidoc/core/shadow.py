"""Shadowed rules: a rule whose whole traffic an earlier rule already takes.

FortiOS applies the first matching rule. A later rule B never applies when an
earlier, enabled rule A of the same VDOM and table matches every packet that
B matches. This module finds such pairs on the resolved values.

The check is conservative: it only reports what it can prove.

- B is checked only if its sides consist of exact networks and ranges and its
  services are resolved. FQDN, Geo, dynamic, VIP, Internet Service, negation
  and values without subnet make B "not checkable", never "shadowed".
- A counts only with what is certain: its exact networks/ranges and resolved
  services. A rule with negation, Internet Service or an application/URL
  category (security policies) never shadows.
- Further conditions of A must not restrict it: users/groups (unless B has the
  same), a schedule other than "always" (unless B has the same).

Criteria fortidoc does not evaluate (keys outside the data model) are named
in a note when A has them. See ANNAHMEN.md, U1-U4.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass, field

from fortidoc.core.resolver import value_interval
from fortidoc.model.schema import AddressSide, ResolvedConfig, ResolvedPolicy, ServiceEntry, ServiceSide

ANY = "any"
ALWAYS = "always"  # ASSUMPTION(U2): the predefined schedule "always" never restricts
_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "SCTP": 132, "ICMP": 1, "ICMP6": 58}
_ALL_PORTS = (0, 65535)

Intervals = dict[int, list[tuple[int, int]]]


@dataclass
class Shadowing:
    shadowed: ResolvedPolicy
    by: ResolvedPolicy
    different_action: bool
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Normalised rule parts
# ---------------------------------------------------------------------------


def _merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _exact_intervals(side: AddressSide) -> tuple[Intervals, bool]:
    """Exact address intervals of a side and whether *every* value is exact."""
    raw: dict[int, list[tuple[int, int]]] = {}
    complete = bool(side.values) and not side.negate and not side.internet_services
    for value in side.values:
        iv = value_interval(value.value) if value.kind in ("network", "range") and not value.from_default else None
        if iv is None:
            complete = False
            continue
        raw.setdefault(iv[0], []).append((iv[1], iv[2]))
    return {version: _merge(items) for version, items in raw.items()}, complete


def _covers_addresses(a: Intervals, b: Intervals) -> bool:
    for version, items in b.items():
        merged = a.get(version)
        if not merged:
            return False
        starts = [lo for lo, _ in merged]
        for lo, hi in items:
            i = bisect_right(starts, lo) - 1
            if i < 0 or merged[i][1] < hi:
                return False
    return True


def _ports(text: str | None) -> tuple[int, int]:
    if not text:
        return _ALL_PORTS
    lo, _, hi = text.partition("-")
    return int(lo), int(hi or lo)


@dataclass(frozen=True)
class _Svc:
    kind: str  # "ports", "ip", "icmp"
    protocol: str | None = None
    number: int | None = None
    dst: tuple[int, int] = _ALL_PORTS
    src: tuple[int, int] = _ALL_PORTS
    icmp_type: int | None = None
    icmp_code: int | None = None


def _services(side: ServiceSide) -> tuple[list[_Svc], bool]:
    """Resolved services and whether every entry is resolved."""
    result: list[_Svc] = []
    complete = bool(side.entries) and not side.negate
    for e in side.entries:
        svc = _service(e)
        if svc is None:
            complete = False
        else:
            result.append(svc)
    return result, complete


def _service(e: ServiceEntry) -> _Svc | None:
    if e.kind == "ports":
        return _Svc("ports", protocol=e.protocol, dst=_ports(e.dst_ports), src=_ports(e.src_ports))
    if e.kind == "ip":
        return _Svc("ip", number=e.protocol_number)
    if e.kind == "icmp":
        return _Svc("icmp", protocol=e.protocol, icmp_type=e.icmp_type, icmp_code=e.icmp_code)
    return None


def _contains(outer: tuple[int, int], inner: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def _covers_service(a: list[_Svc], b: _Svc) -> bool:
    for s in a:
        if s.kind == "ip":
            # ASSUMPTION(R2): protocol 0 is every protocol, 6/17/132 every port of TCP/UDP/SCTP.
            if s.number == 0:
                return True
            if b.kind == "ip" and b.number == s.number:
                return True
            if b.kind in ("ports", "icmp") and _PROTOCOL_NUMBERS.get(b.protocol or "") == s.number:
                return True
        elif s.kind == "icmp" and b.kind == "icmp" and s.protocol == b.protocol:
            if s.icmp_type is None:
                return True
            if s.icmp_type == b.icmp_type and (s.icmp_code is None or s.icmp_code == b.icmp_code):
                return True
    if b.kind != "ports":
        return False
    # Destination ports may be covered by several entries of A together.
    ranges = [s.dst for s in a if s.kind == "ports" and s.protocol == b.protocol and _contains(s.src, b.src)]
    return any(_contains(r, b.dst) for r in _merge(ranges))


def _covers_services(a: list[_Svc], b: list[_Svc]) -> bool:
    return all(_covers_service(a, s) for s in b)


@dataclass
class _Rule:
    index: int
    policy: ResolvedPolicy
    src_zones: frozenset[str]
    dst_zones: frozenset[str]
    src: Intervals
    dst: Intervals
    services: list[_Svc]
    checkable: bool  # may be reported as shadowed
    can_shadow: bool  # may shadow later rules


def _rule(index: int, p: ResolvedPolicy) -> _Rule:
    src, src_complete = _exact_intervals(p.source)
    dst, dst_complete = _exact_intervals(p.destination)
    services, svc_complete = _services(p.service)
    plain = not (p.source.negate or p.destination.negate or p.service.negate)
    plain = plain and not (p.source.internet_services or p.destination.internet_services)
    plain = plain and not p.applications  # matches only part of its address/service traffic
    return _Rule(
        index=index,
        policy=p,
        src_zones=frozenset(p.src_zones),
        dst_zones=frozenset(p.dst_zones),
        src=src,
        dst=dst,
        services=services,
        checkable=p.enabled and src_complete and dst_complete and svc_complete and bool(p.src_zones and p.dst_zones),
        can_shadow=p.enabled and plain and bool(src) and bool(dst) and bool(services),
    )


def _conditions_cover(a: ResolvedPolicy, b: ResolvedPolicy) -> bool:
    # ASSUMPTION(U3): users/groups restrict a rule; equal sets match the same traffic.
    if (a.users or a.groups) and (set(a.users) != set(b.users) or set(a.groups) != set(b.groups)):
        return False
    if (a.schedule or ALWAYS) != ALWAYS and a.schedule != b.schedule:
        return False
    return True


def _covers(a: _Rule, b: _Rule) -> bool:
    return (
        _covers_addresses(a.src, b.src)
        and _covers_addresses(a.dst, b.dst)
        and _covers_services(a.services, b.services)
        and _conditions_cover(a.policy, b.policy)
    )


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def _candidates(index: dict[str, set[int]], zones: frozenset[str]) -> set[int]:
    """Rules whose zones contain all of `zones` (or 'any')."""
    any_rules = index.get(ANY, set())
    result: set[int] | None = None
    for zone in zones:
        found = index.get(zone, set()) | any_rules if zone != ANY else set(any_rules)
        result = found if result is None else result & found
        if not result:
            return set()
    return result or set()


def _table(policies: list[ResolvedPolicy]) -> list[Shadowing]:
    rules = [_rule(i, p) for i, p in enumerate(policies)]
    src_index: dict[str, set[int]] = {}
    dst_index: dict[str, set[int]] = {}
    for r in rules:
        if not r.can_shadow:
            continue
        for zone in r.src_zones:
            src_index.setdefault(zone, set()).add(r.index)
        for zone in r.dst_zones:
            dst_index.setdefault(zone, set()).add(r.index)
    found: list[Shadowing] = []
    for b in rules:
        if not b.checkable:
            continue
        candidates = _candidates(src_index, b.src_zones) & _candidates(dst_index, b.dst_zones)
        for i in sorted(c for c in candidates if c < b.index):
            a = rules[i]
            if _covers(a, b):
                notes = []
                if a.policy.unknown_keys:
                    notes.append(
                        f"Regel ID {a.policy.policy_id} hat nicht ausgewertete Schlüssel "
                        f"({', '.join(a.policy.unknown_keys)}), die ihren Verkehr einschränken könnten."
                    )
                found.append(Shadowing(b.policy, a.policy, a.policy.action != b.policy.action, notes))
                break
    return found


def find_shadowed(resolved: ResolvedConfig) -> list[Shadowing]:
    """Shadowed rules of every VDOM, per rule table, in file order."""
    result: list[Shadowing] = []
    for vdom in resolved.vdoms:
        tables: dict[str, list[ResolvedPolicy]] = {}
        for p in [*vdom.policies, *vdom.local_in]:
            if not p.implicit:
                tables.setdefault(p.section, []).append(p)
        for policies in tables.values():
            result.extend(_table(policies))
    return result
