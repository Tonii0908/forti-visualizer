"""Zone matrix and findings ("Auffälligkeiten") on the resolved rule set.

Rule checks work on resolved values, never on object names. The search for
unused objects looks at references in the whole tree, including sections
fortidoc does not evaluate; only the result (object kind and name) is
reported, never a raw value from those sections.
"""

from __future__ import annotations

from collections.abc import Iterable

from fortidoc.core.shadow import Shadowing, find_shadowed
from fortidoc.model.defaults import FACTORY_OBJECTS
from fortidoc.model.schema import (
    AddressSide,
    Finding,
    MatrixCell,
    ResolvedConfig,
    ResolvedPolicy,
    ZoneMatrix,
)
from fortidoc.parser.conf_parser import ConfigNode, ConfigTree, EditNode, SetNode

CAT_DISABLED = "Deaktivierte Regel"
CAT_ALL = "ACCEPT mit all/ALL"
CAT_NO_SUBNET = "Adresse ohne subnet"
CAT_NO_LOGGING = "ACCEPT ohne Logging"
CAT_UNUSED = "Unbenutztes Objekt"
CAT_UNUSED_FACTORY = "Unbenutztes Werksobjekt"
CAT_SHADOWED = "Überdeckte Regel"

# Every check, in the order the exports list them.
CATEGORIES = [
    CAT_DISABLED,
    CAT_ALL,
    CAT_NO_SUBNET,
    CAT_NO_LOGGING,
    CAT_SHADOWED,
    CAT_UNUSED,
    CAT_UNUSED_FACTORY,
]

# Object sections checked for references -> German label.
_OBJECT_SECTIONS: dict[tuple[str, ...], str] = {
    ("firewall", "address"): "Adresse",
    ("firewall", "addrgrp"): "Adressgruppe",
    ("firewall", "address6"): "IPv6-Adresse",
    ("firewall", "addrgrp6"): "IPv6-Adressgruppe",
    ("firewall", "vip"): "VIP",
    ("firewall", "vipgrp"): "VIP-Gruppe",
    ("firewall", "ippool"): "IP-Pool",
    ("firewall", "service", "custom"): "Dienst",
    ("firewall", "service", "group"): "Dienstgruppe",
}

# Free-text keys: a name that only appears there is not a reference.
_TEXT_KEYS = frozenset({"comment", "comments", "description"})


def analyze(tree: ConfigTree, resolved: ResolvedConfig) -> list[Finding]:
    findings: list[Finding] = []
    shadowed = {id(s.shadowed): s for s in find_shadowed(resolved)}
    for vdom in resolved.vdoms:
        for policy in [*vdom.policies, *vdom.local_in]:
            if not policy.implicit:
                findings.extend(_policy_findings(policy))
                hit = shadowed.get(id(policy))
                if hit is not None:
                    findings.append(_shadow_finding(hit))
    findings.extend(_unused_objects(tree, resolved))
    return findings


def _shadow_finding(hit: Shadowing) -> Finding:
    by = hit.by
    detail = (
        f"Greift nie: Die frühere Regel ID {by.policy_id} (Position {by.position}, {by.action.upper()}) "
        "erfasst den gesamten Verkehr dieser Regel."
    )
    if hit.different_action:
        detail += f" Sie hat eine andere Action ({by.action.upper()} statt {hit.shadowed.action.upper()})."
    else:
        detail += " Gleiche Action, die Regel ist überflüssig."
    detail += "".join(" " + note for note in hit.notes)
    return _finding(hit.shadowed, CAT_SHADOWED, detail)


def count_by_category(findings: Iterable[Finding]) -> dict[str, int]:
    """Number of findings per check, every check listed (also with 0)."""
    counts = dict.fromkeys(CATEGORIES, 0)
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Zone matrix
# ---------------------------------------------------------------------------

ANY_ZONE = "any"
NO_ZONE = "(nicht gesetzt)"


def zone_matrix(resolved: ResolvedConfig) -> list[ZoneMatrix]:
    """One matrix per VDOM: source zones x destination zones.

    A rule with several source and destination zones counts in every
    combination. Active rules are counted by action, disabled rules separately.
    "any" is a zone of its own (first row and column); the implicit deny is
    not part of the matrix.
    """
    matrices: list[ZoneMatrix] = []
    for vdom in resolved.vdoms:
        cells: dict[tuple[str, str], MatrixCell] = {}
        sources: list[str] = []
        destinations: list[str] = []
        for policy in vdom.policies:
            if policy.implicit:
                continue
            src_zones = policy.src_zones or [NO_ZONE]
            dst_zones = policy.dst_zones or [NO_ZONE]
            sources.extend(z for z in src_zones if z not in sources)
            destinations.extend(z for z in dst_zones if z not in destinations)
            for src in src_zones:
                for dst in dst_zones:
                    cell = cells.get((src, dst))
                    if cell is None:
                        cell = cells[(src, dst)] = MatrixCell(src=src, dst=dst)
                    cell.positions.append(policy.position)
                    if not policy.enabled:
                        cell.disabled += 1
                    elif policy.action == "accept":
                        cell.accept += 1
                    elif policy.action == "deny":
                        cell.deny += 1
                    else:
                        cell.other += 1
        known = [z.name for z in vdom.zones]
        rows = _axis(sources, known)
        cols = _axis(destinations, known)
        order_r = {z: i for i, z in enumerate(rows)}
        order_c = {z: i for i, z in enumerate(cols)}
        ordered = sorted(cells.values(), key=lambda c: (order_r[c.src], order_c[c.dst]))
        matrices.append(ZoneMatrix(vdom=vdom.name, rows=rows, cols=cols, cells=ordered))
    return matrices


def _axis(used: list[str], known: list[str]) -> list[str]:
    """'any' first, then the zones in the order of the configuration, then unknown names."""
    ordered = [ANY_ZONE]
    ordered += [z for z in known if z in used and z != ANY_ZONE]
    ordered += [z for z in used if z not in ordered]
    return ordered


# ---------------------------------------------------------------------------
# Rule checks
# ---------------------------------------------------------------------------


def rule_kind(policy: ResolvedPolicy) -> str:
    """'Regel' or 'Local-In-Regel': the two tables number their positions separately."""
    return "Local-In-Regel" if policy.section.startswith("firewall local-in") else "Regel"


def _finding(policy: ResolvedPolicy, category: str, detail: str) -> Finding:
    return Finding(
        category=category,
        vdom=policy.vdom,
        object_kind=rule_kind(policy),
        position=policy.position,
        ref=policy.policy_id,
        name=policy.name,
        detail=detail,
    )


def _label(value) -> str:
    origin = value.origin[0] if value.origin else None
    return f"{value.value} ({origin})" if origin else value.value


def _any_values(side: AddressSide, from_default: bool) -> list[str]:
    """Values of a side that stand for every address (0.0.0.0/0 or ::/0)."""
    if side.negate:
        return []  # "alles außer …" is never "all"
    return [
        _label(v)
        for v in side.values
        if v.kind == "network" and v.value.endswith("/0") and v.from_default == from_default
    ]


def _policy_findings(policy: ResolvedPolicy) -> Iterable[Finding]:
    if not policy.enabled:
        yield _finding(policy, CAT_DISABLED, "Die Regel ist deaktiviert (status disable).")
    if policy.action != "accept":
        return

    parts = []
    sides = [("Quelle", policy.source), ("Ziel", policy.destination)]
    if rule_kind(policy) == "Local-In-Regel":
        # The destination of a local-in rule is the FortiGate itself: 'all' there means
        # "every address of the FortiGate", not every host.
        sides = sides[:1]
    for label, side in sides:
        hits = _any_values(side, from_default=False)
        if hits:
            parts.append(f"{label}: {', '.join(hits)}")
    if not policy.service.negate:
        services = [
            e.value + (f" ({e.origin[0]})" if e.origin else "")
            for e in policy.service.entries
            if e.kind == "ip" and e.protocol_number == 0
        ]
        if services:
            parts.append(f"Dienst: {', '.join(services)}")
    if parts:
        yield _finding(policy, CAT_ALL, "; ".join(parts))

    no_subnet = []
    for label, side in (("Quelle", policy.source), ("Ziel", policy.destination)):
        hits = _any_values(side, from_default=True)
        if hits:
            no_subnet.append(f"{label}: {', '.join(hits)}")
    if no_subnet:
        yield _finding(
            policy,
            CAT_NO_SUBNET,
            "; ".join(no_subnet)
            + ". Das Objekt hat kein subnet im Backup; der FortiOS-Default 0.0.0.0/0 bzw. ::/0 "
            "ist angenommen, der tatsächliche Inhalt ist nur auf dem Gerät sichtbar.",
        )

    if policy.logtraffic == "disable":
        yield _finding(policy, CAT_NO_LOGGING, "Logging ist deaktiviert (logtraffic disable).")


# ---------------------------------------------------------------------------
# Unused objects
# ---------------------------------------------------------------------------

Owner = tuple[tuple[str, ...], str | None]


def _collect_references(sections: Iterable, refs: dict[str, set[Owner]]) -> None:
    """Map every value token to the top-level entries (section, edit) that use it."""
    for section in sections:
        if not isinstance(section, ConfigNode):
            continue
        path = tuple(section.path)
        for child in section.children:
            owner: Owner = (path, child.name if isinstance(child, EditNode) else None)
            _walk(child, owner, refs)


def _walk(node, owner: Owner, refs: dict[str, set[Owner]]) -> None:
    if isinstance(node, SetNode):
        if node.key in _TEXT_KEYS or node.redacted:
            return
        for value in node.values:
            refs.setdefault(value, set()).add(owner)
    elif isinstance(node, (ConfigNode, EditNode)):
        for child in node.children:
            _walk(child, owner, refs)


def _unused_objects(tree: ConfigTree, resolved: ResolvedConfig) -> list[Finding]:
    findings: list[Finding] = []
    shared: dict[str, set[Owner]] = {}
    _collect_references(tree.global_sections, shared)
    _collect_references(tree.outside_sections, shared)
    central_nat = {v.name: v.central_nat for v in resolved.vdoms}
    for vdom in tree.vdoms:
        refs: dict[str, set[Owner]] = {k: set(v) for k, v in shared.items()}
        _collect_references(vdom.sections, refs)
        for section in vdom.sections:
            if not isinstance(section, ConfigNode):
                continue
            path = tuple(section.path)
            kind = _OBJECT_SECTIONS.get(path)
            if kind is None:
                continue
            for edit in section.children:
                if not isinstance(edit, EditNode):
                    continue
                if kind == "VIP" and central_nat.get(vdom.name):
                    continue  # with central NAT a VIP works without any reference
                users = refs.get(edit.name, set()) - {(path, edit.name)}
                if users:
                    continue
                # ASSUMPTION(X7): factory-default names, see defaults.FACTORY_OBJECTS.
                factory = edit.name in FACTORY_OBJECTS.get(" ".join(path), frozenset())
                findings.append(
                    Finding(
                        category=CAT_UNUSED_FACTORY if factory else CAT_UNUSED,
                        vdom=vdom.name,
                        object_kind=kind,
                        ref=edit.name,
                        name=edit.name,
                        detail=(
                            "Kein Verweis im gesamten Backup gefunden. Der Name gehört zu den "
                            "werkseitig angelegten Objekten (siehe ANNAHMEN.md, X7)."
                            if factory
                            else "Kein Verweis im gesamten Backup gefunden."
                        ),
                    )
                )
    return findings
