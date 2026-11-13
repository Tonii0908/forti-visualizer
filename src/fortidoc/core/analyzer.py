"""Findings ("Auffälligkeiten") on the resolved rule set.

Rule checks work on resolved values, never on object names. The search for
unused objects looks at references in the whole tree, including sections
fortidoc does not evaluate; only the result (object kind and name) is
reported, never a raw value from those sections.
"""

from __future__ import annotations

from collections.abc import Iterable

from fortidoc.model.schema import AddressSide, Finding, ResolvedConfig, ResolvedPolicy
from fortidoc.parser.conf_parser import ConfigNode, ConfigTree, EditNode, SetNode

CAT_DISABLED = "Deaktivierte Regel"
CAT_ALL = "ACCEPT mit all/ALL"
CAT_NO_SUBNET = "Adresse ohne subnet"
CAT_NO_LOGGING = "ACCEPT ohne Logging"
CAT_UNUSED = "Unbenutztes Objekt"

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
    for vdom in resolved.vdoms:
        for policy in vdom.policies:
            if not policy.implicit:
                findings.extend(_policy_findings(policy))
    findings.extend(_unused_objects(tree, resolved))
    return findings


# ---------------------------------------------------------------------------
# Rule checks
# ---------------------------------------------------------------------------


def _finding(policy: ResolvedPolicy, category: str, detail: str) -> Finding:
    return Finding(
        category=category,
        vdom=policy.vdom,
        object_kind="Regel",
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
    for label, side in (("Quelle", policy.source), ("Ziel", policy.destination)):
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
                if not users:
                    findings.append(
                        Finding(
                            category=CAT_UNUSED,
                            vdom=vdom.name,
                            object_kind=kind,
                            ref=edit.name,
                            name=edit.name,
                            detail="Kein Verweis im gesamten Backup gefunden.",
                        )
                    )
    return findings
