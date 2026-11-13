"""Texts and tables shared by regelwerk.xlsx and report.html.

Both exports read the same resolved model and the same findings, and build
their object tables with the functions here, so a row in the report is the
same row as in the workbook. ``join`` decides how a list becomes one cell:
Excel shortens long lists to fit a cell, the report shows them in full.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from fortidoc import __version__
from fortidoc.core.analyzer import count_by_category
from fortidoc.model.schema import (
    AddressSide,
    Finding,
    ResolvedConfig,
    ResolvedPolicy,
    ResolvedValue,
    ServiceEntry,
    ServiceSide,
)

# join(lines, sheet): one cell from lines; sheet names where the full list is.
Join = Callable[[Sequence[str], str | None], str]


def join_all(lines: Sequence[str], sheet: str | None = None) -> str:
    return "\n".join(lines)


Table = tuple[list[str], list[list[object]]]

ADDRESS_COLUMNS = ["VDOM", "Kategorie", "Name", "Typ", "Mitglieder", "Ausgenommen", "Aufgelöst", "Kommentar", "Hinweise"]
SERVICE_COLUMNS = ["VDOM", "Kategorie", "Name", "Protokoll", "Mitglieder", "Aufgelöst", "Kommentar", "Hinweise"]
NAT_COLUMNS = [
    "VDOM",
    "Art",
    "Position",
    "Name/ID",
    "Status",
    "Interfaces",
    "Ursprung",
    "Übersetzt auf",
    "Details",
    "Kommentar",
    "Hinweise",
]
INTERFACE_COLUMNS = [
    "Interface",
    "Typ",
    "IP",
    "VLAN-ID",
    "Parent",
    "Mitglieder",
    "Zone",
    "VDOM",
    "Alias",
    "Beschreibung",
    "Hinweise",
]
ZONE_COLUMNS = ["VDOM", "Zone", "Art", "Interfaces", "Intrazone"]
FINDING_COLUMNS = ["VDOM", "Prüfung", "Objektart", "Position", "ID/Name", "Name", "Detail"]
COVERAGE_COLUMNS = ["Art", "Bereich", "Abschnitt", "Schlüssel", "Anzahl", "Zeile"]
OVERVIEW_COLUMNS = ["Angabe", "Wert"]

CATEGORY_LABELS = {
    "address": "Adresse",
    "addrgrp": "Adressgruppe",
    "address6": "IPv6-Adresse",
    "addrgrp6": "IPv6-Adressgruppe",
    "vip": "VIP",
    "vipgrp": "VIP-Gruppe",
}
NAT_LABELS = {
    "none": "kein NAT",
    "interface": "Adresse des Ausgangs-Interfaces",
    "pool": "IP-Pool",
    "central": "Central NAT (siehe NAT)",
}
ZONE_KIND_LABELS = {"zone": "Zone", "sdwan-zone": "SD-WAN-Zone", "interface": "Interface ohne Zone"}

# ---------------------------------------------------------------------------
# Single values
# ---------------------------------------------------------------------------


def value_line(value: ResolvedValue) -> str:
    if value.kind == "unresolvable":
        return f"{value.value} [nicht auflösbar: {value.note}]"
    if value.note:
        return f"{value.value} [{value.note}]"
    return value.value


def entry_line(entry: ServiceEntry) -> str:
    if entry.kind == "unresolvable":
        return f"{entry.value} [nicht auflösbar: {entry.note}]"
    return entry.value


def side_objects(side: AddressSide) -> list[str]:
    lines = ["NICHT (alles außer):"] if side.negate else []
    lines += side.objects
    lines += [f"{name} (IPv6)" for name in side.objects6]
    lines += [f"Internet Service: {name}" for name in side.internet_services]
    return lines


def side_values(side: AddressSide) -> list[str]:
    lines = ["alles außer:"] if side.negate else []
    return lines + [value_line(v) for v in side.values]


def service_objects(service: ServiceSide) -> list[str]:
    return (["NICHT (alles außer):"] if service.negate else []) + service.objects


def service_values(service: ServiceSide) -> list[str]:
    return (["alles außer:"] if service.negate else []) + [entry_line(e) for e in service.entries]


# ---------------------------------------------------------------------------
# Policy texts
# ---------------------------------------------------------------------------


def policy_notes(p: ResolvedPolicy) -> list[str]:
    notes = list(p.notes)
    if p.section == "firewall policy6":
        notes.append("IPv6-Regel (firewall policy6).")
    elif p.ip_version != "4" and not p.implicit:
        notes.append("IPv6" if p.ip_version == "6" else "IPv4 und IPv6")
    if "action" in p.defaults_applied and not p.implicit:
        notes.append(f"action nicht gesetzt, FortiOS-Default {p.action}.")
    if p.unknown_keys:
        notes.append("Nicht ausgewertete Schlüssel: " + ", ".join(p.unknown_keys))
    return notes


def nat_text(p: ResolvedPolicy) -> str:
    if p.implicit:
        return ""
    text = NAT_LABELS[p.nat.mode]
    if p.nat.pools:
        text += ": " + ", ".join(pool.value for pool in p.nat.pools)
    return text


def users_lines(p: ResolvedPolicy) -> list[str]:
    lines = []
    if p.users:
        lines.append("Benutzer: " + ", ".join(p.users))
    if p.groups:
        lines.append("Gruppen: " + ", ".join(p.groups))
    return lines


def profile_lines(p: ResolvedPolicy) -> list[str]:
    return [f"{k}: {v}" for k, v in p.profiles.items()]


def status_text(p: ResolvedPolicy) -> str:
    return "aktiv" if p.enabled else "deaktiviert"


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


def overview_rows(resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> list[list[object]]:
    d = resolved.device
    rows: list[list[object]] = [
        ["Gerät", d.model or "unbekannt"],
        ["FortiOS-Version", d.version or "unbekannt"],
        ["Build", d.build],
        ["Firmware-Typ", d.firmware_type],
        ["VDOM-Modus", "Multi-VDOM" if d.vdom_mode == "multi-vdom" else "ohne VDOMs (als VDOM root geführt)"],
        ["VDOMs", ", ".join(v.name for v in resolved.vdoms)],
        ["Eingabedatei", d.input_name],
        ["SHA-256 der Eingabedatei", d.input_sha256],
        ["Dateigröße (Bytes)", d.input_size_bytes],
        ["Erstellzeit (UTC)", created_at.isoformat()],
        ["Tool-Version", f"fortidoc {__version__}"],
        ["Interfaces und SD-WAN-Zonen", len(resolved.interfaces)],
    ]
    for vdom in resolved.vdoms:
        rules = [p for p in vdom.policies if not p.implicit]
        rows += [
            [f"VDOM {vdom.name}: Regeln (ohne implizites Deny)", len(rules)],
            [f"VDOM {vdom.name}: davon aktiv", sum(1 for p in rules if p.enabled)],
            [f"VDOM {vdom.name}: davon deaktiviert", sum(1 for p in rules if not p.enabled)],
            [f"VDOM {vdom.name}: Adressobjekte", len(vdom.addresses)],
            [f"VDOM {vdom.name}: Dienstobjekte", len(vdom.services)],
            [f"VDOM {vdom.name}: VIPs", len(vdom.vips)],
            [f"VDOM {vdom.name}: IP-Pools", len(vdom.ippools)],
            [f"VDOM {vdom.name}: Central-SNAT-Regeln", len(vdom.snat)],
            [f"VDOM {vdom.name}: Central NAT", "ja" if vdom.central_nat else "nein"],
        ]
    rows.append(["Auffälligkeiten gesamt", len(findings)])
    rows += [[f"Auffälligkeiten: {category}", count] for category, count in count_by_category(findings).items()]
    rows += [
        ["Nicht verarbeitete Abschnitte", len(resolved.coverage.unprocessed_sections)],
        ["Nicht ausgewertete Schlüssel", len(resolved.coverage.unknown_keys)],
    ]
    for vdom in resolved.vdoms:
        rows += [[f"Hinweis VDOM {vdom.name}", note] for note in vdom.notes]
    rows += [["Hinweis beim Einlesen", note] for note in resolved.notes]
    return rows


def address_rows(resolved: ResolvedConfig, join: Join = join_all) -> list[list[object]]:
    rows = []
    for vdom in resolved.vdoms:
        for a in vdom.addresses:
            notes = []
            if a.unknown_keys:
                notes.append("Nicht ausgewertete Schlüssel: " + ", ".join(a.unknown_keys))
            rows.append(
                [
                    a.vdom,
                    CATEGORY_LABELS[a.category],
                    a.name,
                    a.type,
                    join(a.members, None),
                    join(a.exclude_members, None),
                    join([value_line(v) for v in a.values], None),
                    a.comment,
                    "\n".join(notes),
                ]
            )
    return rows


def service_rows(resolved: ResolvedConfig, join: Join = join_all) -> list[list[object]]:
    rows = []
    for vdom in resolved.vdoms:
        for s in vdom.services:
            notes = []
            if s.unknown_keys:
                notes.append("Nicht ausgewertete Schlüssel: " + ", ".join(s.unknown_keys))
            rows.append(
                [
                    s.vdom,
                    "Dienst" if s.category == "custom" else "Dienstgruppe",
                    s.name,
                    s.protocol,
                    join(s.members, None),
                    join([entry_line(e) for e in s.entries], None),
                    s.comment,
                    "\n".join(notes),
                ]
            )
    return rows


def nat_rows(resolved: ResolvedConfig, join: Join = join_all) -> list[list[object]]:
    rows: list[list[object]] = []
    for vdom in resolved.vdoms:
        for vip in vdom.vips:
            origin = vip.ext_ip or "?"
            if vip.portforward:
                origin += f":{vip.ext_port or '?'}/{(vip.protocol or '?').upper()}"
            target = ", ".join(
                f"{m}:{vip.mapped_port}" if vip.portforward and vip.mapped_port else m for m in vip.mapped_ips
            )
            details = [f"Typ {vip.type}"]
            if vip.portforward:
                details.append("Portweiterleitung")
            if vdom.central_nat:
                details.append("Central NAT: wirkt ohne Verweis in der Policy")
            rows.append(
                [vdom.name, "VIP (DNAT)", None, vip.name, None, vip.ext_intf, origin, target,
                 "\n".join(details), vip.comment, "\n".join(vip.notes)]
            )  # fmt: skip
        for pool in vdom.ippools:
            origin = (
                f"{pool.source_start_ip}-{pool.source_end_ip}" if pool.source_start_ip or pool.source_end_ip else None
            )
            rows.append(
                [vdom.name, "IP-Pool", None, pool.name, None, None, origin,
                 f"{pool.start_ip or '?'}-{pool.end_ip or '?'}", f"Typ {pool.type}", pool.comment,
                 "\n".join(pool.notes)]
            )  # fmt: skip
        for rule in vdom.snat:
            src = ", ".join(r.name for r in rule.src_interfaces) or "-"
            dst = ", ".join(r.name for r in rule.dst_interfaces) or "-"
            if not rule.nat:
                target = "kein NAT"
            elif rule.pools:
                target = "\n".join(pool.value for pool in rule.pools)
            else:
                target = "Adresse des Ausgangs-Interfaces"
            details = ["Ziel: " + (", ".join(value_line(v) for v in rule.dst_addr.values) or "-")]
            if rule.protocol:
                details.append(f"Protokoll {rule.protocol}")
            if rule.orig_port:
                details.append(f"Ursprungsport {rule.orig_port}")
            rows.append(
                [vdom.name, "Central-SNAT", rule.position, rule.rule_id,
                 "aktiv" if rule.enabled else "deaktiviert", f"{src} → {dst}",
                 join(rule.orig_addr.objects + [value_line(v) for v in rule.orig_addr.values], "Adressen"),
                 target, "\n".join(details), rule.comments, "\n".join(rule.notes)]
            )  # fmt: skip
    return rows


def interface_rows(resolved: ResolvedConfig) -> list[list[object]]:
    return [
        [i.name, i.type_label, i.ip, i.vlan_id, i.parent, "\n".join(i.members),
         i.zone if i.zone != i.name else None, i.vdom,
         i.alias, i.description, "\n".join(i.notes)]
        for i in resolved.interfaces
    ]  # fmt: skip


def zone_rows(resolved: ResolvedConfig) -> list[list[object]]:
    return [
        [vdom.name, z.name, ZONE_KIND_LABELS[z.kind], "\n".join(z.interfaces), z.intrazone]
        for vdom in resolved.vdoms
        for z in vdom.zones
    ]


def finding_rows(findings: list[Finding]) -> list[list[object]]:
    return [[f.vdom, f.category, f.object_kind, f.position, f.ref, f.name, f.detail] for f in findings]


def coverage_rows(resolved: ResolvedConfig) -> list[list[object]]:
    coverage = resolved.coverage
    rows: list[list[object]] = [
        ["Abschnitt", s.scope, s.path, None, s.entries, s.line] for s in coverage.unprocessed_sections
    ]
    rows += [["Schlüssel", ", ".join(k.scopes), k.section, k.key, k.count, None] for k in coverage.unknown_keys]
    return rows
