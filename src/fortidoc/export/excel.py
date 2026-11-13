"""Excel export: regelwerk.xlsx with eight sheets.

Every text from the configuration is written as a plain string cell, never
as a formula, after removing characters that XLSX does not allow. Cells are
limited to 32,767 characters; long lists are shortened with
"… und N weitere" and point to the sheet that holds the full list.

For the same input and the same creation time the file is byte-identical:
document timestamps and ZIP entry dates are set to the creation time.
"""

from __future__ import annotations

import io
import re
import zipfile
from copy import copy
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

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

WORKBOOK_NAME = "regelwerk.xlsx"
CELL_LIMIT = 32767
# Room kept free in a cell for the "… und N weitere" line.
_RESERVE = 200

SHEETS = [
    "Übersicht",
    "Policies",
    "Adressen",
    "Dienste",
    "NAT",
    "Interfaces",
    "Auffälligkeiten",
    "Nicht verarbeitet",
]

POLICY_COLUMNS = [
    "VDOM",
    "Position",
    "ID",
    "Name",
    "Status",
    "Action",
    "Quellzone",
    "Zielzone",
    "Quelle (Objekt)",
    "Quelle (aufgelöst)",
    "Ziel (Objekt)",
    "Ziel (aufgelöst)",
    "Dienst (Objekt)",
    "Dienst (aufgelöst)",
    "NAT",
    "Benutzer und Gruppen",
    "Schedule",
    "Logging",
    "Profile",
    "Kommentar",
    "Hinweise",
]
OVERVIEW_COLUMNS = ["Angabe", "Wert"]
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
FINDING_COLUMNS = ["VDOM", "Prüfung", "Objektart", "Position", "ID/Name", "Name", "Detail"]
COVERAGE_COLUMNS = ["Art", "Bereich", "Abschnitt", "Schlüssel", "Anzahl", "Zeile"]

_HEADER_FONT = Font(bold=True, color="FFFFFF")
_HEADER_FILL = PatternFill("solid", fgColor="44546A")
_ACCEPT_FILL = PatternFill("solid", fgColor="C6EFCE")
_DENY_FILL = PatternFill("solid", fgColor="FFC7CE")
_DISABLED_FILL = PatternFill("solid", fgColor="D9D9D9")
_DISABLED_FONT = Font(color="808080")
_WRAP = Alignment(wrap_text=True, vertical="top")

_WIDTHS = {
    "VDOM": 10, "Position": 9, "ID": 7, "Name": 22, "Status": 11, "Action": 9,
    "Quellzone": 16, "Zielzone": 16, "Quelle (Objekt)": 24, "Quelle (aufgelöst)": 32,
    "Ziel (Objekt)": 24, "Ziel (aufgelöst)": 32, "Dienst (Objekt)": 18, "Dienst (aufgelöst)": 26,
    "NAT": 22, "Benutzer und Gruppen": 20, "Schedule": 12, "Logging": 10, "Profile": 26,
    "Kommentar": 30, "Hinweise": 45, "Angabe": 34, "Wert": 70, "Detail": 70, "Aufgelöst": 40,
    "Mitglieder": 28, "Ausgenommen": 22, "Ursprung": 30, "Übersetzt auf": 30, "Details": 34,
    "Interfaces": 22, "Abschnitt": 32, "Schlüssel": 26, "Prüfung": 22,
}

_CATEGORY_LABELS = {
    "address": "Adresse",
    "addrgrp": "Adressgruppe",
    "address6": "IPv6-Adresse",
    "addrgrp6": "IPv6-Adressgruppe",
    "vip": "VIP",
    "vipgrp": "VIP-Gruppe",
}
_NAT_LABELS = {
    "none": "kein NAT",
    "interface": "Adresse des Ausgangs-Interfaces",
    "pool": "IP-Pool",
    "central": "Central NAT (siehe Reiter NAT)",
}

# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def clean_text(value: object) -> str:
    """Text safe for a cell: no illegal characters, at most CELL_LIMIT characters."""
    text = ILLEGAL_CHARACTERS_RE.sub("", str(value))
    if len(text) > CELL_LIMIT:
        suffix = "\n… (gekürzt)"
        text = text[: CELL_LIMIT - len(suffix)] + suffix
    return text


def fit_lines(lines: Sequence[str], sheet: str | None = None) -> str:
    """Join lines; if the cell would overflow, end with '… und N weitere'."""
    out: list[str] = []
    size = 0
    budget = CELL_LIMIT - _RESERVE
    for index, line in enumerate(lines):
        line = ILLEGAL_CHARACTERS_RE.sub("", line)
        if size + len(line) + 1 > budget:
            rest = len(lines) - index
            where = f" (vollständig im Reiter {sheet})" if sheet else ""
            out.append(f"… und {rest} weitere{where}")
            break
        out.append(line)
        size += len(line) + 1
    return "\n".join(out)


def _value_line(value: ResolvedValue) -> str:
    if value.kind == "unresolvable":
        return f"{value.value} [nicht auflösbar: {value.note}]"
    if value.note:
        return f"{value.value} [{value.note}]"
    return value.value


def _entry_line(entry: ServiceEntry) -> str:
    if entry.kind == "unresolvable":
        return f"{entry.value} [nicht auflösbar: {entry.note}]"
    return entry.value


def _side_objects(side: AddressSide) -> list[str]:
    lines = ["NICHT (alles außer):"] if side.negate else []
    lines += side.objects
    lines += [f"{name} (IPv6)" for name in side.objects6]
    lines += [f"Internet Service: {name}" for name in side.internet_services]
    return lines


def _side_values(side: AddressSide) -> list[str]:
    lines = ["alles außer:"] if side.negate else []
    return lines + [_value_line(v) for v in side.values]


def _service_objects(service: ServiceSide) -> list[str]:
    return (["NICHT (alles außer):"] if service.negate else []) + service.objects


def _service_values(service: ServiceSide) -> list[str]:
    return (["alles außer:"] if service.negate else []) + [_entry_line(e) for e in service.entries]


# ---------------------------------------------------------------------------
# Sheet writing
# ---------------------------------------------------------------------------


class _Styles:
    """Cell styles built once and copied, because setting styles per cell is slow."""

    _SPEC = {
        "wrap": {},
        "accept": {"fill": _ACCEPT_FILL},
        "deny": {"fill": _DENY_FILL},
        "disabled": {"fill": _DISABLED_FILL, "font": _DISABLED_FONT},
    }

    def __init__(self) -> None:
        self._cache: dict[str, object] = {}

    def apply(self, cell, key: str) -> None:
        cached = self._cache.get(key)
        if cached is not None:
            cell._style = copy(cached)
            return
        cell.alignment = _WRAP
        for attr, value in self._SPEC[key].items():
            setattr(cell, attr, value)
        self._cache[key] = copy(cell._style)


def _write_table(
    ws,
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    row_style: Callable[[int], str] | None = None,
) -> None:
    """Write header and rows. row_style(index) names the style of a data row."""
    for col, title in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col, value=title)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = _WRAP
        ws.column_dimensions[get_column_letter(col)].width = _WIDTHS.get(title, 16)
    styles = _Styles()
    row_number = 1
    for index, row in enumerate(rows):
        row_number += 1
        key = row_style(index) if row_style else "wrap"
        # Coloured rows are coloured across all columns, also in empty cells.
        fill_empty = key != "wrap"
        for col, value in enumerate(row, start=1):
            if value is None or value == "":
                if fill_empty:
                    styles.apply(ws.cell(row=row_number, column=col), key)
                continue
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cell = ws.cell(row=row_number, column=col, value=value)
            else:
                cell = ws.cell(row=row_number, column=col, value=clean_text(value))
                cell.data_type = "s"  # never a formula, even for text starting with '='
            styles.apply(cell, key)
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{row_number}"


def policy_id_cell(policy_id: str) -> int | str:
    """A purely numeric policy ID as a number, so the column sorts numerically."""
    if policy_id.isascii() and policy_id.isdigit() and (policy_id == "0" or not policy_id.startswith("0")):
        return int(policy_id)
    return policy_id


def _policy_row(p: ResolvedPolicy) -> list[object]:
    notes = list(p.notes)
    if p.section == "firewall policy6":
        notes.append("IPv6-Regel (firewall policy6).")
    elif p.ip_version != "4" and not p.implicit:
        notes.append("IPv6" if p.ip_version == "6" else "IPv4 und IPv6")
    if "action" in p.defaults_applied and not p.implicit:
        notes.append(f"action nicht gesetzt, FortiOS-Default {p.action}.")
    if p.unknown_keys:
        notes.append("Nicht ausgewertete Schlüssel: " + ", ".join(p.unknown_keys))
    nat = _NAT_LABELS[p.nat.mode] if not p.implicit else ""
    if p.nat.pools:
        nat += ": " + ", ".join(pool.value for pool in p.nat.pools)
    users = []
    if p.users:
        users.append("Benutzer: " + ", ".join(p.users))
    if p.groups:
        users.append("Gruppen: " + ", ".join(p.groups))
    return [
        p.vdom,
        p.position,
        policy_id_cell(p.policy_id),
        p.name,
        "aktiv" if p.enabled else "deaktiviert",
        p.action.upper(),
        "\n".join(p.src_zones),
        "\n".join(p.dst_zones),
        fit_lines(_side_objects(p.source)),
        fit_lines(_side_values(p.source), "Adressen"),
        fit_lines(_side_objects(p.destination)),
        fit_lines(_side_values(p.destination), "Adressen"),
        fit_lines(_service_objects(p.service)),
        fit_lines(_service_values(p.service), "Dienste"),
        nat,
        "\n".join(users),
        p.schedule,
        p.logtraffic,
        "\n".join(f"{k}: {v}" for k, v in p.profiles.items()),
        p.comments,
        fit_lines(notes),
    ]


def _policy_style(policy: ResolvedPolicy) -> str:
    if not policy.enabled:
        return "disabled"
    if policy.action in ("accept", "deny"):
        return policy.action
    return "wrap"


def _policies_sheet(ws, resolved: ResolvedConfig) -> None:
    policies = [p for vdom in resolved.vdoms for p in vdom.policies]
    _write_table(
        ws, POLICY_COLUMNS, (_policy_row(p) for p in policies), lambda i: _policy_style(policies[i])
    )


def _overview_sheet(ws, resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> None:
    d = resolved.device
    rows: list[tuple[str, object]] = [
        ("Gerät", d.model or "unbekannt"),
        ("FortiOS-Version", d.version or "unbekannt"),
        ("Build", d.build),
        ("Firmware-Typ", d.firmware_type),
        ("VDOM-Modus", "Multi-VDOM" if d.vdom_mode == "multi-vdom" else "ohne VDOMs (als VDOM root geführt)"),
        ("VDOMs", ", ".join(v.name for v in resolved.vdoms)),
        ("Eingabedatei", d.input_name),
        ("SHA-256 der Eingabedatei", d.input_sha256),
        ("Dateigröße (Bytes)", d.input_size_bytes),
        ("Erstellzeit (UTC)", created_at.isoformat()),
        ("Tool-Version", f"fortidoc {__version__}"),
        ("Interfaces und SD-WAN-Zonen", len(resolved.interfaces)),
    ]
    for vdom in resolved.vdoms:
        rules = [p for p in vdom.policies if not p.implicit]
        rows += [
            (f"VDOM {vdom.name}: Regeln (ohne implizites Deny)", len(rules)),
            (f"VDOM {vdom.name}: davon aktiv", sum(1 for p in rules if p.enabled)),
            (f"VDOM {vdom.name}: davon deaktiviert", sum(1 for p in rules if not p.enabled)),
            (f"VDOM {vdom.name}: Adressobjekte", len(vdom.addresses)),
            (f"VDOM {vdom.name}: Dienstobjekte", len(vdom.services)),
            (f"VDOM {vdom.name}: VIPs", len(vdom.vips)),
            (f"VDOM {vdom.name}: IP-Pools", len(vdom.ippools)),
            (f"VDOM {vdom.name}: Central-SNAT-Regeln", len(vdom.snat)),
            (f"VDOM {vdom.name}: Central NAT", "ja" if vdom.central_nat else "nein"),
        ]
    rows.append(("Auffälligkeiten gesamt", len(findings)))
    rows += [(f"Auffälligkeiten: {category}", count) for category, count in count_by_category(findings).items()]
    rows += [
        ("Nicht verarbeitete Abschnitte", len(resolved.coverage.unprocessed_sections)),
        ("Nicht ausgewertete Schlüssel", len(resolved.coverage.unknown_keys)),
    ]
    for vdom in resolved.vdoms:
        rows += [(f"Hinweis VDOM {vdom.name}", note) for note in vdom.notes]
    rows += [("Hinweis beim Einlesen", note) for note in resolved.notes]
    _write_table(ws, OVERVIEW_COLUMNS, rows)


def _addresses_sheet(ws, resolved: ResolvedConfig) -> None:
    rows = []
    for vdom in resolved.vdoms:
        for a in vdom.addresses:
            notes = []
            if a.unknown_keys:
                notes.append("Nicht ausgewertete Schlüssel: " + ", ".join(a.unknown_keys))
            rows.append(
                [
                    a.vdom,
                    _CATEGORY_LABELS[a.category],
                    a.name,
                    a.type,
                    fit_lines(a.members),
                    fit_lines(a.exclude_members),
                    fit_lines([_value_line(v) for v in a.values]),
                    a.comment,
                    "\n".join(notes),
                ]
            )
    _write_table(ws, ADDRESS_COLUMNS, rows)


def _services_sheet(ws, resolved: ResolvedConfig) -> None:
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
                    fit_lines(s.members),
                    fit_lines([_entry_line(e) for e in s.entries]),
                    s.comment,
                    "\n".join(notes),
                ]
            )
    _write_table(ws, SERVICE_COLUMNS, rows)


def _nat_sheet(ws, resolved: ResolvedConfig) -> None:
    rows = []
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
            )
        for pool in vdom.ippools:
            origin = (
                f"{pool.source_start_ip}-{pool.source_end_ip}" if pool.source_start_ip or pool.source_end_ip else None
            )
            rows.append(
                [vdom.name, "IP-Pool", None, pool.name, None, None, origin,
                 f"{pool.start_ip or '?'}-{pool.end_ip or '?'}", f"Typ {pool.type}", pool.comment,
                 "\n".join(pool.notes)]
            )
        for rule in vdom.snat:
            src = ", ".join(r.name for r in rule.src_interfaces) or "-"
            dst = ", ".join(r.name for r in rule.dst_interfaces) or "-"
            if not rule.nat:
                target = "kein NAT"
            elif rule.pools:
                target = "\n".join(pool.value for pool in rule.pools)
            else:
                target = "Adresse des Ausgangs-Interfaces"
            details = ["Ziel: " + (", ".join(_value_line(v) for v in rule.dst_addr.values) or "-")]
            if rule.protocol:
                details.append(f"Protokoll {rule.protocol}")
            if rule.orig_port:
                details.append(f"Ursprungsport {rule.orig_port}")
            rows.append(
                [vdom.name, "Central-SNAT", rule.position, rule.rule_id,
                 "aktiv" if rule.enabled else "deaktiviert", f"{src} → {dst}",
                 fit_lines(rule.orig_addr.objects + [_value_line(v) for v in rule.orig_addr.values], "Adressen"),
                 target, "\n".join(details), rule.comments, "\n".join(rule.notes)]
            )
    _write_table(ws, NAT_COLUMNS, rows)


def _interfaces_sheet(ws, resolved: ResolvedConfig) -> None:
    rows = [
        [i.name, i.type_label, i.ip, i.vlan_id, i.parent, "\n".join(i.members),
         i.zone if i.zone != i.name else None, i.vdom,
         i.alias, i.description, "\n".join(i.notes)]
        for i in resolved.interfaces
    ]
    _write_table(ws, INTERFACE_COLUMNS, rows)


def _findings_sheet(ws, findings: list[Finding]) -> None:
    rows = [[f.vdom, f.category, f.object_kind, f.position, f.ref, f.name, f.detail] for f in findings]
    _write_table(ws, FINDING_COLUMNS, rows)


def _coverage_sheet(ws, resolved: ResolvedConfig) -> None:
    coverage = resolved.coverage
    rows: list[list[object]] = [
        ["Abschnitt", s.scope, s.path, None, s.entries, s.line] for s in coverage.unprocessed_sections
    ]
    rows += [
        ["Schlüssel", ", ".join(k.scopes), k.section, k.key, k.count, None] for k in coverage.unknown_keys
    ]
    _write_table(ws, COVERAGE_COLUMNS, rows)


# ---------------------------------------------------------------------------
# Workbook
# ---------------------------------------------------------------------------


def build_workbook(resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> Workbook:
    wb = Workbook()
    wb.remove(wb.active)
    sheets = {name: wb.create_sheet(title=name) for name in SHEETS}
    _overview_sheet(sheets["Übersicht"], resolved, findings, created_at)
    _policies_sheet(sheets["Policies"], resolved)
    _addresses_sheet(sheets["Adressen"], resolved)
    _services_sheet(sheets["Dienste"], resolved)
    _nat_sheet(sheets["NAT"], resolved)
    _interfaces_sheet(sheets["Interfaces"], resolved)
    _findings_sheet(sheets["Auffälligkeiten"], findings)
    _coverage_sheet(sheets["Nicht verarbeitet"], resolved)
    wb.properties.creator = f"fortidoc {__version__}"
    wb.properties.title = "Regelwerk"
    return wb


def _utc_naive(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.replace(microsecond=0)


def _normalize_zip(data: bytes, moment: datetime) -> bytes:
    """Fix ZIP entry dates and document timestamps so equal input gives equal bytes."""
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    date_time = (max(moment.year, 1980), moment.month, moment.day, moment.hour, moment.minute, moment.second)
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            content = src.read(info.filename)
            if info.filename == "docProps/core.xml":
                text = content.decode("utf-8")
                text = re.sub(
                    r"(<dcterms:(?:created|modified)[^>]*>)[^<]*(</dcterms:)", rf"\g<1>{stamp}\g<2>", text
                )
                content = text.encode("utf-8")
            entry = zipfile.ZipInfo(info.filename, date_time=date_time)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o600 << 16
            dst.writestr(entry, content)
    return out.getvalue()


def write_workbook(
    resolved: ResolvedConfig, findings: list[Finding], path: str | Path, created_at: datetime
) -> Path:
    """Write regelwerk.xlsx (or the given file name) and return its path."""
    moment = _utc_naive(created_at)
    wb = build_workbook(resolved, findings, moment)
    wb.properties.created = moment
    buffer = io.BytesIO()
    wb.save(buffer)
    path = Path(path)
    path.write_bytes(_normalize_zip(buffer.getvalue(), moment))
    return path
