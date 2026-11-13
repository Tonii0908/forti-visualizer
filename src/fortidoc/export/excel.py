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
from fortidoc.export.common import (
    ADDRESS_COLUMNS,
    COVERAGE_COLUMNS,
    FINDING_COLUMNS,
    INTERFACE_COLUMNS,
    NAT_COLUMNS,
    OVERVIEW_COLUMNS,
    SERVICE_COLUMNS,
    address_rows,
    coverage_rows,
    finding_rows,
    interface_rows,
    nat_rows,
    nat_text,
    overview_rows,
    policy_notes,
    profile_lines,
    policy_service_objects,
    service_rows,
    service_values,
    side_objects,
    side_values,
    status_text,
    users_lines,
)
from fortidoc.model.schema import Finding, ResolvedConfig, ResolvedPolicy

WORKBOOK_NAME = "regelwerk.xlsx"
CELL_LIMIT = 32767
# Room kept free in a cell for the "… und N weitere" line.
_RESERVE = 200

SHEETS = [
    "Übersicht",
    "Policies",
    "Local-In",
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
    return [
        p.vdom,
        p.position,
        policy_id_cell(p.policy_id),
        p.name,
        status_text(p),
        p.action.upper(),
        "\n".join(p.src_zones),
        "\n".join(p.dst_zones),
        fit_lines(side_objects(p.source)),
        fit_lines(side_values(p.source), "Adressen"),
        fit_lines(side_objects(p.destination)),
        fit_lines(side_values(p.destination), "Adressen"),
        fit_lines(policy_service_objects(p)),
        fit_lines(service_values(p.service), "Dienste"),
        nat_text(p),
        "\n".join(users_lines(p)),
        p.schedule,
        p.logtraffic,
        "\n".join(profile_lines(p)),
        p.comments,
        fit_lines(policy_notes(p)),
    ]


def _policy_style(policy: ResolvedPolicy) -> str:
    if not policy.enabled:
        return "disabled"
    if policy.action in ("accept", "deny"):
        return policy.action
    return "wrap"


def _policies_sheet(ws, resolved: ResolvedConfig, local_in: bool = False) -> None:
    policies = [p for vdom in resolved.vdoms for p in (vdom.local_in if local_in else vdom.policies)]
    _write_table(
        ws, POLICY_COLUMNS, (_policy_row(p) for p in policies), lambda i: _policy_style(policies[i])
    )


def _overview_sheet(ws, resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> None:
    _write_table(ws, OVERVIEW_COLUMNS, overview_rows(resolved, findings, created_at))


# ---------------------------------------------------------------------------
# Workbook
# ---------------------------------------------------------------------------


def build_workbook(resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> Workbook:
    wb = Workbook()
    wb.remove(wb.active)
    sheets = {name: wb.create_sheet(title=name) for name in SHEETS}
    _overview_sheet(sheets["Übersicht"], resolved, findings, created_at)
    _policies_sheet(sheets["Policies"], resolved)
    _policies_sheet(sheets["Local-In"], resolved, local_in=True)
    _write_table(sheets["Adressen"], ADDRESS_COLUMNS, address_rows(resolved, fit_lines))
    _write_table(sheets["Dienste"], SERVICE_COLUMNS, service_rows(resolved, fit_lines))
    _write_table(sheets["NAT"], NAT_COLUMNS, nat_rows(resolved, fit_lines))
    _write_table(sheets["Interfaces"], INTERFACE_COLUMNS, interface_rows(resolved))
    _write_table(sheets["Auffälligkeiten"], FINDING_COLUMNS, finding_rows(findings))
    _write_table(sheets["Nicht verarbeitet"], COVERAGE_COLUMNS, coverage_rows(resolved))
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
