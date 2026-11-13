"""Markdown export: regelwerk.md with a Mermaid zone diagram per VDOM.

The file reads the same resolved model and findings as the workbook and the
report and builds its rows with the shared helpers in ``common``.

Escaping: every text from the backup goes through ``md_cell`` (HTML special
characters as entities, Markdown punctuation with a backslash, line breaks
as ``<br>``) or, inside a Mermaid block, through ``mermaid_label`` (only
letters, digits and a few punctuation characters stay, everything else
becomes ``?``). Mermaid's own entity codes (``#60;``) are not used: tested
with Mermaid 11, they show up undecoded. Mermaid also reads ``*`` and ``_``
at word edges as emphasis, so those become ``?`` as well. The only HTML the file contains is
``<br>``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from fortidoc import __version__
from fortidoc.core.analyzer import zone_matrix
from fortidoc.export.common import (
    FINDING_COLUMNS,
    finding_rows,
    nat_text,
    overview_rows,
    policy_notes,
    policy_service_objects,
    service_values,
    side_objects,
    side_values,
    status_text,
    users_lines,
)
from fortidoc.export.diagram import KINDS
from fortidoc.model.schema import Finding, MatrixCell, ResolvedConfig, ResolvedPolicy, ZoneMatrix

MARKDOWN_NAME = "regelwerk.md"
MAX_VALUES = 10  # resolved values per cell; the workbook has the full lists
# Mermaid refuses diagrams above 500 edges or 50 000 characters (defaults of maxEdges/maxTextSize).
MAX_MERMAID_EDGES = 500
MAX_MERMAID_CHARS = 50_000

RULE_COLUMNS = [
    "Pos.", "ID", "Name", "Status", "Action", "Quellzone", "Zielzone", "Quelle", "Ziel", "Dienst",
    "NAT", "Benutzer und Gruppen", "Schedule", "Logging", "Kommentar", "Hinweise",
]  # fmt: skip

_MD_ESCAPES = str.maketrans({c: "\\" + c for c in "\\`*_[]|~"})
_MERMAID_SAFE = frozenset(" .,-:/+=@()")
_EDGE_UNDERSCORE = re.compile(r"(?<![^\W_])_|_(?![^\W_])")  # '_' not between two letters/digits
_EDGE_COLOURS = {
    "accept": "stroke:#1e7b34",
    "deny": "stroke:#b42318",
    "mixed": "stroke:#8a5a00",
    "other": "stroke:#8a5a00",
    "disabled": "stroke:#7b8794,stroke-dasharray:4 4",
}


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def md_cell(value: object) -> str:
    """Text for a Markdown table cell or paragraph, with no active Markdown or HTML."""
    if value is None:
        return ""
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.translate(_MD_ESCAPES)
    return "<br>".join(text.replace("\r\n", "\n").split("\n"))


def mermaid_label(text: str) -> str:
    """Label text Mermaid shows as written: letters, digits and a few punctuation marks, else '?'."""
    text = _EDGE_UNDERSCORE.sub("?", text)
    return "".join(c if c.isalnum() or c in _MERMAID_SAFE or c == "_" else "?" for c in text)


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(md_cell(h) for h in headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(md_cell(c) if not isinstance(c, _Raw) else c.text for c in row) + " |" for row in rows]
    return lines


class _Raw:
    """A cell that is already escaped (several escaped parts joined with <br>)."""

    def __init__(self, text: str) -> None:
        self.text = text


# ---------------------------------------------------------------------------
# Zone diagram
# ---------------------------------------------------------------------------


def _edge_kind(cell: MatrixCell) -> str:
    if cell.accept and cell.deny:
        return "mixed"
    for kind in ("accept", "deny", "other"):
        if getattr(cell, kind):
            return kind
    return "disabled"


def _edge_label(cell: MatrixCell) -> str:
    return ", ".join(f"{getattr(cell, kind)} {label}" for kind, label in KINDS if getattr(cell, kind))


def mermaid_zones(matrix: ZoneMatrix) -> str | None:
    """Mermaid flowchart of the zone matrix, or None if Mermaid would refuse it."""
    if len(matrix.cells) > MAX_MERMAID_EDGES:
        return None
    used = {c.src for c in matrix.cells} | {c.dst for c in matrix.cells}
    zones = [z for z in dict.fromkeys(matrix.rows + matrix.cols) if z in used]
    ids = {z: f"z{i}" for i, z in enumerate(zones)}
    lines = ["flowchart LR"]
    lines += [f'    {ids[z]}["{mermaid_label(z)}"]' for z in zones]
    lines += [f"    {ids[c.src]} -->|{mermaid_label(_edge_label(c))}| {ids[c.dst]}" for c in matrix.cells]
    lines += [f"    linkStyle {i} {_EDGE_COLOURS[_edge_kind(c)]}" for i, c in enumerate(matrix.cells)]
    text = "\n".join(lines) + "\n"
    return text if len(text) <= MAX_MERMAID_CHARS else None


def _matrix_table(matrix: ZoneMatrix) -> list[str]:
    cells = {(c.src, c.dst): c for c in matrix.cells}
    rows = []
    for src in matrix.rows:
        row: list[object] = [src]
        for dst in matrix.cols:
            cell = cells.get((src, dst))
            row.append(_edge_label(cell) if cell else "")
        rows.append(row)
    return _table(["Quelle / Ziel", *matrix.cols], rows)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def value_cell(objects: list[str], values: list[str]) -> str:
    """Escaped cell: object names, then at most MAX_VALUES resolved values."""
    parts = [md_cell(", ".join(objects))] if objects else []
    if values:
        shown = ", ".join(values[:MAX_VALUES])
        if len(values) > MAX_VALUES:
            shown += f" … und {len(values) - MAX_VALUES} weitere"
        parts.append("= " + md_cell(shown))
    return "<br>".join(parts)


def _rule_row(p: ResolvedPolicy) -> list[object]:
    return [
        p.position,
        p.policy_id,
        p.name,
        status_text(p),
        p.action.upper(),
        ", ".join(p.src_zones),
        ", ".join(p.dst_zones),
        _Raw(value_cell(side_objects(p.source), side_values(p.source))),
        _Raw(value_cell(side_objects(p.destination), side_values(p.destination))),
        _Raw(value_cell(policy_service_objects(p), service_values(p.service))),
        nat_text(p),
        "\n".join(users_lines(p)),
        p.schedule,
        p.logtraffic,
        p.comments,
        "\n".join(policy_notes(p)),
    ]


# ---------------------------------------------------------------------------
# Document
# ---------------------------------------------------------------------------


def render_markdown(resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> str:
    created = _utc(created_at)
    created_text = created.isoformat()
    device = resolved.device
    out = [f"# Regelwerk {md_cell(device.model or 'FortiGate')}", ""]
    out += [
        f"Erzeugt mit fortidoc {__version__} am {created_text} UTC aus "
        f"{md_cell(device.input_name or 'dem Backup')} (SHA-256 `{device.input_sha256 or ''}`).",
        "",
        "Passwörter, Schlüssel und Zertifikate sind entfernt. Das Dokument kann trotzdem "
        "vertrauliche Angaben zur Netzstruktur enthalten.",
        "",
        "## Übersicht",
        "",
    ]
    out += _table(["Angabe", "Wert"], overview_rows(resolved, findings, created))
    matrices = {m.vdom: m for m in zone_matrix(resolved)}
    for vdom in resolved.vdoms:
        out += ["", f"## VDOM {md_cell(vdom.name)}", "", "### Zonen", ""]
        matrix = matrices[vdom.name]
        if not matrix.cells:
            out.append("Keine Regeln.")
        else:
            diagram = mermaid_zones(matrix)
            if diagram is None:
                out.append(
                    f"Zu viele Zonen-Kombinationen ({len(matrix.cells)}) für ein Mermaid-Diagramm; "
                    "die Tabelle unten zeigt alle."
                )
            else:
                out += ["```mermaid", diagram.rstrip("\n"), "```"]
                if any(mermaid_label(z) != z for z in matrix.rows + matrix.cols):
                    out += ["", "Sonderzeichen in Zonennamen stehen im Diagramm als ?; die Tabelle zeigt die genauen Namen."]
            out += ["", "Zeilen: Quellzonen, Spalten: Zielzonen. Ohne implizites Deny, Local-In- und SSL-Inspection-Regeln.", ""]
            out += _matrix_table(matrix)
        out += ["", "### Regeln", ""]
        out += _table(RULE_COLUMNS, [_rule_row(p) for p in vdom.policies])
        out += ["", "### Local-In-Regeln", ""]
        if vdom.local_in:
            out += _table(RULE_COLUMNS, [_rule_row(p) for p in vdom.local_in])
        else:
            out.append("Keine Local-In-Regeln.")
        if vdom.inspection:
            out += [
                "",
                "### SSL-Inspection- und Authentifizierungsregeln",
                "",
                "NGFW-Modus richtlinienbasiert: Die Einträge in firewall policy steuern SSL-Inspection "
                "und Authentifizierung, keine Zugriffe. Das Regelwerk oben besteht aus den Security-Policies.",
                "",
            ]
            out += _table(RULE_COLUMNS, [_rule_row(p) for p in vdom.inspection])
    out += ["", "## Auffälligkeiten", ""]
    if findings:
        out += _table(FINDING_COLUMNS, finding_rows(findings))
    else:
        out.append("Keine Auffälligkeiten.")
    out += [
        "",
        "## Nicht verarbeitet",
        "",
        f"{len(resolved.coverage.unprocessed_sections)} Abschnitte und "
        f"{len(resolved.coverage.unknown_keys)} Schlüssel wertet fortidoc nicht aus; "
        "die Liste steht in regelwerk.xlsx und report.html.",
        "",
    ]
    return "\n".join(out)


def _utc(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.replace(microsecond=0)


def write_markdown(resolved: ResolvedConfig, findings: list[Finding], path: str | Path, created_at: datetime) -> Path:
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_markdown(resolved, findings, created_at))
    return path
