"""Command line interface. All user-facing text is German."""

from __future__ import annotations

import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer

from fortidoc import __version__
from fortidoc.core.analyzer import analyze
from fortidoc.core.resolver import resolve_config
from fortidoc.errors import FortidocError
from fortidoc.export.excel import WORKBOOK_NAME, write_workbook
from fortidoc.export.html import REPORT_NAME, write_report
from fortidoc.export.markdown import MARKDOWN_NAME, write_markdown
from fortidoc.model.schema import AddressSide, ResolvedConfig, ResolvedPolicy
from fortidoc.parser.conf_parser import ConfigNode, ConfigTree, EditNode, iter_nodes, parse_file

CONFIDENTIAL_NOTICE = (
    "Geheimnisse wie Passwörter, Schlüssel und Zertifikate sind entfernt. Der Baum enthält "
    "trotzdem alle übrigen Werte des Backups und kann vertrauliche Daten enthalten "
    "(z. B. Webhook-URLs, Benutzernamen, Telefonnummern). Nicht ungeprüft weitergeben."
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="fortidoc: Dokumentation aus FortiGate-Konfigurations-Backups erzeugen.",
)


def _utf8_streams() -> None:
    """Make stdout/stderr UTF-8 so umlauts and config text never crash on Windows."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            try:
                stream.reconfigure(encoding="utf-8")
            except (ValueError, io.UnsupportedOperation):
                pass


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"fortidoc {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    input_file: Annotated[
        Optional[Path], typer.Option("--input", "-i", help="FortiGate-Backup (.conf, unverschlüsselt).")
    ] = None,
    output_dir: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Zielordner für regelwerk.xlsx, report.html und regelwerk.md.")
    ] = None,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Version anzeigen."),
    ] = False,
) -> None:
    _utf8_streams()
    if ctx.invoked_subcommand is not None:
        return
    if input_file is None and output_dir is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()
    if input_file is None or output_dir is None:
        typer.echo("Fehler: --input und --output müssen zusammen angegeben werden.", err=True)
        raise typer.Exit(2)
    _generate(input_file, output_dir)


def _generate(input_file: Path, output_dir: Path) -> None:
    """Parse, resolve and analyse the backup once, then write regelwerk.xlsx, report.html and regelwerk.md.

    All files are built from the same resolved model and the same findings.
    """
    try:
        tree = parse_file(input_file)
    except FortidocError as exc:
        typer.echo(f"Fehler: {exc}", err=True)
        raise typer.Exit(1) from None
    for warning in tree.warnings:
        typer.echo(f"Hinweis: {'Zeile ' + str(warning.line) + ': ' if warning.line else ''}{warning.message}", err=True)
    resolved = resolve_config(tree)
    findings = analyze(tree, resolved)
    created = _now()
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        workbook = write_workbook(resolved, findings, output_dir / WORKBOOK_NAME, created)
        report = write_report(resolved, findings, output_dir / REPORT_NAME, created)
        markdown = write_markdown(resolved, findings, output_dir / MARKDOWN_NAME, created)
    except OSError as exc:
        typer.echo(f"Fehler: Ausgabe konnte nicht geschrieben werden: {exc.strerror or exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"Geschrieben: {workbook}")
    typer.echo(f"Geschrieben: {report}")
    typer.echo(f"Geschrieben: {markdown}")
    typer.echo(f"Auffälligkeiten: {len(findings)}")


@app.command("parse")
def parse_command(
    file: Annotated[Path, typer.Argument(help="FortiGate-Backup (.conf, unverschlüsselt).")],
    as_json: Annotated[bool, typer.Option("--json", help="Baum als JSON ausgeben.")] = False,
) -> None:
    """Backup einlesen und den generischen Konfigurationsbaum ausgeben."""
    try:
        tree = parse_file(file)
    except FortidocError as exc:
        typer.echo(f"Fehler: {exc}", err=True)
        raise typer.Exit(1) from None

    if as_json:
        meta = _meta(tree)
        meta["hinweis"] = CONFIDENTIAL_NOTICE
        payload = {"meta": meta, "tree": tree.model_dump(mode="json")}
        typer.echo(f"Hinweis: {CONFIDENTIAL_NOTICE}", err=True)
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        typer.echo(_summary(tree))


@app.command("resolve")
def resolve_command(
    file: Annotated[Path, typer.Argument(help="FortiGate-Backup (.conf, unverschlüsselt).")],
    as_json: Annotated[bool, typer.Option("--json", help="Aufgelöstes Modell als JSON ausgeben.")] = False,
) -> None:
    """Backup einlesen und das Regelwerk mit allen Objektverweisen auflösen."""
    try:
        tree = parse_file(file)
    except FortidocError as exc:
        typer.echo(f"Fehler: {exc}", err=True)
        raise typer.Exit(1) from None
    resolved = resolve_config(tree)
    if as_json:
        payload = {"meta": _meta(tree), "resolved": resolved.model_dump(mode="json")}
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        typer.echo(_resolved_summary(tree, resolved))


_NAT_LABELS = {
    "none": "kein NAT",
    "interface": "Adresse des Ausgangs-Interfaces",
    "pool": "IP-Pool",
    "central": "Central NAT (siehe NAT-Tabellen)",
}


def _side_text(side: AddressSide) -> str:
    names = side.objects + side.objects6 + side.internet_services
    values = ", ".join(v.value + (" (nicht auflösbar)" if v.kind == "unresolvable" else "") for v in side.values)
    text = f"{', '.join(names) or '-'} = {values or '-'}"
    return f"alles außer: {text}" if side.negate else text


def _policy_lines(p: ResolvedPolicy) -> list[str]:
    state = "aktiv" if p.enabled else "deaktiviert"
    title = f"  [{p.position}] ID {p.policy_id}"
    if p.name:
        title += f' "{p.name}"'
    title += f" {p.action} ({state}, IPv{p.ip_version})"
    if p.section == "firewall policy6":
        title += " [policy6]"
    service = ", ".join(e.value for e in p.service.entries) or "-"
    service_text = f"{', '.join(p.service.objects) or '-'} = {service}"
    if p.service.negate:
        service_text = f"alles außer: {service_text}"
    lines = [
        title,
        f"      Zonen: {', '.join(p.src_zones) or '-'} → {', '.join(p.dst_zones) or '-'}",
        f"      Quelle: {_side_text(p.source)}",
        f"      Ziel: {_side_text(p.destination)}",
        f"      Dienst: {service_text}",
    ]
    if not p.implicit:
        nat = _NAT_LABELS[p.nat.mode]
        if p.nat.pools:
            nat += ": " + ", ".join(pool.value for pool in p.nat.pools)
        lines.append(f"      NAT: {nat}")
    lines.extend(f"      Hinweis: {note}" for note in p.notes)
    return lines


def _resolved_summary(tree: ConfigTree, resolved: ResolvedConfig) -> str:
    meta = _meta(tree)
    d = resolved.device
    lines = [
        f"Datei: {meta['input_file']}",
        f"SHA-256: {meta['input_sha256']}",
        f"Tool-Version: fortidoc {__version__}",
        f"Erstellt: {meta['created_at']}",
        f"Gerät: {d.model or 'unbekannt'}, FortiOS {d.version or 'unbekannt'}",
    ]
    for vdom in resolved.vdoms:
        lines.append("")
        lines.append(f"VDOM {vdom.name}: {len(vdom.policies)} Regeln (inkl. implizitem Deny)")
        lines.extend(f"  Hinweis: {note}" for note in vdom.notes)
        for policy in vdom.policies:
            lines.extend(_policy_lines(policy))
    coverage = resolved.coverage
    lines.append("")
    lines.append(
        f"Nicht verarbeitet: {len(coverage.unprocessed_sections)} Abschnitte, "
        f"{len(coverage.unknown_keys)} unbekannte Schlüssel in ausgewerteten Abschnitten"
    )
    lines.extend(f"Hinweis: {note}" for note in resolved.notes)
    return "\n".join(lines)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _meta(tree: ConfigTree) -> dict:
    source = tree.source
    return {
        "tool": "fortidoc",
        "tool_version": __version__,
        "input_file": source.name if source else None,
        "input_sha256": source.sha256 if source else None,
        "input_size_bytes": source.size_bytes if source else None,
        "fortios_version": tree.header.version,
        "created_at": _now().isoformat(),
    }


def _count_entries(sections) -> tuple[int, int]:
    configs = edits = 0
    for node in iter_nodes(sections):
        if isinstance(node, ConfigNode):
            configs += 1
        elif isinstance(node, EditNode):
            edits += 1
    return configs, edits


def _summary(tree: ConfigTree) -> str:
    h = tree.header
    meta = _meta(tree)
    unknown = "unbekannt"
    lines = [
        f"Datei: {meta['input_file']}",
        f"SHA-256: {meta['input_sha256']}",
        f"Tool-Version: fortidoc {__version__}",
        f"Erstellt: {meta['created_at']}",
        f"Gerät: {h.model or unknown}",
        f"FortiOS-Version: {h.version or unknown}"
        + (f" (Build {h.build}, {h.firmware_type})" if h.build else ""),
        "VDOM-Modus: " + ("Multi-VDOM" if tree.vdom_mode == "multi-vdom" else "ohne VDOMs (als VDOM root geführt)"),
    ]
    if tree.vdom_mode == "multi-vdom":
        configs, edits = _count_entries(tree.global_sections)
        lines.append(f"Global: {len(tree.global_sections)} Abschnitte, {configs} config-Blöcke, {edits} Einträge")
    for vdom in tree.vdoms:
        configs, edits = _count_entries(vdom.sections)
        lines.append(f"VDOM {vdom.name}: {len(vdom.sections)} Abschnitte, {configs} config-Blöcke, {edits} Einträge")
    if tree.outside_sections:
        lines.append(f"Außerhalb von global/vdom: {len(tree.outside_sections)} Abschnitte")
    if tree.warnings:
        lines.append("Hinweise:")
        lines.extend(
            f"  - {'Zeile ' + str(w.line) + ': ' if w.line else ''}{w.message}" for w in tree.warnings
        )
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    app()
