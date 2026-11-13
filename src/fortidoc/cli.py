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
from fortidoc.errors import FortidocError
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
        Optional[Path], typer.Option("--output", "-o", help="Zielordner für regelwerk.xlsx und report.html.")
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
    typer.echo(
        "Die Erzeugung von regelwerk.xlsx und report.html folgt in Stufe 3 und 4 und ist noch "
        "nicht verfügbar. Verfügbar ist: fortidoc parse <datei> [--json]",
        err=True,
    )
    raise typer.Exit(2)


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


def _meta(tree: ConfigTree) -> dict:
    source = tree.source
    return {
        "tool": "fortidoc",
        "tool_version": __version__,
        "input_file": source.name if source else None,
        "input_sha256": source.sha256 if source else None,
        "input_size_bytes": source.size_bytes if source else None,
        "fortios_version": tree.header.version,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
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
