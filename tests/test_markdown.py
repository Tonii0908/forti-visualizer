"""Stage 5: Markdown export (regelwerk.md) with Mermaid zone diagrams."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from conftest import FIXTURES, SECRET_MARKER, valid_fixtures
from fortidoc.cli import app
from fortidoc.core.analyzer import analyze, zone_matrix
from fortidoc.core.resolver import resolve_config
from fortidoc.export.markdown import (
    MARKDOWN_NAME,
    MAX_MERMAID_EDGES,
    md_cell,
    mermaid_label,
    mermaid_zones,
    render_markdown,
)
from fortidoc.parser.conf_parser import parse_file

CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
MERMAID = re.compile(r"```mermaid\n(.*?)```", re.S)


def render(name: str) -> str:
    tree = parse_file(FIXTURES / name)
    resolved = resolve_config(tree)
    return render_markdown(resolved, analyze(tree, resolved), CREATED)


def table_rows(text: str, heading: str) -> list[list[str]]:
    """Rows of the first table after a heading, split at unescaped '|'."""
    part = text.split(heading, 1)[1]
    lines = [line for line in part.split("\n\n#", 1)[0].splitlines() if line.startswith("|")]
    return [[c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]] for line in lines[2:]]


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def test_md_cell_escapes_markdown_and_html():
    assert md_cell("a|b") == "a\\|b"
    assert md_cell("<img src=x onerror=alert(1)>") == "&lt;img src=x onerror=alert(1)&gt;"
    assert md_cell("*fett* _kursiv_ [link](x) `code`") == "\\*fett\\* \\_kursiv\\_ \\[link\\](x) \\`code\\`"
    assert md_cell("eins\nzwei") == "eins<br>zwei"
    assert md_cell(None) == ""
    assert md_cell("a & b") == "a &amp; b"


def test_mermaid_label_keeps_only_safe_characters():
    assert mermaid_label("port1") == "port1"
    assert mermaid_label('a"b') == "a?b"
    assert mermaid_label("<script>") == "?script?"
    assert mermaid_label("zone]x|y#1;") == "zone?x?y?1?"
    assert mermaid_label("Zone Süd (alt)") == "Zone Süd (alt)"
    assert mermaid_label("`x` &amp; *b*") == "?x? ?amp? ?b?"
    # '_' between letters stays; at a word edge Mermaid would read it as emphasis.
    assert mermaid_label("lan_a_b") == "lan_a_b"
    assert mermaid_label("__init__ x_") == "??init?? x?"


def test_xss_texts_are_escaped():
    text = render("res_xss.conf")
    assert "<img" not in text and "<script" not in text.lower() and "<svg" not in text
    assert "&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;" in text


def test_zone_names_are_escaped_in_mermaid():
    text = render("res_diagram_names.conf")
    (block,) = MERMAID.findall(text)
    assert "<" not in block and ">" not in block.replace("-->", "")
    assert '["?script?alert(7)?/script?"]' in block
    assert "Sonderzeichen in Zonennamen" in text


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


def test_header_names_device_sha_and_tool():
    from fortidoc import __version__

    text = render("res_findings.conf")
    tree = parse_file(FIXTURES / "res_findings.conf")
    assert text.startswith("# Regelwerk FGT60F")
    assert tree.source.sha256 in text
    assert f"fortidoc {__version__}" in text
    assert "2026-01-02T03:04:05" in text
    assert "vertrauliche" in text


def test_one_mermaid_block_per_vdom():
    text = render("res_two_vdoms.conf")
    tree = parse_file(FIXTURES / "res_two_vdoms.conf")
    assert len(MERMAID.findall(text)) == len(resolve_config(tree).vdoms)


def test_mermaid_edges_follow_the_matrix():
    (m,) = zone_matrix(resolve_config(parse_file(FIXTURES / "res_matrix.conf")))
    block = mermaid_zones(m)
    assert block.startswith("flowchart LR\n")
    edges = re.findall(r"(z\d+) -->\|([^|]*)\| (z\d+)", block)
    assert len(edges) == len(m.cells)
    names = dict(re.findall(r'(z\d+)\["([^"]*)"\]', block))
    labels = {(names[a], names[b]): label for a, label, b in edges}
    assert labels[("lan", "port4")] == "2 Accept, 1 Deny"
    assert labels[("lan", "any")] == "1 deaktiviert"
    # Edge colours: one linkStyle per edge, by the dominant kind.
    assert block.count("linkStyle ") == len(m.cells)


def test_too_many_edges_gives_a_note_instead_of_a_diagram():
    from fortidoc.model.schema import MatrixCell, ZoneMatrix

    cells = [MatrixCell(src=f"s{i}", dst="d", accept=1, positions=[i]) for i in range(MAX_MERMAID_EDGES + 1)]
    m = ZoneMatrix(vdom="root", rows=[c.src for c in cells], cols=["d"], cells=cells)
    assert mermaid_zones(m) is None


def test_rules_table_lists_every_rule_in_order():
    text = render("res_matrix.conf")
    rows = table_rows(text, "### Regeln")
    resolved = resolve_config(parse_file(FIXTURES / "res_matrix.conf"))
    assert [r[0] for r in rows] == [str(p.position) for p in resolved.vdoms[0].policies]
    assert rows[-1][1] == "0"  # implicit deny


def test_rule_cells_show_objects_and_resolved_values():
    text = render("res_search.conf")
    row = next(r for r in table_rows(text, "### Regeln") if r[1] == "1")
    assert "10.10.20.0/24" in row[7] or "10.10.20" in row[7]


def test_local_in_and_applications():
    text = render("res_local_in.conf")
    rows = table_rows(text, "### Local-In-Regeln")
    assert [r[1] for r in rows] == ["1", "2", "3", "4", "1"]
    assert all(r[6] == "FortiGate (lokal)" for r in rows)
    sec = render("res_security_policy.conf")
    assert "Anwendung 15832" in sec


def test_findings_section():
    text = render("res_findings.conf")
    rows = table_rows(text, "## Auffälligkeiten")
    tree = parse_file(FIXTURES / "res_findings.conf")
    assert len(rows) == len(analyze(tree, resolve_config(tree)))


def test_value_lists_are_cut_in_long_cells():
    from fortidoc.export.markdown import MAX_VALUES, value_cell

    cell = value_cell([f"o{i}" for i in range(3)], [f"10.0.{i}.0/24" for i in range(MAX_VALUES + 5)])
    assert cell.count("10.0.") == MAX_VALUES
    assert "… und 5 weitere" in cell


# ---------------------------------------------------------------------------
# Confidentiality and determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", valid_fixtures(), ids=lambda p: p.name)
def test_no_secret_in_markdown(path):
    tree = parse_file(path)
    resolved = resolve_config(tree)
    assert SECRET_MARKER not in render_markdown(resolved, analyze(tree, resolved), CREATED)


@pytest.mark.parametrize(
    "name, raw",
    [
        ("res_no_vdom.conf", "fw-res-01"),
        ("no_vdom.conf", "fw-lab-01"),
        ("unknown_sections.conf", "brand-new"),
        ("res_findings.conf", "unevaluated-only-marker"),
    ],
)
def test_no_raw_values_from_unevaluated_sections(name, raw):
    assert raw not in render(name)


def test_same_input_gives_identical_markdown():
    assert render("res_two_vdoms.conf") == render("res_two_vdoms.conf")


def test_cli_writes_markdown(tmp_path):
    result = CliRunner().invoke(app, ["-i", str(FIXTURES / "res_matrix.conf"), "-o", str(tmp_path)])
    assert result.exit_code == 0, result.output
    path = tmp_path / MARKDOWN_NAME
    assert path.exists() and str(path) in result.stdout
    assert path.read_bytes().count(b"\r\n") == 0
