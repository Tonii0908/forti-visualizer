"""Stage 5: zone diagram (inline SVG in the report) and its layout."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from conftest import FIXTURES
from fortidoc.core.analyzer import analyze, zone_matrix
from fortidoc.core.resolver import resolve_config
from fortidoc.export.diagram import zone_diagram
from fortidoc.export.html import render_report
from fortidoc.parser.conf_parser import parse_file

CREATED = datetime(2026, 1, 2, tzinfo=timezone.utc)


def matrix(name):
    (m, *_) = zone_matrix(resolve_config(parse_file(FIXTURES / name)))
    return m


@pytest.fixture(scope="module")
def diagram():
    return zone_diagram(matrix("res_matrix.conf"))


def test_nodes_are_used_zones_in_matrix_order(diagram):
    assert [n.name for n in diagram.sources] == ["any", "lan", "port3", "port9"]
    assert [n.name for n in diagram.targets] == ["any", "port3", "port4"]


def test_unused_any_is_left_out():
    d = zone_diagram(matrix("res_search.conf"))
    assert all(n.name != "any" or n.used for n in d.sources + d.targets)


def test_one_edge_per_cell_and_kind(diagram):
    kinds = {(e.src, e.dst): sorted(k for k, _ in e.parts) for e in diagram.edges}
    assert kinds[("lan", "port4")] == ["accept", "deny"]
    assert kinds[("port3", "port4")] == ["accept", "other"]
    assert kinds[("lan", "any")] == ["disabled"]
    assert len(diagram.edges) == 6


def test_edge_title_names_the_counts(diagram):
    edge = next(e for e in diagram.edges if (e.src, e.dst) == ("lan", "port4"))
    assert edge.title == "lan → port4: 2 Accept, 1 Deny (Regeln an Position 1, 2, 6)"


def test_edge_paths_start_at_source_and_end_at_target(diagram):
    by_name_src = {n.name: n for n in diagram.sources}
    by_name_dst = {n.name: n for n in diagram.targets}
    for edge in diagram.edges:
        for _, path in edge.paths:
            start, end = re.findall(r"[-\d.]+ [-\d.]+", path)[0], re.findall(r"[-\d.]+ [-\d.]+", path)[-1]
            sx, sy = map(float, start.split())
            ex, ey = map(float, end.split())
            src, dst = by_name_src[edge.src], by_name_dst[edge.dst]
            assert sx == src.x + src.width and src.y <= sy <= src.y + src.height
            assert ex == dst.x and dst.y <= ey <= dst.y + dst.height


def test_width_grows_with_rule_count(diagram):
    widths = {(e.src, e.dst): dict(e.widths) for e in diagram.edges}
    assert widths[("lan", "port4")]["accept"] > widths[("any", "port4")]["accept"]


def test_long_zone_names_are_shortened_with_full_title():
    from fortidoc.export.diagram import _short

    assert _short("x" * 40).endswith("…") and len(_short("x" * 40)) <= 26
    assert _short("lan") == "lan"


def test_report_contains_one_svg_per_vdom():
    tree = parse_file(FIXTURES / "res_two_vdoms.conf")
    resolved = resolve_config(tree)
    html = render_report(resolved, analyze(tree, resolved), CREATED)
    section = html.split('id="view-diagram"', 1)[1].split("</section>", 1)[0]
    assert section.count("<svg") == len(resolved.vdoms)
    assert "xmlns" not in section  # inline SVG in HTML needs no namespace URL


def test_zone_names_are_escaped_in_the_svg():
    tree = parse_file(FIXTURES / "res_diagram_names.conf")
    resolved = resolve_config(tree)
    html = render_report(resolved, analyze(tree, resolved), CREATED)
    section = html.split('id="view-diagram"', 1)[1].split("</section>", 1)[0]
    assert "<script" not in section.lower()
    assert "&lt;script&gt;alert(7)&lt;/script&gt;" in section
    assert "zone-with-a-very-long-name-for-the-diagram" in section  # full name in the title


def test_empty_vdom_gets_a_note():
    tree = parse_file(FIXTURES / "header_v5.conf")
    resolved = resolve_config(tree)
    html = render_report(resolved, analyze(tree, resolved), CREATED)
    section = html.split('id="view-diagram"', 1)[1].split("</section>", 1)[0]
    assert "Keine Regeln" in section
