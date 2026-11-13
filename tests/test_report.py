"""Stage 4: report.html (data, escaping, offline, same source as Excel).

Browser behaviour (search, matrix clicks, paging, timing) is tested in
test_report_browser.py, which runs only when Playwright is installed.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import openpyxl
import pytest
from typer.testing import CliRunner

from conftest import FIXTURES, SECRET_MARKER, valid_fixtures
from fortidoc.cli import app
from fortidoc.core.analyzer import CATEGORIES, analyze, zone_matrix
from fortidoc.core.resolver import resolve_config
from fortidoc.export.excel import WORKBOOK_NAME
from fortidoc.export.html import REPORT_NAME, build_report_data, render_report, report_script
from fortidoc.parser.conf_parser import parse_file

CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
XSS_COMMENT = "</script><img src=x onerror=alert(1)>"
DATA_BLOCK = re.compile(r'<script type="application/json" id="report-data">(.*?)</script>', re.S)


def resolved_and_findings(name: str):
    tree = parse_file(FIXTURES / name)
    resolved = resolve_config(tree)
    return resolved, analyze(tree, resolved)


def render(name: str, created: datetime = CREATED) -> str:
    resolved, findings = resolved_and_findings(name)
    return render_report(resolved, findings, created)


def embedded_data(html: str) -> dict:
    match = DATA_BLOCK.search(html)
    assert match, "data block missing"
    return json.loads(match.group(1))


def outside_data(html: str) -> str:
    return DATA_BLOCK.sub("", html)


def policy(data: dict, policy_id: str, vdom: str = "root") -> dict:
    return next(p for p in data["policies"] if p["id"] == policy_id and p["vdom"] == vdom)


# ---------------------------------------------------------------------------
# CLI: both files from one run
# ---------------------------------------------------------------------------


def test_cli_writes_workbook_and_report(tmp_path):
    out = tmp_path / "doku"
    result = CliRunner().invoke(app, ["--input", str(FIXTURES / "res_findings.conf"), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / WORKBOOK_NAME).exists()
    assert (out / REPORT_NAME).exists()
    html = (out / REPORT_NAME).read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "report.html folgt" not in result.output


def test_report_and_workbook_show_the_same_findings(tmp_path):
    out = tmp_path / "doku"
    result = CliRunner().invoke(app, ["--input", str(FIXTURES / "res_findings.conf"), "--output", str(out)])
    assert result.exit_code == 0, result.output
    data = embedded_data((out / REPORT_NAME).read_text(encoding="utf-8"))
    wb = openpyxl.load_workbook(out / WORKBOOK_NAME)
    sheet_rows = [list(r) for r in wb["Auffälligkeiten"].iter_rows(min_row=2, values_only=True)]
    table = data["tables"]["findings"]
    assert table["headers"] == [c.value for c in wb["Auffälligkeiten"][1]]

    def norm(rows):
        return [["" if v is None else str(v) for v in row] for row in rows]

    assert norm(table["rows"]) == norm(sheet_rows)
    overview = {r[0]: r[1] for r in wb["Übersicht"].iter_rows(min_row=2, values_only=True)}
    for category in CATEGORIES:
        assert data["counts"][category] == overview[f"Auffälligkeiten: {category}"]


@pytest.mark.parametrize("table, sheet", [
    ("addresses", "Adressen"), ("services", "Dienste"), ("nat", "NAT"),
    ("interfaces", "Interfaces"), ("coverage", "Nicht verarbeitet"),
])  # fmt: skip
def test_object_tables_use_the_same_rows_as_the_workbook(table, sheet, tmp_path):
    out = tmp_path / "doku"
    CliRunner().invoke(app, ["--input", str(FIXTURES / "res_vip_central_nat.conf"), "--output", str(out)])
    data = embedded_data((out / REPORT_NAME).read_text(encoding="utf-8"))
    wb = openpyxl.load_workbook(out / WORKBOOK_NAME)
    assert data["tables"][table]["headers"] == [c.value for c in wb[sheet][1]]
    assert len(data["tables"][table]["rows"]) == wb[sheet].max_row - 1


def test_policies_in_report_match_the_model():
    resolved, findings = resolved_and_findings("res_two_vdoms.conf")
    data = build_report_data(resolved, findings, CREATED)
    expected = [(p.vdom, p.position, p.policy_id) for v in resolved.vdoms for p in v.policies]
    assert [(p["vdom"], p["pos"], p["id"]) for p in data["policies"]] == expected
    assert data["vdoms"] == [v.name for v in resolved.vdoms]


# ---------------------------------------------------------------------------
# Escaping
# ---------------------------------------------------------------------------


def test_backup_text_never_becomes_markup():
    html = render("res_xss.conf")
    assert XSS_COMMENT not in html
    assert "<img src=x" not in html
    assert "<svg onload" not in html
    assert "<iframe" not in html
    # The only </script> tags are the ones of the template.
    assert len(re.findall(r"</script", html, re.I)) == len(re.findall(r"<script", html, re.I))
    assert "<!--" not in html


def test_xss_texts_survive_as_data():
    data = embedded_data(render("res_xss.conf"))
    first = policy(data, "1")
    assert first["comment"] == XSS_COMMENT
    assert first["name"] == "<img src=x onerror=alert(5)>"
    assert first["src"]["o"] == ['"><svg onload=alert(2)>']
    assert policy(data, "2")["comment"] == "</SCRIPT ><script>alert(6)</script><!--"


def test_json_block_escapes_angle_brackets_and_line_separators():
    from fortidoc.export.html import encode_json

    text = encode_json({"a": "</script><!--  &"})
    assert "<" not in text and ">" not in text and "&" not in text
    assert " " not in text and " " not in text
    assert json.loads(text) == {"a": "</script><!--  &"}


def test_template_autoescapes(tmp_path):
    resolved, findings = resolved_and_findings("res_findings.conf")
    resolved.device.model = "<script>alert(3)</script>"
    resolved.notes.append('<a href="x">Hinweis</a>')
    html = render_report(resolved, findings, CREATED)
    assert "<script>alert(3)" not in html
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in html
    assert '<a href="x">' not in html


def test_template_syntax_in_backup_is_not_evaluated():
    html = render("res_xss.conf")
    alias = embedded_data(html)["tables"]["interfaces"]["rows"][0][8]
    assert alias == "<b>{{ 7*7 }}</b>"


def test_script_uses_no_html_sinks():
    script = report_script()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                 "setAttribute(\"on", "setAttribute('on", "srcdoc"):  # fmt: skip
        assert sink not in script, sink
    assert "textContent" in script
    assert "</script" not in script.lower()


# ---------------------------------------------------------------------------
# Offline: nothing is loaded from anywhere
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["res_xss.conf", "res_findings.conf", "res_two_vdoms.conf"])
def test_report_loads_no_external_url(name):
    html = render(name)
    shell = outside_data(html)
    assert not re.search(r"<(link|iframe|object|embed|base|img|audio|video|source|frame)\b", shell, re.I)
    assert not re.search(r"\s(src|href|srcset|poster|action|formaction|background)\s*=", shell, re.I)
    assert "url(" not in shell.lower()
    assert "@import" not in shell.lower()
    assert not re.search(r"https?:|//[a-z0-9]|\bftp:", shell, re.I)
    script = report_script()
    for api in ("fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "import(",
                "importScripts", "Worker(", "window.open", ".src =", ".href =", "location"):  # fmt: skip
        assert api not in script, api


def test_content_security_policy_forbids_every_load():
    html = render("res_findings.conf")
    match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html)
    assert match
    csp = match.group(1)
    assert "default-src 'none'" in csp
    assert "unsafe-eval" not in csp
    # The inline script is allowed by its hash only, so injected inline handlers would not run.
    script_src = next(d for d in csp.split(";") if d.strip().startswith("script-src")).split()
    assert script_src[1:] == [f"'sha256-{_sha256_b64(report_script())}'"]
    assert "http" not in csp


def _sha256_b64(text: str) -> str:
    import base64
    import hashlib

    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def test_external_url_in_comment_stays_text():
    html = render("res_xss.conf")
    assert "evil.example" not in outside_data(html)
    rows = embedded_data(html)["tables"]["addresses"]["rows"]
    assert any("https://evil.example/x.js" in (r[7] or "") for r in rows)


# ---------------------------------------------------------------------------
# Confidentiality, provenance, determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", valid_fixtures(), ids=lambda p: p.name)
def test_no_secret_in_report(path):
    tree = parse_file(path)
    resolved = resolve_config(tree)
    assert SECRET_MARKER not in render_report(resolved, analyze(tree, resolved), CREATED)


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
    assert raw in (FIXTURES / name).read_text(encoding="utf-8")
    tree = parse_file(FIXTURES / name)
    resolved = resolve_config(tree)
    assert raw not in render_report(resolved, analyze(tree, resolved), CREATED)


def test_report_names_sha_version_tool_and_time():
    from fortidoc import __version__

    html = render("res_findings.conf")
    tree = parse_file(FIXTURES / "res_findings.conf")
    shell = outside_data(html)
    assert tree.source.sha256 in shell
    assert "7.2.5" in shell
    assert f"fortidoc {__version__}" in shell
    assert "2026-01-02T03:04:05" in shell


def test_same_input_gives_identical_report():
    assert render("res_two_vdoms.conf") == render("res_two_vdoms.conf")


def test_only_creation_time_differs():
    a = render("res_two_vdoms.conf")
    b = render("res_two_vdoms.conf", datetime(2027, 6, 1, tzinfo=timezone.utc))
    assert a != b
    assert a.replace("2026-01-02T03:04:05", "X") == b.replace("2027-06-01T00:00:00", "X")


# ---------------------------------------------------------------------------
# Content of the page
# ---------------------------------------------------------------------------


def test_report_has_all_views_and_the_routing_notice():
    shell = outside_data(render("res_findings.conf"))
    for view in ("Übersicht", "Zonen-Matrix", "Regeln", "Adressen", "Dienste", "Interfaces und Zonen", "NAT",
                 "Auffälligkeiten", "Nicht verarbeitet"):  # fmt: skip
        assert view in shell, view
    assert "Die Suche wertet nur das Regelwerk aus, kein Routing." in shell


def test_search_notice_names_first_match_and_order():
    from fortidoc.export.html import FIRST_MATCH_NOTICE

    shell = outside_data(render("res_findings.conf"))
    assert FIRST_MATCH_NOTICE in shell
    assert "erste passende Regel" in FIRST_MATCH_NOTICE
    assert "Überdeckung" in FIRST_MATCH_NOTICE
    assert "Regelreihenfolge" in FIRST_MATCH_NOTICE


def test_print_stylesheet_a4_landscape_with_cover():
    shell = outside_data(render("res_findings.conf"))
    assert "@media print" in shell
    assert re.search(r"@page\s*\{[^}]*size:\s*A4 landscape", shell)
    assert 'id="cover"' in shell


def test_overview_lists_findings_per_check():
    resolved, findings = resolved_and_findings("res_findings.conf")
    data = build_report_data(resolved, findings, CREATED)
    assert list(data["counts"]) == CATEGORIES
    assert sum(data["counts"].values()) == len(findings)
    shell = outside_data(render_report(resolved, findings, CREATED))
    for category in CATEGORIES:
        assert category in shell


# ---------------------------------------------------------------------------
# Search data: intervals and uncertainty are prepared in Python
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def search_data():
    resolved, findings = resolved_and_findings("res_search.conf")
    return build_report_data(resolved, findings, CREATED)


def side_values(data, policy_id, side="src"):
    return [data["values"][i] for i in policy(data, policy_id)[side]["v"]]


VALUE_KIND, VALUE_TEXT, VALUE_NOTE, VALUE_REASON, VALUE_DEFAULT, VALUE_INTERVALS, VALUE_IP_VERSION = range(7)


def as_int(ip: str) -> str:
    return str(int(ipaddress.ip_address(ip)))


def test_network_and_range_values_carry_intervals(search_data):
    (net,) = side_values(search_data, "1")
    assert net[VALUE_KIND] == "network" and net[VALUE_TEXT] == "10.10.20.0/24"
    assert net[VALUE_INTERVALS] == [[4, as_int("10.10.20.0"), as_int("10.10.20.255")]]
    (rng,) = side_values(search_data, "8")
    assert rng[VALUE_KIND] == "range"
    assert rng[VALUE_INTERVALS] == [[4, as_int("10.10.20.10"), as_int("10.10.20.20")]]
    (net6,) = side_values(search_data, "9")
    assert net6[VALUE_INTERVALS] == [[6, as_int("2001:db8::"), as_int("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")]]


def test_uncertain_values_are_marked(search_data):
    assert side_values(search_data, "2")[0][VALUE_KIND] == "fqdn"
    assert side_values(search_data, "4")[0][VALUE_REASON] == "geo"
    assert side_values(search_data, "5")[0][VALUE_REASON] == "dynamic"
    assert side_values(search_data, "6")[0][VALUE_REASON] == "isdb"
    fabric = side_values(search_data, "12")[0]
    assert fabric[VALUE_DEFAULT] == 1
    for pid in ("2", "4", "5", "6"):
        assert side_values(search_data, pid)[0][VALUE_INTERVALS] == []


def test_negation_is_flagged_not_inverted(search_data):
    third = policy(search_data, "3")
    assert third["src"]["neg"] is True
    assert side_values(search_data, "3")[0][VALUE_TEXT] == "10.10.20.0/24"


def test_vip_value_has_external_and_mapped_interval(search_data):
    (vip,) = side_values(search_data, "13", "dst")
    assert vip[VALUE_KIND] == "vip"
    # The fourth element says which side of the VIP an interval belongs to.
    assert vip[VALUE_INTERVALS] == [
        [4, as_int("203.0.113.10"), as_int("203.0.113.10"), "extern"],
        [4, as_int("192.168.50.10"), as_int("192.168.50.10"), "intern"],
    ]


SVC_KIND, SVC_TEXT, SVC_NOTE, SVC_PROTOCOL, SVC_PORTS, SVC_SRC_RESTRICTED, SVC_PROTOCOL_NUMBER = range(7)


def services_of(data, policy_id):
    return [data["svcs"][i] for i in policy(data, policy_id)["svc"]["v"]]


def test_service_entries_carry_port_intervals(search_data):
    (https,) = services_of(search_data, "1")
    assert https[SVC_PROTOCOL] == "TCP" and https[SVC_PORTS] == [443, 443]
    (restricted,) = services_of(search_data, "11")
    assert restricted[SVC_SRC_RESTRICTED] == 1
    tcp_any, ping = services_of(search_data, "14")
    assert tcp_any[SVC_KIND] == "ip" and tcp_any[SVC_PROTOCOL_NUMBER] == 6
    assert ping[SVC_KIND] == "icmp"
    assert policy(search_data, "10")["svc"]["neg"] is True


def test_value_table_is_deduplicated(search_data):
    texts = [(v[VALUE_KIND], v[VALUE_TEXT], v[VALUE_NOTE], v[VALUE_REASON], v[VALUE_DEFAULT]) for v in search_data["values"]]
    assert len(texts) == len(set(texts))


# ---------------------------------------------------------------------------
# Zone matrix
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def matrix():
    resolved, _ = resolved_and_findings("res_matrix.conf")
    (m,) = zone_matrix(resolved)
    return m


def cell(m, src, dst):
    return next((c for c in m.cells if c.src == src and c.dst == dst), None)


def test_matrix_axes(matrix):
    assert matrix.vdom == "root"
    assert matrix.rows == ["any", "lan", "port3", "port9"]
    assert matrix.cols == ["any", "port3", "port4"]


def test_rule_counts_in_every_combination(matrix):
    lan_wan = cell(matrix, "lan", "port4")
    assert (lan_wan.accept, lan_wan.deny, lan_wan.disabled) == (2, 1, 0)  # rules 10, 60 and 20
    assert cell(matrix, "port3", "port4").accept == 1  # rule 10
    assert cell(matrix, "lan", "port3").deny == 1  # rule 20 (no action -> deny)
    assert cell(matrix, "any", "port4").accept == 1  # rule 30


def test_disabled_rules_counted_separately(matrix):
    lan_any = cell(matrix, "lan", "any")
    assert (lan_any.accept, lan_any.deny, lan_any.other, lan_any.disabled) == (0, 0, 0, 1)


def test_other_actions_and_unknown_interfaces(matrix):
    assert cell(matrix, "port3", "port4").other == 1  # action ipsec
    assert cell(matrix, "port9", "port4").accept == 1


def test_cells_list_their_rules_in_file_order(matrix):
    assert cell(matrix, "lan", "port4").positions == [1, 2, 6]


def test_implicit_deny_is_not_in_the_matrix(matrix):
    assert cell(matrix, "any", "any") is None
    resolved, _ = resolved_and_findings("res_matrix.conf")
    implicit = resolved.vdoms[0].policies[-1]
    assert implicit.implicit
    assert all(implicit.position not in c.positions for c in matrix.cells)


def test_one_matrix_per_vdom():
    resolved, _ = resolved_and_findings("res_two_vdoms.conf")
    matrices = zone_matrix(resolved)
    assert [m.vdom for m in matrices] == [v.name for v in resolved.vdoms]


def test_matrix_is_embedded_in_report():
    resolved, findings = resolved_and_findings("res_matrix.conf")
    data = build_report_data(resolved, findings, CREATED)
    (m,) = data["matrices"]
    assert m["rows"] == ["any", "lan", "port3", "port9"]
    assert ["lan", "port4", 2, 1, 0, 0, [1, 2, 6]] in m["cells"]


def test_report_path_is_written(tmp_path):
    from fortidoc.export.html import write_report

    resolved, findings = resolved_and_findings("res_matrix.conf")
    path = write_report(resolved, findings, tmp_path / REPORT_NAME, CREATED)
    assert isinstance(path, Path) and path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


# ---------------------------------------------------------------------------
# Rule flows: data for the flow view
# ---------------------------------------------------------------------------


def test_values_and_services_name_their_object():
    data = build_report_data(*resolved_and_findings("res_search.conf"), CREATED)
    p = policy(data, "1")
    # Runs of [object, count] cover the value list of each side exactly.
    for side in (p["src"], p["dst"]):
        assert sum(n for _, n in side["g"]) == len(side["v"])
        assert {name for name, _ in side["g"]} <= set(side["o"]) | set(side["o6"]) | set(side["isdb"])
    assert sum(n for _, n in p["svc"]["g"]) == len(p["svc"]["v"])
    assert [name for name, _ in p["svc"]["g"]] == p["svc"]["o"]


def test_zone_info_lists_interfaces_with_subnet():
    data = build_report_data(*resolved_and_findings("res_matrix.conf"), CREATED)
    lan = data["zoneInfo"]["root"]["lan"]
    assert len(lan) == 2 and all(line.startswith("port") for line in lan)
    assert any("/" in line for line in lan)


def test_flow_view_has_no_svg_namespace_url():
    html = render("res_search.conf")
    assert 'id="svg-ns"' in html
    assert "w3.org" not in html
