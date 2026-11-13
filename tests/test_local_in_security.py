"""Stage 5: firewall local-in-policy and firewall security-policy."""

from __future__ import annotations

from datetime import datetime, timezone

import openpyxl
import pytest

from conftest import FIXTURES
from fortidoc.core.analyzer import CAT_ALL, CAT_SHADOWED, analyze, zone_matrix
from fortidoc.core.resolver import LOCAL_ZONE, resolve_config
from fortidoc.export.excel import SHEETS, WORKBOOK_NAME, write_workbook
from fortidoc.export.html import build_report_data
from fortidoc.parser.conf_parser import parse_file

CREATED = datetime(2026, 1, 2, tzinfo=timezone.utc)


def load(name):
    tree = parse_file(FIXTURES / name)
    resolved = resolve_config(tree)
    return tree, resolved, analyze(tree, resolved)


@pytest.fixture(scope="module")
def local_in():
    return load("res_local_in.conf")


@pytest.fixture(scope="module")
def security():
    return load("res_security_policy.conf")


# ---------------------------------------------------------------------------
# Local-in
# ---------------------------------------------------------------------------


def test_local_in_rules_are_a_table_of_their_own(local_in):
    _, resolved, _ = local_in
    vdom = resolved.vdoms[0]
    assert [(p.section, p.policy_id) for p in vdom.local_in] == [
        ("firewall local-in-policy", "1"),
        ("firewall local-in-policy", "2"),
        ("firewall local-in-policy", "3"),
        ("firewall local-in-policy", "4"),
        ("firewall local-in-policy6", "1"),
    ]
    assert all(p.section == "firewall policy" or p.implicit for p in vdom.policies)


def test_local_in_interfaces_and_destination(local_in):
    _, resolved, _ = local_in
    first, _, third, fourth, six = resolved.vdoms[0].local_in
    assert first.src_zones == ["port2"]
    assert first.dst_zones == [LOCAL_ZONE]
    assert fourth.src_zones == ["port1"]  # FortiOS 7.4 style 'srcintf'
    assert [v.value for v in first.destination.values] == ["198.51.100.2/32"]
    assert six.ip_version == "6"
    assert [v.value for v in six.source.values] == ["::/0"]


def test_local_in_default_action_is_deny(local_in):
    _, resolved, _ = local_in
    third = resolved.vdoms[0].local_in[2]
    assert third.action == "deny"
    assert "action" in third.defaults_applied


def test_local_in_is_not_in_the_zone_matrix(local_in):
    _, resolved, _ = local_in
    (matrix,) = zone_matrix(resolved)
    assert LOCAL_ZONE not in matrix.cols
    assert sum(len(c.positions) for c in matrix.cells) == 1


def test_local_in_rules_get_findings(local_in):
    _, _, findings = local_in
    hits = [f for f in findings if f.category == CAT_ALL and f.object_kind == "Local-In-Regel"]
    assert [f.ref for f in hits] == ["1"]
    shadowed = [f for f in findings if f.category == CAT_SHADOWED]
    assert [(f.object_kind, f.ref) for f in shadowed] == [("Local-In-Regel", "4")]  # same as rule 2


def test_local_in_is_no_longer_unprocessed(local_in):
    _, resolved, _ = local_in
    paths = [s.path for s in resolved.coverage.unprocessed_sections]
    assert "firewall local-in-policy" not in paths
    assert "firewall local-in-policy6" not in paths


def test_local_in_sheet(local_in, tmp_path):
    _, resolved, findings = local_in
    wb = openpyxl.load_workbook(write_workbook(resolved, findings, tmp_path / WORKBOOK_NAME, CREATED))
    assert SHEETS[2] == "Local-In"
    ws = wb["Local-In"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    assert len(rows) == 5
    header = [c.value for c in ws[1]]
    assert dict(zip(header, rows[0]))["Zielzone"] == LOCAL_ZONE


def test_local_in_in_report(local_in):
    _, resolved, findings = local_in
    data = build_report_data(resolved, findings, CREATED)
    assert [p["id"] for p in data["localIn"]] == ["1", "2", "3", "4", "1"]
    assert all(p["dz"] == [LOCAL_ZONE] for p in data["localIn"])


# ---------------------------------------------------------------------------
# Security policies (NGFW policy-based mode)
# ---------------------------------------------------------------------------


def test_security_policies_form_the_rule_table(security):
    # ngfw-mode policy-based: firewall policy 1 is an SSL inspection rule (test_ngfw_mode.py).
    _, resolved, _ = security
    sections = [(p.section, p.policy_id) for p in resolved.vdoms[0].policies if not p.implicit]
    assert sections == [
        ("firewall security-policy", "1"),
        ("firewall security-policy", "2"),
        ("firewall security-policy", "3"),
        ("firewall security-policy", "4"),
    ]


def test_applications_and_categories_are_kept(security):
    _, resolved, _ = security
    sp1 = resolved.vdoms[0].policy("1", "firewall security-policy")
    assert sp1.applications == ["Anwendung 15832", "Anwendung 16354", "App-Kategorie 2"]
    assert any("Anwendungserkennung" in n for n in sp1.notes)
    sp2 = resolved.vdoms[0].policy("2", "firewall security-policy")
    assert sp2.applications == ["URL-Kategorie 52"]


def test_old_srcaddr4_keys(security):
    _, resolved, _ = security
    sp2 = resolved.vdoms[0].policy("2", "firewall security-policy")
    assert sp2.source.objects == ["net-lan"]
    assert [v.value for v in sp2.source.values] == ["10.0.1.0/24"]
    assert sp2.action == "deny" and "action" in sp2.defaults_applied


def test_security_policy_counts_in_the_matrix(security):
    _, resolved, _ = security
    (matrix,) = zone_matrix(resolved)
    cell = next(c for c in matrix.cells if c.src == "port1" and c.dst == "port2")
    assert len(cell.positions) == 4


def test_application_rule_is_covered_by_rule_without_application(security):
    _, _, findings = security
    shadowed = {f.ref: f.detail for f in findings if f.category == CAT_SHADOWED}
    # 4 (HTTPS + application) lies inside 3 (HTTPS, no application restriction).
    assert "4" in shadowed and "ID 3" in shadowed["4"]
    # 3 lies inside 1 by addresses and services, but 1 is restricted to applications.
    assert "3" not in shadowed


def test_applications_in_excel_and_report(security, tmp_path):
    _, resolved, findings = security
    wb = openpyxl.load_workbook(write_workbook(resolved, findings, tmp_path / WORKBOOK_NAME, CREATED))
    ws = wb["Policies"]
    header = [c.value for c in ws[1]]
    row = dict(zip(header, next(r for r in ws.iter_rows(min_row=2, values_only=True) if r[3] == "web-apps")))
    assert "Anwendung 15832" in row["Dienst (Objekt)"]
    assert "Security-Policy" in row["Hinweise"]
    data = build_report_data(resolved, findings, CREATED)
    web = next(p for p in data["policies"] if p["name"] == "web-apps")
    assert web["apps"] == ["Anwendung 15832", "Anwendung 16354", "App-Kategorie 2"]
