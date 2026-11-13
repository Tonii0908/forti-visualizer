"""Follow-up to stage 5: NGFW mode policy-based.

In policy-based mode the entries of 'firewall policy' are SSL inspection and
authentication rules; the access rules of the VDOM are the security policies.
"""

from __future__ import annotations

from datetime import datetime, timezone

import openpyxl
import pytest

from conftest import FIXTURES
from fortidoc.core.analyzer import CAT_ALL, CAT_DISABLED, CAT_NO_LOGGING, analyze, zone_matrix
from fortidoc.core.resolver import resolve_config
from fortidoc.export.common import overview_rows
from fortidoc.export.excel import SHEETS, WORKBOOK_NAME, write_workbook
from fortidoc.export.html import build_report_data, render_report
from fortidoc.export.markdown import render_markdown
from fortidoc.parser.conf_parser import parse_file

CREATED = datetime(2026, 1, 2, tzinfo=timezone.utc)


def load(name):
    tree = parse_file(FIXTURES / name)
    resolved = resolve_config(tree)
    return resolved, analyze(tree, resolved)


@pytest.fixture(scope="module")
def policy_based():
    return load("res_security_policy.conf")


def test_mode_is_read_and_defaults_to_profile_based(policy_based):
    resolved, _ = policy_based
    assert resolved.vdoms[0].ngfw_mode == "policy-based"
    other, _ = load("res_matrix.conf")
    assert other.vdoms[0].ngfw_mode == "profile-based"
    assert other.vdoms[0].inspection == []


def test_ngfw_mode_is_no_unknown_key(policy_based):
    resolved, _ = policy_based
    assert not any(k.section == "system settings" and k.key == "ngfw-mode" for k in resolved.coverage.unknown_keys)


def test_firewall_policies_become_inspection_rules(policy_based):
    resolved, _ = policy_based
    vdom = resolved.vdoms[0]
    assert [(p.section, p.policy_id, p.position) for p in vdom.inspection] == [("firewall policy", "1", 1)]
    assert [p.policy_id for p in vdom.policies if not p.implicit] == ["1", "2", "3", "4"]
    assert all(p.section == "firewall security-policy" for p in vdom.policies if not p.implicit)
    assert [p.position for p in vdom.policies] == [1, 2, 3, 4, 5]
    assert vdom.policies[-1].implicit


def test_inspection_rules_are_not_in_the_matrix(policy_based):
    resolved, _ = policy_based
    (matrix,) = zone_matrix(resolved)
    cell = next(c for c in matrix.cells if c.src == "port1" and c.dst == "port2")
    assert cell.positions == [1, 2, 3, 4]  # the security policies only


def test_inspection_rules_skip_all_and_logging_checks(policy_based):
    _, findings = policy_based
    kinds = {(f.object_kind, f.category) for f in findings}
    assert ("SSL-Inspection-Regel", CAT_ALL) not in kinds
    assert ("SSL-Inspection-Regel", CAT_NO_LOGGING) not in kinds


def test_other_checks_still_apply_to_inspection_rules(tmp_path):
    text = (FIXTURES / "res_security_policy.conf").read_text(encoding="utf-8")
    text = text.replace('set ssl-ssh-profile "certificate-inspection"', 'set ssl-ssh-profile "certificate-inspection"\n        set status disable')
    path = tmp_path / "disabled.conf"
    path.write_text(text, encoding="utf-8")
    tree = parse_file(path)
    findings = analyze(tree, resolve_config(tree))
    assert [(f.object_kind, f.ref) for f in findings if f.category == CAT_DISABLED] == [("SSL-Inspection-Regel", "1")]


def test_overview_names_the_mode(policy_based):
    resolved, findings = policy_based
    rows = dict((str(k), v) for k, v in overview_rows(resolved, findings, CREATED.replace(tzinfo=None)))
    assert rows["VDOM root: NGFW-Modus"].startswith("richtlinienbasiert")
    assert rows["VDOM root: SSL-Inspection-Regeln"] == 1
    assert rows["VDOM root: Regeln (ohne implizites Deny)"] == 4
    assert any("Security-Policies" in str(v) for k, v in rows.items() if k.startswith("Hinweis VDOM"))
    other, other_findings = load("res_matrix.conf")
    other_rows = dict(overview_rows(other, other_findings, CREATED.replace(tzinfo=None)))
    assert other_rows["VDOM root: NGFW-Modus"] == "profilbasiert"


def test_excel_sheet(policy_based, tmp_path):
    resolved, findings = policy_based
    wb = openpyxl.load_workbook(write_workbook(resolved, findings, tmp_path / WORKBOOK_NAME, CREATED))
    assert SHEETS[3] == "SSL-Inspection"
    rows = list(wb["SSL-Inspection"].iter_rows(min_row=2, values_only=True))
    assert len(rows) == 1 and rows[0][3] == "ssl-inspection"
    names = [r[3] for r in wb["Policies"].iter_rows(min_row=2, values_only=True)]
    assert "ssl-inspection" not in names


def test_report_view_and_search_data(policy_based):
    resolved, findings = policy_based
    data = build_report_data(resolved, findings, CREATED)
    assert [p["name"] for p in data["inspection"]] == ["ssl-inspection"]
    assert "ssl-inspection" not in [p["name"] for p in data["policies"]]
    html = render_report(resolved, findings, CREATED)
    assert 'data-view="inspection"' in html
    diagram = html.split('id="view-diagram"', 1)[1].split("</section>", 1)[0]
    assert diagram.count('class="edge ') == 2  # accept and deny of the security policies


def test_profile_based_report_hides_the_view():
    resolved, findings = load("res_matrix.conf")
    html = render_report(resolved, findings, CREATED)
    assert 'data-view="inspection" hidden' in html


def test_markdown_section(policy_based):
    resolved, findings = policy_based
    text = render_markdown(resolved, findings, CREATED)
    assert "### SSL-Inspection- und Authentifizierungsregeln" in text
    assert "NGFW-Modus" in text
