"""Stage 3: regelwerk.xlsx."""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import openpyxl
import pytest

from conftest import FIXTURES, SECRET_MARKER, valid_fixtures
from fortidoc.core.analyzer import analyze
from fortidoc.core.resolver import resolve_config
from fortidoc.export.excel import (
    CELL_LIMIT,
    POLICY_COLUMNS,
    SHEETS,
    WORKBOOK_NAME,
    write_workbook,
)
from fortidoc.parser.conf_parser import parse_file

CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
HEADER = "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"
INTERFACES = """config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.1.1 255.255.255.0
        set type physical
    next
    edit "port2"
        set vdom "root"
        set ip 10.0.2.1 255.255.255.0
        set type physical
    next
end
"""


def build(path: Path, out_dir: Path, created: datetime = CREATED) -> Path:
    tree = parse_file(path)
    resolved = resolve_config(tree)
    return write_workbook(resolved, analyze(tree, resolved), out_dir / WORKBOOK_NAME, created)


def rows(ws) -> list[tuple]:
    return list(ws.iter_rows(min_row=2, values_only=True))


def all_xml(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        return "\n".join(zf.read(name).decode("utf-8") for name in zf.namelist())


@pytest.fixture(scope="module")
def findings_book(tmp_path_factory):
    out = tmp_path_factory.mktemp("findings")
    path = build(FIXTURES / "res_findings.conf", out)
    return path, openpyxl.load_workbook(path)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_sheet_names_and_order(findings_book):
    _, wb = findings_book
    assert wb.sheetnames == SHEETS
    assert SHEETS == [
        "Übersicht",
        "Policies",
        "Local-In",
        "SSL-Inspection",
        "Adressen",
        "Dienste",
        "NAT",
        "Interfaces",
        "Auffälligkeiten",
        "Nicht verarbeitet",
    ]


def test_policy_columns_exactly_as_specified(findings_book):
    _, wb = findings_book
    header = [c.value for c in wb["Policies"][1]]
    assert header == POLICY_COLUMNS
    assert header == [
        "VDOM", "Position", "ID", "Name", "Status", "Action", "Quellzone", "Zielzone",
        "Quelle (Objekt)", "Quelle (aufgelöst)", "Ziel (Objekt)", "Ziel (aufgelöst)",
        "Dienst (Objekt)", "Dienst (aufgelöst)", "NAT", "Benutzer und Gruppen", "Schedule",
        "Logging", "Profile", "Kommentar", "Hinweise",
    ]  # fmt: skip


def test_every_sheet_has_frozen_header_and_autofilter(findings_book):
    _, wb = findings_book
    for ws in wb.worksheets:
        assert ws.freeze_panes == "A2", ws.title
        assert ws.auto_filter.ref and ws.auto_filter.ref.startswith("A1:"), ws.title
        assert ws["A1"].font.bold, ws.title


def test_cells_are_wrapped(findings_book):
    _, wb = findings_book
    assert wb["Policies"]["J2"].alignment.wrap_text


# Expected data rows (without header) per sheet.
EXPECTED_ROWS = {
    "res_findings.conf": {
        "Policies": 7, "Adressen": 11, "Dienste": 3, "NAT": 2, "Interfaces": 2,
        "Auffälligkeiten": 12, "Nicht verarbeitet": 1,
    },
    "res_two_vdoms.conf": {
        "Policies": 5, "Adressen": 4, "Dienste": 2, "NAT": 0, "Interfaces": 3,
        "Auffälligkeiten": 3, "Nicht verarbeitet": 0,
    },
    "res_vip_central_nat.conf": {"Policies": 4, "Adressen": 5, "Dienste": 1, "NAT": 5, "Interfaces": 3},
    "res_services.conf": {"Dienste": 15},
}  # fmt: skip


@pytest.mark.parametrize("name", sorted(EXPECTED_ROWS))
def test_row_counts_per_fixture(name, tmp_path):
    wb = openpyxl.load_workbook(build(FIXTURES / name, tmp_path))
    for sheet, count in EXPECTED_ROWS[name].items():
        assert len(rows(wb[sheet])) == count, sheet


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("res_*.conf")), ids=lambda p: p.name)
def test_row_counts_match_resolved_model(path, tmp_path):
    tree = parse_file(path)
    resolved = resolve_config(tree)
    findings = analyze(tree, resolved)
    wb = openpyxl.load_workbook(write_workbook(resolved, findings, tmp_path / WORKBOOK_NAME, CREATED))
    vdoms = resolved.vdoms
    assert len(rows(wb["Policies"])) == sum(len(v.policies) for v in vdoms)
    assert len(rows(wb["Adressen"])) == sum(len(v.addresses) for v in vdoms)
    assert len(rows(wb["Dienste"])) == sum(len(v.services) for v in vdoms)
    assert len(rows(wb["NAT"])) == sum(len(v.vips) + len(v.ippools) + len(v.snat) for v in vdoms)
    assert len(rows(wb["Interfaces"])) == len(resolved.interfaces)
    assert len(rows(wb["Auffälligkeiten"])) == len(findings)
    coverage = resolved.coverage
    expected = len(coverage.unprocessed_sections) + len(coverage.unknown_keys)
    assert len(rows(wb["Nicht verarbeitet"])) == expected


def test_policy_row_content(findings_book):
    _, wb = findings_book
    ws = wb["Policies"]
    header = [c.value for c in ws[1]]
    first = dict(zip(header, rows(ws)[0]))
    assert first["VDOM"] == "root"
    assert first["Position"] == 1
    assert first["ID"] == 1
    assert first["Action"] == "ACCEPT"
    assert first["Status"] == "aktiv"
    assert first["Quelle (Objekt)"] == "all"
    assert first["Quelle (aufgelöst)"] == "0.0.0.0/0"
    assert first["Dienst (aufgelöst)"] == "TCP/443"
    implicit = dict(zip(header, rows(ws)[-1]))
    assert implicit["ID"] == 0
    assert implicit["Action"] == "DENY"


def test_numeric_policy_ids_are_numbers(findings_book):
    _, wb = findings_book
    ws = wb["Policies"]
    column = POLICY_COLUMNS.index("ID") + 1
    cells = [ws.cell(row=r, column=column) for r in range(2, ws.max_row + 1)]
    assert cells and all(isinstance(c.value, int) for c in cells)
    assert all(c.data_type == "n" for c in cells)


def test_non_numeric_policy_id_stays_text():
    from fortidoc.export.excel import policy_id_cell

    assert policy_id_cell("17") == 17
    assert policy_id_cell("007") == "007"  # a leading zero would get lost as a number
    assert policy_id_cell("1a") == "1a"
    assert policy_id_cell("") == ""


def test_overview_counts_findings_per_check(findings_book):
    from fortidoc.core.analyzer import CATEGORIES

    _, wb = findings_book
    overview = dict(rows(wb["Übersicht"]))
    tree = parse_file(FIXTURES / "res_findings.conf")
    findings = analyze(tree, resolve_config(tree))
    assert overview["Auffälligkeiten gesamt"] == len(findings)
    for category in CATEGORIES:
        expected = sum(1 for f in findings if f.category == category)
        assert overview[f"Auffälligkeiten: {category}"] == expected, category
    assert overview["Auffälligkeiten: Deaktivierte Regel"] == 1


def test_address_without_subnet_shows_note_in_policies(findings_book):
    _, wb = findings_book
    ws = wb["Policies"]
    row = next(r for r in rows(ws) if r[3] == "fabric-source")
    assert "kein subnet im Backup, FortiOS-Default" in row[POLICY_COLUMNS.index("Quelle (aufgelöst)")]


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def fill_of(ws, row: int) -> str:
    return ws.cell(row=row, column=1).fill.fgColor.rgb[-6:]


def test_action_colors_and_disabled_grey(findings_book):
    _, wb = findings_book
    ws = wb["Policies"]
    by_name = {ws.cell(row=r, column=4).value: r for r in range(2, ws.max_row + 1)}
    assert fill_of(ws, by_name["any-source"]) == "C6EFCE"  # accept green
    assert fill_of(ws, by_name["Implizites Deny"]) == "FFC7CE"  # deny red
    disabled = by_name["disabled-deny"]
    assert fill_of(ws, disabled) == "D9D9D9"
    assert ws.cell(row=disabled, column=1).font.color.rgb[-6:] == "808080"
    # The whole row is coloured, not only the first cell.
    assert ws.cell(row=by_name["any-source"], column=len(POLICY_COLUMNS)).fill.fgColor.rgb[-6:] == "C6EFCE"


# ---------------------------------------------------------------------------
# Formula safety, control characters, cell limit
# ---------------------------------------------------------------------------


def test_text_starting_with_equals_is_text_not_formula(findings_book):
    path, wb = findings_book
    ws = wb["Policies"]
    comment = next(r for r in rows(ws) if r[3] == "all-services-no-log")[POLICY_COLUMNS.index("Kommentar")]
    assert comment == "=> siehe Ticket"
    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str) and cell.value.startswith("="):
                    assert cell.data_type == "s", (sheet.title, cell.coordinate)
    addresses = {r[2]: r for r in rows(wb["Adressen"])}
    assert addresses["=cmd"][7] == '=HYPERLINK("http://example.invalid")'
    # No formula element anywhere in the file.
    assert "<f>" not in all_xml(path) and "<f " not in all_xml(path)


def test_formula_text_survives_reload_without_formula_evaluation(findings_book):
    path, _ = findings_book
    wb = openpyxl.load_workbook(path, data_only=False)
    values = [c.value for ws in wb.worksheets for row in ws.iter_rows() for c in row]
    assert "=> siehe Ticket" in values
    assert "=cmd" in values


def test_illegal_control_characters_are_removed(tmp_path):
    conf = tmp_path / "ctrl.conf"
    text = (
        HEADER
        + INTERFACES
        + """config firewall address
    edit "net-a"
        set subnet 10.0.1.0 255.255.255.0
        set comment "bell\x07here"
    next
end
config firewall policy
    edit 1
        set name "ctrl\x01name"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "net-a"
        set dstaddr "net-a"
        set action accept
        set schedule "always"
        set service "ALL"
        set comments "esc\x1bape"
    next
end
"""
    )
    conf.write_bytes(text.encode("utf-8"))
    path = build(conf, tmp_path)
    wb = openpyxl.load_workbook(path)
    values = [c.value for ws in wb.worksheets for row in ws.iter_rows() for c in row]
    assert "ctrlname" in values
    assert "escape" in values
    assert "bellhere" in values
    xml = all_xml(path)
    for char in ("\x01", "\x07", "\x1b"):
        assert char not in xml


def big_group_conf(tmp_path: Path, count: int) -> Path:
    addresses = "".join(
        f'    edit "h-{i:05d}"\n        set subnet 10.{i // 250}.{i % 250}.1 255.255.255.255\n    next\n'
        for i in range(count)
    )
    members = " ".join(f'"h-{i:05d}"' for i in range(count))
    text = (
        HEADER
        + INTERFACES
        + "config firewall address\n"
        + addresses
        + "end\n"
        + f'config firewall addrgrp\n    edit "grp-big"\n        set member {members}\n    next\nend\n'
        + """config firewall policy
    edit 1
        set name "big"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "grp-big"
        set dstaddr "grp-big"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
"""
    )
    conf = tmp_path / "big.conf"
    conf.write_text(text, encoding="utf-8")
    return conf


def test_cell_limit_shortens_long_lists(tmp_path):
    count = 4000
    path = build(big_group_conf(tmp_path, count), tmp_path)
    wb = openpyxl.load_workbook(path)
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if isinstance(cell.value, str):
                    assert len(cell.value) <= CELL_LIMIT, (ws.title, cell.coordinate)
    policy = rows(wb["Policies"])[0]
    source = policy[POLICY_COLUMNS.index("Quelle (aufgelöst)")]
    last = source.splitlines()[-1]
    assert last.startswith("… und ") and "weitere" in last
    assert "Reiter Adressen" in last
    shown = len(source.splitlines()) - 1
    assert int(last.split()[2]) == count - shown
    group = next(r for r in rows(wb["Adressen"]) if r[2] == "grp-big")
    assert "… und " in group[6].splitlines()[-1]  # "Aufgelöst"


# ---------------------------------------------------------------------------
# Provenance, determinism, confidentiality
# ---------------------------------------------------------------------------


def test_overview_names_sha_version_tool_and_time(findings_book):
    from fortidoc import __version__

    _, wb = findings_book
    overview = dict(rows(wb["Übersicht"]))
    tree = parse_file(FIXTURES / "res_findings.conf")
    assert overview["SHA-256 der Eingabedatei"] == tree.source.sha256
    assert overview["FortiOS-Version"] == "7.2.5"
    assert overview["Tool-Version"] == f"fortidoc {__version__}"
    assert overview["Erstellzeit (UTC)"] == "2026-01-02T03:04:05"


def test_same_input_gives_identical_bytes(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = build(FIXTURES / "res_two_vdoms.conf", tmp_path / "a")
    b = build(FIXTURES / "res_two_vdoms.conf", tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


def test_only_creation_time_differs(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = build(FIXTURES / "res_two_vdoms.conf", tmp_path / "a")
    b = build(FIXTURES / "res_two_vdoms.conf", tmp_path / "b", datetime(2027, 6, 1, tzinfo=timezone.utc))
    with zipfile.ZipFile(a) as za, zipfile.ZipFile(b) as zb:
        assert za.namelist() == zb.namelist()
        differing = [n for n in za.namelist() if za.read(n) != zb.read(n)]
    # Creation time is in the document properties and on the overview sheet.
    assert set(differing) <= {"docProps/core.xml", "xl/worksheets/sheet1.xml", "xl/sharedStrings.xml"}


@pytest.mark.parametrize("path", valid_fixtures(), ids=lambda p: p.name)
def test_no_secret_in_workbook(path, tmp_path):
    assert SECRET_MARKER not in all_xml(build(path, tmp_path))


@pytest.mark.parametrize(
    "name, raw",
    [
        ("res_no_vdom.conf", "fw-res-01"),  # system global hostname
        ("no_vdom.conf", "fw-lab-01"),
        ("unknown_sections.conf", "brand-new"),
        ("res_findings.conf", "unevaluated-only-marker"),  # value inside firewall shaping-policy
    ],
)
def test_no_raw_values_from_unevaluated_sections(name, raw, tmp_path):
    assert raw in (FIXTURES / name).read_text(encoding="utf-8")
    assert raw not in all_xml(build(FIXTURES / name, tmp_path))


def test_coverage_sheet_names_unprocessed_section(findings_book):
    _, wb = findings_book
    assert ("Abschnitt", "root", "firewall shaping-policy", None, 1) == rows(wb["Nicht verarbeitet"])[0][:5]


@pytest.mark.skipif(shutil.which("soffice") is None, reason="LibreOffice nicht installiert")
def test_libreoffice_opens_workbook(tmp_path):
    path = build(FIXTURES / "res_findings.conf", tmp_path)
    out = tmp_path / "csv"
    result = subprocess.run(
        ["soffice", "--headless", "--convert-to", "csv", "--outdir", str(out), str(path)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    csv = out / "regelwerk.csv"
    assert csv.exists()
    assert "Gerät" in csv.read_text(encoding="utf-8", errors="replace")
