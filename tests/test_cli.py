"""CLI: `fortidoc parse <file> --json` and secret-free output."""

from __future__ import annotations

import hashlib
import json

import pytest
from typer.testing import CliRunner

from conftest import SECRET_MARKER, error_fixtures, valid_fixtures
from fortidoc import __version__
from fortidoc.cli import app

runner = CliRunner()


def run(*args: str):
    return runner.invoke(app, list(args))


def test_parse_json_outputs_tree(fixture_path):
    path = fixture_path("two_vdoms.conf")
    result = run("parse", str(path), "--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    meta = data["meta"]
    assert meta["tool_version"] == __version__
    assert meta["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert meta["fortios_version"] == "7.4.3"
    assert meta["created_at"]
    tree = data["tree"]
    assert tree["vdom_mode"] == "multi-vdom"
    assert [v["name"] for v in tree["vdoms"]] == ["root", "dmz"]


def test_parse_json_warns_about_confidential_data(fixture_path):
    result = run("parse", str(fixture_path("no_vdom.conf")), "--json")
    data = json.loads(result.stdout)
    assert "vertrauliche" in data["meta"]["hinweis"]
    assert "vertrauliche" in result.stderr


def test_parse_json_is_deterministic_except_creation_time(fixture_path):
    path = str(fixture_path("two_vdoms.conf"))
    first = json.loads(run("parse", path, "--json").stdout)
    second = json.loads(run("parse", path, "--json").stdout)
    first["meta"].pop("created_at")
    second["meta"].pop("created_at")
    assert first == second


def test_parse_without_json_prints_german_summary(fixture_path):
    result = run("parse", str(fixture_path("two_vdoms.conf")))
    assert result.exit_code == 0, result.output
    assert "FortiOS-Version: 7.4.3" in result.stdout
    assert "VDOM-Modus: Multi-VDOM" in result.stdout
    assert "SHA-256" in result.stdout


def test_parse_error_exit_code_and_message(fixture_path):
    result = run("parse", str(fixture_path("next_without_edit.conf")), "--json")
    assert result.exit_code == 1
    assert "Zeile 6" in result.stderr
    assert result.stdout == ""


def test_binary_file_is_rejected(fixture_path):
    result = run("parse", str(fixture_path("binary.conf")))
    assert result.exit_code == 1
    assert "verschlüsselt" in result.stderr


def test_main_command_writes_workbook(tmp_path, fixture_path):
    out = tmp_path / "doku" / "neu"
    result = run("--input", str(fixture_path("res_findings.conf")), "--output", str(out))
    assert result.exit_code == 0, result.output
    workbook = out / "regelwerk.xlsx"
    assert workbook.exists()
    assert str(workbook) in result.stdout
    assert "report.html" in result.stderr  # follows in stage 4
    import openpyxl

    assert openpyxl.load_workbook(workbook).sheetnames[0] == "Übersicht"


def test_main_command_short_options(tmp_path, fixture_path):
    result = run("-i", str(fixture_path("res_no_vdom.conf")), "-o", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert (tmp_path / "regelwerk.xlsx").exists()


@pytest.mark.parametrize("args", [("--input", "x.conf"), ("--output", "out")])
def test_main_command_needs_input_and_output(args):
    result = run(*args)
    assert result.exit_code == 2
    assert "zusammen" in result.stderr


def test_main_command_reports_parse_errors(tmp_path, fixture_path):
    result = run("--input", str(fixture_path("encrypted_fgbk.conf")), "--output", str(tmp_path))
    assert result.exit_code == 1
    assert result.stderr.startswith("Fehler:")
    assert not (tmp_path / "regelwerk.xlsx").exists()


@pytest.mark.parametrize("path", valid_fixtures() + error_fixtures(), ids=lambda p: p.name)
def test_no_secret_in_main_command_output(path, tmp_path):
    result = run("--input", str(path), "--output", str(tmp_path))
    assert SECRET_MARKER not in result.stdout
    assert SECRET_MARKER not in result.stderr


def test_version_option():
    result = run("--version")
    assert result.exit_code == 0
    assert __version__ in result.stdout


@pytest.mark.parametrize("path", valid_fixtures() + error_fixtures(), ids=lambda p: p.name)
@pytest.mark.parametrize("as_json", [True, False])
def test_no_secret_in_any_cli_output(path, as_json):
    args = ["parse", str(path)] + (["--json"] if as_json else [])
    result = run(*args)
    assert SECRET_MARKER not in result.stdout
    assert SECRET_MARKER not in result.stderr


# --- resolve (stage 2) ----------------------------------------------------------


def test_resolve_json(fixture_path):
    result = run("resolve", str(fixture_path("res_no_vdom.conf")), "--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["meta"]["fortios_version"] == "7.2.5"
    policies = data["resolved"]["vdoms"][0]["policies"]
    assert [p["policy_id"] for p in policies] == ["10", "3", "7", "0"]


def test_resolve_summary_is_german(fixture_path):
    result = run("resolve", str(fixture_path("res_negate_isdb.conf")))
    assert result.exit_code == 0, result.output
    assert "alles außer:" in result.stdout
    assert "Implizites Deny" in result.stdout
    assert "Nicht verarbeitet:" in result.stdout


def test_resolve_error(fixture_path):
    result = run("resolve", str(fixture_path("encrypted_fgbk.conf")))
    assert result.exit_code == 1
    assert "verschlüsselt" in result.stderr


@pytest.mark.parametrize("path", valid_fixtures() + error_fixtures(), ids=lambda p: p.name)
@pytest.mark.parametrize("as_json", [True, False])
def test_no_secret_in_resolve_output(path, as_json):
    result = run(*(["resolve", str(path)] + (["--json"] if as_json else [])))
    assert SECRET_MARKER not in result.stdout
    assert SECRET_MARKER not in result.stderr
