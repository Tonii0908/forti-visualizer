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


def test_main_command_not_yet_available(tmp_path, fixture_path):
    result = run("--input", str(fixture_path("no_vdom.conf")), "--output", str(tmp_path))
    assert result.exit_code == 2
    assert "Stufe" in result.stderr


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
