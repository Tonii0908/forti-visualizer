"""Golden files: the parsed tree as JSON must not change unnoticed.

Regenerate after an intended change with:
    FORTIDOC_UPDATE_GOLDEN=1 pytest tests/test_golden.py
and review the diff before committing.
"""

from __future__ import annotations

import json
import os

import pytest

from conftest import FIXTURES, GOLDEN
from fortidoc.parser.conf_parser import parse_file

CASES = ["no_vdom", "two_vdoms", "edit_closed_by_end", "multiline_string", "secrets"]


@pytest.mark.parametrize("name", CASES)
def test_parse_tree_matches_golden(name):
    tree = parse_file(FIXTURES / f"{name}.conf")
    actual = json.dumps(tree.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    golden = GOLDEN / f"parse_{name}.json"
    if os.environ.get("FORTIDOC_UPDATE_GOLDEN"):
        golden.write_text(actual, encoding="utf-8")
    assert golden.exists(), f"golden file missing: {golden.name} (run with FORTIDOC_UPDATE_GOLDEN=1)"
    assert actual == golden.read_text(encoding="utf-8")
