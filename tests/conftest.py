"""Shared pytest helpers for fortidoc tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
ERROR_FIXTURES = FIXTURES / "errors"
GOLDEN = Path(__file__).parent / "golden"

# Every secret value in the fixtures contains this marker. It must never
# appear in any output, log or error message.
SECRET_MARKER = "S3CR3T"


def valid_fixtures() -> list[Path]:
    """All fixtures that must parse without error."""
    return sorted(FIXTURES.glob("*.conf"))


def error_fixtures() -> list[Path]:
    return sorted(ERROR_FIXTURES.glob("*.conf"))


@pytest.fixture
def fixture_path():
    def _get(name: str) -> Path:
        path = FIXTURES / name
        if not path.exists():
            path = ERROR_FIXTURES / name
        assert path.exists(), f"missing fixture {name}"
        return path

    return _get


def strip_positions(data):
    """Remove line information so trees from different sources compare equal."""
    if isinstance(data, dict):
        return {
            k: strip_positions(v)
            for k, v in data.items()
            if k not in {"line", "end_line", "declared_line"}
        }
    if isinstance(data, list):
        return [strip_positions(v) for v in data]
    return data
