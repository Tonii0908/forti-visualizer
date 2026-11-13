"""Syntax errors report line and context; binary/encrypted files are rejected."""

from __future__ import annotations

import pytest

from conftest import SECRET_MARKER
from fortidoc.errors import ConfigSyntaxError, InputFormatError
from fortidoc.parser.conf_parser import parse_bytes, parse_file


@pytest.mark.parametrize(
    ("name", "line", "fragment", "context"),
    [
        ("next_without_edit.conf", 6, "'next' ohne offenes 'edit'", "config firewall address"),
        ("end_without_config.conf", 7, "'end' ohne offenen 'config'-Block", ""),
        ("unclosed_config.conf", 2, "Dateiende", "config firewall address"),
        ("unterminated_quote.conf", 4, "Anführungszeichen", "config firewall address > edit \"a\""),
        ("unknown_command.conf", 4, "Unbekannter Befehl 'sett'", "config firewall address > edit \"a\""),
        ("edit_outside_config.conf", 2, "'edit' außerhalb eines 'config'-Blocks", ""),
        ("set_at_top_level.conf", 2, "'set' außerhalb eines Blocks", ""),
        ("edit_without_name.conf", 3, "'edit' ohne Namen", "config firewall address"),
        ("set_without_key.conf", 4, "'set' ohne Schlüssel", "config firewall address > edit \"a\""),
        ("secret_in_error_line.conf", 4, "Unbekannter Befehl 'sett'", "config user local > edit \"bob\""),
        ("edit_inside_edit.conf", 5, "'edit' innerhalb eines offenen 'edit'", "config firewall address > edit \"a\""),
    ],
)
def test_syntax_errors(fixture_path, name, line, fragment, context):
    with pytest.raises(ConfigSyntaxError) as exc:
        parse_file(fixture_path(name))
    err = exc.value
    assert err.line == line
    assert fragment in err.message
    assert err.context == context
    text = str(err)
    assert f"Zeile {line}" in text
    assert SECRET_MARKER not in text


def test_unclosed_config_names_the_open_blocks(fixture_path):
    with pytest.raises(ConfigSyntaxError) as exc:
        parse_file(fixture_path("unclosed_config.conf"))
    assert "config firewall address" in str(exc.value)


def test_error_shows_the_offending_line(fixture_path):
    with pytest.raises(ConfigSyntaxError) as exc:
        parse_file(fixture_path("unknown_command.conf"))
    assert exc.value.source_line == "sett subnet 10.0.0.0 255.0.0.0"


@pytest.mark.parametrize(
    "name", ["secret_in_error_line.conf", "secret_unterminated.conf", "secret_snmp_error_line.conf"]
)
def test_secrets_never_appear_in_error_messages(fixture_path, name):
    with pytest.raises(ConfigSyntaxError) as exc:
        parse_file(fixture_path(name))
    assert SECRET_MARKER not in str(exc.value)
    assert SECRET_MARKER not in repr(exc.value)
    assert SECRET_MARKER not in (exc.value.source_line or "")


def test_secret_line_in_context_is_redacted():
    text = "config user local\nedit bob\nset passwd ENC S3CR3Tx==\nnext\nnext\nend\n"
    with pytest.raises(ConfigSyntaxError) as exc:
        parse_bytes(text.encode())
    assert SECRET_MARKER not in str(exc.value)


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("binary.conf", "verschlüsselt"),
        ("encrypted.conf", "verschlüsselt"),
        ("not_a_config.conf", "Keine FortiOS-Konfiguration"),
        ("empty.conf", "leer"),
        ("whitespace_only.conf", "leer"),
        ("encrypted_fgbk.conf", "verschlüsselt"),
    ],
)
def test_input_format_errors(fixture_path, name, fragment):
    with pytest.raises(InputFormatError) as exc:
        parse_file(fixture_path(name))
    assert fragment in str(exc.value)


def test_fgbk_header_names_encryption(fixture_path):
    with pytest.raises(InputFormatError) as exc:
        parse_file(fixture_path("encrypted_fgbk.conf"))
    assert "#FGBK" in str(exc.value)


def test_invalid_utf8_falls_back_to_latin1_with_warning(fixture_path):
    tree = parse_file(fixture_path("latin1.conf"))
    assert tree.vdoms[0].config("firewall", "address").edit("München") is not None
    (warning,) = [w for w in tree.warnings if "Latin-1" in w.message]
    assert warning.line == 3
    assert "Zeile 3" in warning.message


def test_valid_utf8_has_no_encoding_warning(fixture_path):
    tree = parse_file(fixture_path("no_vdom.conf"))
    assert not any("Latin-1" in w.message for w in tree.warnings)


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(InputFormatError) as exc:
        parse_file(tmp_path / "does-not-exist.conf")
    assert "nicht gefunden" in str(exc.value)
