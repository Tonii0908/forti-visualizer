"""Tokenizer: quotes, escapes, multiple values, multi-line strings."""

from __future__ import annotations

import pytest

from fortidoc.errors import TokenizeError
from fortidoc.parser.tokenizer import Comment, Statement, tokenize


def statements(text: str) -> list[Statement]:
    return [s for s in tokenize(text) if isinstance(s, Statement)]


def words(text: str) -> list[list[str]]:
    return [[t.text for t in s.tokens] for s in statements(text)]


def test_plain_words_split_on_whitespace():
    assert words("    set ip 10.0.0.1 255.255.255.0\n") == [
        ["set", "ip", "10.0.0.1", "255.255.255.0"]
    ]


def test_tabs_are_whitespace():
    assert words("\tset\tname\t\"a b\"\n") == [["set", "name", "a b"]]


def test_multiple_quoted_values_become_list():
    assert words('set member "a" "b c"\n') == [["set", "member", "a", "b c"]]


def test_quoted_flag_is_kept():
    (stmt,) = statements('set member "a" b\n')
    assert [t.quoted for t in stmt.tokens] == [False, False, True, False]


def test_escaped_quote_and_backslash():
    assert words(r'set comment "say \"hi\" to C:\\dir"' + "\n") == [
        ["set", "comment", 'say "hi" to C:\\dir']
    ]


def test_other_backslash_sequences_stay_literal():
    assert words(r'set comment "a\nb\tc"' + "\n") == [["set", "comment", r"a\nb\tc"]]


def test_escape_outside_quotes():
    assert words(r"set x a\"b c\\d" + "\n") == [["set", "x", 'a"b', "c\\d"]]


def test_empty_quoted_string_is_a_value():
    (stmt,) = statements('set comment ""\n')
    assert [t.text for t in stmt.tokens] == ["set", "comment", ""]
    assert stmt.tokens[2].quoted


def test_adjacent_quoted_and_plain_parts_join():
    assert words('set x ab"c d"e\n') == [["set", "x", "abc de"]]


def test_hash_and_apostrophe_inside_tokens_are_text():
    assert words("set fqdn host#1.example.com\nset c don't\n") == [
        ["set", "fqdn", "host#1.example.com"],
        ["set", "c", "don't"],
    ]


def test_multiline_string_lines_are_not_commands():
    text = 'set buffer "first\nconfig firewall policy\nnext\nend\nlast"\nset header http\n'
    stmts = statements(text)
    assert [[t.text for t in s.tokens] for s in stmts] == [
        ["set", "buffer", "first\nconfig firewall policy\nnext\nend\nlast"],
        ["set", "header", "http"],
    ]
    assert stmts[0].line == 1
    assert stmts[0].end_line == 5
    assert stmts[1].line == 6


def test_multiline_string_with_escaped_quote_inside():
    text = 'set buffer "a\n\\"b\\"\nc"\nend\n'
    assert words(text) == [["set", "buffer", 'a\n"b"\nc'], ["end"]]


def test_crlf_line_endings():
    text = 'config a\r\n  set c "x\r\ny"\r\nend\r\n'
    assert words(text) == [["config", "a"], ["set", "c", "x\ny"], ["end"]]


def test_comment_lines_and_blank_lines():
    items = list(tokenize("#config-version=X\n\n   \nconfig a\n# inner\nend\n"))
    assert isinstance(items[0], Comment) and items[0].text == "config-version=X"
    assert items[0].line == 1
    assert isinstance(items[1], Statement) and items[1].line == 4
    assert isinstance(items[2], Comment) and items[2].line == 5
    assert isinstance(items[3], Statement) and items[3].line == 6


def test_unterminated_quote_reports_start_line():
    with pytest.raises(TokenizeError) as exc:
        list(tokenize('config a\n  set c "open\nnext\nend\n'))
    assert exc.value.line == 2
    assert [t.text for t in exc.value.partial_tokens] == ["set", "c"]


def test_line_numbers_after_multiline_string():
    text = 'set a "1\n2\n3"\nset b x\n'
    stmts = statements(text)
    assert stmts[1].line == 4


# --- empty value '' and escaped apostrophe (ANNAHMEN T1, T2) -----------------


def test_two_apostrophes_are_an_empty_string():
    (stmt,) = statements("set image-base64 ''\n")
    assert [t.text for t in stmt.tokens] == ["set", "image-base64", ""]
    assert stmt.tokens[2].quoted


def test_two_apostrophes_among_other_values():
    assert words('set a \'\' "x" \'\'\n') == [["set", "a", "", "x", ""]]


def test_escaped_apostrophe_inside_quotes():
    assert words(r'set comment "Bob\'s rule"' + "\n") == [["set", "comment", "Bob's rule"]]


def test_escaped_apostrophe_outside_quotes():
    assert words(r"set x it\'s" + "\n") == [["set", "x", "it's"]]


def test_escaped_apostrophes_are_not_an_empty_string():
    (stmt,) = statements(r"set x \'\'" + "\n")
    assert stmt.tokens[2].text == "''"


def test_apostrophes_inside_a_word_stay_text():
    assert words("set x a''b 'abc'\n") == [["set", "x", "a''b", "'abc'"]]
