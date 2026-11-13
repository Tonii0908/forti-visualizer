"""Tokenizer for FortiOS CLI configuration text.

Turns the file into a sequence of statements (a list of tokens with line
numbers) and comment lines. It knows nothing about the meaning of the
statements.

Rules (see ANNAHMEN.md, items T1-T6):
- Tokens are separated by spaces and tabs.
- Only the double quote ``"`` starts a quoted string. A quoted string may span
  many lines; lines inside it are never statements.
- Inside and outside quotes, ``\\"`` yields ``"``, ``\\'`` yields ``'`` and
  ``\\\\`` yields ``\\``. Any other backslash is kept literally.
- A token that is exactly two apostrophes (``''``) is an empty string; FortiOS
  writes empty values that way (e.g. ``set image-base64 ''``). Apostrophes do
  not quote anything else.
- Quoted and unquoted parts that touch (``ab"c d"``) form one token.
- A line whose first non-blank character is ``#`` (outside a string) is a
  comment / header line.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from fortidoc.errors import TokenizeError

_WHITESPACE = " \t\r"
# ASSUMPTION(T2): \" \' and \\ are the only escapes.
_ESCAPABLE = "\"'\\"
# ASSUMPTION(T1): '' as a whole token is an empty string.
_EMPTY_APOSTROPHES = "''"
# One token on a line without backslashes and with balanced quotes:
# plain parts and complete quoted parts, joined when they touch.
_SIMPLE_TOKEN = re.compile(r'(?:[^ \t\r"]+|"[^"]*")+')


@dataclass(frozen=True, slots=True)
class Token:
    text: str
    quoted: bool
    line: int


@dataclass(frozen=True, slots=True)
class Statement:
    """One CLI statement. ``end_line`` differs from ``line`` for multi-line strings."""

    line: int
    end_line: int
    tokens: tuple[Token, ...]

    @property
    def words(self) -> list[str]:
        return [t.text for t in self.tokens]


@dataclass(frozen=True, slots=True)
class Comment:
    line: int
    text: str  # without the leading '#'


def tokenize(text: str) -> Iterator[Statement | Comment]:
    """Yield statements and comments in file order."""
    lines = text.replace("\r\n", "\n").split("\n")
    count = len(lines)
    index = 0
    while index < count:
        line = lines[index]
        lineno = index + 1
        stripped = line.strip(_WHITESPACE)
        if not stripped:
            index += 1
            continue
        if stripped.startswith("#"):
            yield Comment(lineno, stripped[1:])
            index += 1
            continue
        if "\\" not in line:
            quotes = line.count('"')
            if quotes == 0:
                # Fast path: plain words only.
                words = _split_plain(stripped)
                yield Statement(lineno, lineno, tuple(_plain_token(w, lineno) for w in words))
                index += 1
                continue
            if quotes % 2 == 0:
                # Fast path: quotes open and close on this line, no escapes.
                yield Statement(
                    lineno,
                    lineno,
                    tuple(
                        Token(m.replace('"', ""), True, lineno)
                        if '"' in m
                        else _plain_token(m, lineno)
                        for m in _SIMPLE_TOKEN.findall(stripped)
                    ),
                )
                index += 1
                continue
        statement, index = _scan_statement(lines, index)
        yield statement


def _plain_token(word: str, lineno: int) -> Token:
    """Token for an unquoted word without escapes."""
    if word == _EMPTY_APOSTROPHES:
        return Token("", True, lineno)
    return Token(word, False, lineno)


def _split_plain(stripped: str) -> list[str]:
    words: list[str] = []
    current: list[str] = []
    for ch in stripped:
        if ch in _WHITESPACE:
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        words.append("".join(current))
    return words


def _scan_statement(lines: list[str], start: int) -> tuple[Statement, int]:
    """Character scan of one statement starting at ``lines[start]``.

    Returns the statement and the index of the next unread line.
    """
    tokens: list[Token] = []
    buf: list[str] = []
    in_token = False
    quoted = False
    escaped = False
    in_quote = False
    quote_line = 0
    token_line = start + 1
    index = start
    text = lines[index]
    pos = 0

    while True:
        length = len(text)
        while pos < length:
            ch = text[pos]
            if ch == "\\" and pos + 1 < length and text[pos + 1] in _ESCAPABLE:
                if not in_token:
                    in_token = True
                    token_line = index + 1
                buf.append(text[pos + 1])
                escaped = True
                pos += 2
                continue
            if in_quote:
                if ch == '"':
                    in_quote = False
                else:
                    buf.append(ch)
                pos += 1
                continue
            if ch in _WHITESPACE:
                if in_token:
                    tokens.append(_finish_token(buf, quoted, escaped, token_line))
                    buf, in_token, quoted, escaped = [], False, False, False
                pos += 1
                continue
            if not in_token:
                in_token = True
                token_line = index + 1
            if ch == '"':
                in_quote = True
                quoted = True
                quote_line = index + 1
            else:
                buf.append(ch)
            pos += 1

        if not in_quote:
            break
        # The quoted string continues on the next line.
        index += 1
        if index >= len(lines):
            raise TokenizeError(
                "Anführungszeichen wird bis zum Dateiende nicht geschlossen.",
                line=quote_line,
                partial_tokens=tuple(tokens),
            )
        buf.append("\n")
        text = lines[index]
        pos = 0

    if in_token:
        tokens.append(_finish_token(buf, quoted, escaped, token_line))
    return Statement(start + 1, index + 1, tuple(tokens)), index + 1


def _finish_token(buf: list[str], quoted: bool, escaped: bool, line: int) -> Token:
    text = "".join(buf)
    if not quoted and not escaped:
        return _plain_token(text, line)
    return Token(text, quoted, line)
