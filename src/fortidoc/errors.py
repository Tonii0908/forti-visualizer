"""Exception types. All user-facing messages are German.

Messages must never contain secret values: every code path that puts input
text into a message goes through ``fortidoc.redaction`` first.
"""

from __future__ import annotations


class FortidocError(Exception):
    """Base class for all errors reported to the user."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message


class InputFormatError(FortidocError):
    """The input is not a readable, unencrypted FortiOS CLI configuration."""


class TokenizeError(FortidocError):
    """Raised by the tokenizer; the parser converts it into ConfigSyntaxError.

    ``partial_tokens`` holds the tokens of the broken statement that were
    complete before the error (used for a redacted context line).
    """

    def __init__(self, message: str, line: int, partial_tokens: tuple = ()) -> None:
        super().__init__(message)
        self.line = line
        self.partial_tokens = partial_tokens


class ConfigSyntaxError(FortidocError):
    """Syntax error with line number, block context and the (redacted) line."""

    def __init__(
        self,
        message: str,
        line: int,
        context: str = "",
        source_line: str | None = None,
    ) -> None:
        self.line = line
        self.context = context
        self.source_line = source_line
        parts = [f"Syntaxfehler in Zeile {line}: {message}"]
        if context:
            parts.append(f"  Kontext: {context}")
        if source_line:
            parts.append(f"  Zeile {line}: {source_line}")
        super().__init__("\n".join(parts))
        # Keep the bare message for programmatic checks.
        self.message = message

    def __str__(self) -> str:
        return self.args[0]

    def __repr__(self) -> str:
        return f"ConfigSyntaxError(line={self.line}, message={self.message!r})"
