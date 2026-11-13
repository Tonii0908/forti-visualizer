"""Generic parser: FortiOS CLI text -> tree of config/edit/set/unset nodes.

The parser knows no section names. The only structure it interprets is the
VDOM wrapping (``config global`` and ``config vdom`` / ``edit <name>`` at the
top level), which it unwraps so that every node carries its VDOM.

The tree is lossless with one deliberate exception: secret values are
replaced by ``fortidoc.redaction.REDACTED`` while parsing (the key stays).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

from fortidoc.errors import ConfigSyntaxError, InputFormatError, TokenizeError
from fortidoc.parser.tokenizer import Comment, Statement, Token, tokenize
from fortidoc.redaction import REDACTED, is_secret_value, redact_tokens, redact_values

# ---------------------------------------------------------------------------
# Tree model
# ---------------------------------------------------------------------------


class SetNode(BaseModel):
    kind: Literal["set"] = "set"
    key: str
    values: list[str]
    line: int
    redacted: bool = False


class UnsetNode(BaseModel):
    kind: Literal["unset"] = "unset"
    key: str
    line: int


Node = Annotated[
    Union[SetNode, UnsetNode, "EditNode", "ConfigNode"],
    Field(discriminator="kind"),
]


class _Container:
    """Shared navigation helpers. They only look things up, they never interpret.

    Subclasses declare ``children`` as their last field (keeps JSON readable).
    """

    def get(self, key: str) -> SetNode | None:
        """First ``set`` with this key among the direct children."""
        for child in self.children:
            if isinstance(child, SetNode) and child.key == key:
                return child
        return None

    def get_all(self, key: str) -> list[SetNode]:
        return [c for c in self.children if isinstance(c, SetNode) and c.key == key]

    def config(self, *path: str) -> ConfigNode | None:
        """First nested ``config`` block with exactly this path."""
        wanted = list(path)
        for child in self.children:
            if isinstance(child, ConfigNode) and child.path == wanted:
                return child
        return None


class EditNode(_Container, BaseModel):
    kind: Literal["edit"] = "edit"
    name: str
    line: int
    end_line: int | None = None
    closed_by: Literal["next", "end"] | None = None
    vdom: str | None = None
    children: list[Node] = Field(default_factory=list)


class ConfigNode(_Container, BaseModel):
    kind: Literal["config"] = "config"
    path: list[str]
    line: int
    end_line: int | None = None
    vdom: str | None = None
    children: list[Node] = Field(default_factory=list)

    def edit(self, name: str) -> EditNode | None:
        for child in self.children:
            if isinstance(child, EditNode) and child.name == name:
                return child
        return None

    @property
    def edits(self) -> list[EditNode]:
        return [c for c in self.children if isinstance(c, EditNode)]


class Header(BaseModel):
    """Data from the ``#config-version=...`` line and other leading ``#k=v`` lines."""

    raw: str | None = None
    model: str | None = None
    version: str | None = None
    firmware_type: str | None = None
    build: str | None = None
    build_date: str | None = None
    opmode: str | None = None
    vdom_flag: str | None = None
    user: str | None = None
    options: dict[str, str] = Field(default_factory=dict)
    extra: dict[str, str] = Field(default_factory=dict)

    def version_tuple(self) -> tuple[int, ...] | None:
        """Numeric version for comparisons: '7.2.5' -> (7, 2, 5), '5.06' -> (5, 6).

        ASSUMPTION(H4): the two-part form of FortiOS 5.x means major.minor.
        """
        if not self.version:
            return None
        return tuple(int(part) for part in self.version.split("."))


class Vdom(BaseModel):
    name: str
    declared: bool = False
    declared_line: int | None = None
    sections: list[Node] = Field(default_factory=list)

    def config(self, *path: str) -> ConfigNode | None:
        wanted = list(path)
        for node in self.sections:
            if isinstance(node, ConfigNode) and node.path == wanted:
                return node
        return None


class SourceInfo(BaseModel):
    name: str | None = None
    sha256: str
    size_bytes: int


class ParseWarning(BaseModel):
    line: int | None = None
    message: str


class CommentLine(BaseModel):
    line: int
    text: str


class ConfigTree(BaseModel):
    source: SourceInfo | None = None
    header: Header = Field(default_factory=Header)
    vdom_mode: Literal["no-vdom", "multi-vdom"]
    global_sections: list[Node] = Field(default_factory=list)
    vdoms: list[Vdom] = Field(default_factory=list)
    # Top-level blocks in a multi-VDOM file that are neither 'config global'
    # nor 'config vdom'. Kept, never dropped.
    outside_sections: list[Node] = Field(default_factory=list)
    comments: list[CommentLine] = Field(default_factory=list)
    warnings: list[ParseWarning] = Field(default_factory=list)

    def vdom(self, name: str) -> Vdom | None:
        for v in self.vdoms:
            if v.name == name:
                return v
        return None


EditNode.model_rebuild()
ConfigNode.model_rebuild()
Vdom.model_rebuild()
ConfigTree.model_rebuild()


def iter_nodes(nodes: Iterable[Node]) -> Iterator[Node]:
    """Depth-first, file-order walk over nodes and all their descendants."""
    for node in nodes:
        yield node
        if isinstance(node, (ConfigNode, EditNode)):
            yield from iter_nodes(node.children)


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

_UTF8_BOM = b"\xef\xbb\xbf"
_BINARY_MESSAGE = (
    "Die Eingabedatei enthält Binärdaten. Vermutlich ist das Backup verschlüsselt "
    "oder es ist keine Textdatei. fortidoc verarbeitet nur unverschlüsselte Backups "
    "im FortiOS-CLI-Format (.conf). Bitte das Backup ohne Passwortschutz exportieren."
)
_ENCRYPTED_MARKER = b"#FGBK"
_ENCRYPTED_MESSAGE = (
    "Das Backup ist verschlüsselt (Kennung #FGBK am Dateianfang). fortidoc verarbeitet nur "
    "unverschlüsselte Backups im FortiOS-CLI-Format (.conf). Bitte das Backup ohne "
    "Passwortschutz exportieren."
)
# Share of control characters above which a file counts as binary.
# ASSUMPTION(E1): heuristic, no real encrypted backup was available. See ANNAHMEN.md.
_BINARY_CONTROL_RATIO = 0.01


def parse_file(path: str | Path) -> ConfigTree:
    path = Path(path)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise InputFormatError(f"Eingabedatei nicht gefunden: {path}") from None
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__
        raise InputFormatError(f"Eingabedatei kann nicht gelesen werden: {path} ({reason})") from None
    return parse_bytes(data, name=path.name)


def parse_bytes(data: bytes, name: str | None = None) -> ConfigTree:
    text, warnings = decode_config_bytes(data)
    tree = parse_text(text)
    tree.warnings = warnings + tree.warnings
    tree.source = SourceInfo(name=name, sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
    return tree


def _control_ratio(data: bytes) -> float:
    control = sum(1 for b in data if (b < 0x20 and b not in (9, 10, 13)) or b == 0x7F)
    return control / len(data)


def decode_config_bytes(data: bytes) -> tuple[str, list[ParseWarning]]:
    """Check that the bytes are a plain-text FortiOS CLI config and decode them.

    Returns the text and warnings (e.g. about the Latin-1 fallback).
    """
    warnings: list[ParseWarning] = []
    if not data.strip():
        raise InputFormatError("Die Eingabedatei ist leer.")
    if data.startswith(_UTF8_BOM):
        data = data[len(_UTF8_BOM):]
    # ASSUMPTION(E3): encrypted backups start with '#FGBK'.
    if data.lstrip().startswith(_ENCRYPTED_MARKER):
        raise InputFormatError(_ENCRYPTED_MESSAGE)
    if b"\x00" in data or _control_ratio(data) > _BINARY_CONTROL_RATIO:
        raise InputFormatError(_BINARY_MESSAGE)
    try:
        # ASSUMPTION(E2): backups are UTF-8 (optionally with BOM). See ANNAHMEN.md.
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        line = data.count(b"\n", 0, exc.start) + 1
        bad_lines = _count_invalid_utf8_lines(data)
        text = data.decode("latin-1")
        warnings.append(
            ParseWarning(
                line=line,
                message=(
                    f"Die Eingabedatei ist kein gültiges UTF-8 (erstes ungültiges Byte in Zeile {line}, "
                    f"betroffen sind {bad_lines} Zeile(n)). Sie wurde ersatzweise als Latin-1 gelesen; "
                    "Sonderzeichen können falsch dargestellt sein."
                ),
            )
        )
    first = next(line.strip() for line in text.splitlines() if line.strip())
    if first.startswith(_ENCRYPTED_MARKER.decode()):
        raise InputFormatError(_ENCRYPTED_MESSAGE)
    if not (first.startswith("#") or first.split()[0] == "config"):
        raise InputFormatError(
            "Keine FortiOS-Konfiguration erkannt: Die erste Zeile beginnt weder mit "
            "'#config-version' noch mit 'config'. Unterstützt werden nur unverschlüsselte "
            "Backups im FortiOS-CLI-Format, keine verschlüsselten oder YAML-Backups."
        )
    return text, warnings


def _count_invalid_utf8_lines(data: bytes) -> int:
    count = 0
    for raw_line in data.split(b"\n"):
        try:
            raw_line.decode("utf-8")
        except UnicodeDecodeError:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

# FGT60F-7.2.5-FW-build1517-230606 ; the model may itself contain hyphens.
# ASSUMPTION(H1): layout of the version string. See ANNAHMEN.md.
_VERSION_RE = re.compile(
    r"^(?P<model>.+?)-(?P<version>\d+\.\d+(?:\.\d+)?)-(?P<type>[A-Za-z]+)"
    r"-build(?P<build>\d+)-(?P<date>\d{6})$"
)


def parse_header(lines: Iterable[str]) -> Header:
    """Read header data from leading comment lines (with or without '#')."""
    header = Header()
    for raw_line in lines:
        line = raw_line.strip().removeprefix("#").strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "config-version":
            header.raw = value
            _parse_config_version(value, header)
        else:
            values, _ = redact_values(key, [value])
            header.extra[key] = values[0]
    return header


def _parse_config_version(value: str, header: Header) -> None:
    version_part, *option_parts = value.split(":")
    match = _VERSION_RE.match(version_part)
    if match:
        header.model = match["model"]
        header.version = match["version"]
        header.firmware_type = match["type"]
        header.build = match["build"]
        header.build_date = match["date"]
    for part in option_parts:
        key, sep, val = part.partition("=")
        if sep:
            header.options[key] = val
    header.opmode = header.options.get("opmode")
    header.vdom_flag = header.options.get("vdom")
    header.user = header.options.get("user")


# ---------------------------------------------------------------------------
# Rendering helpers (also used for error messages)
# ---------------------------------------------------------------------------

_PLAIN_TOKEN = re.compile(r'^[^\s"\'\\]+$')
_MAX_SOURCE_LINE = 160


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _maybe_quote(text: str) -> str:
    return text if _PLAIN_TOKEN.match(text) else _quote(text)


def _edit_label(name: str) -> str:
    return name if name.isdigit() else _quote(name)


def _describe(node: ConfigNode | EditNode) -> str:
    if isinstance(node, ConfigNode):
        return "config " + " ".join(_maybe_quote(p) for p in node.path)
    return "edit " + _edit_label(node.name)


def _render_source(words: list[str], unterminated: bool = False, path: tuple[str, ...] = ()) -> str:
    """One-line, redacted rendering of a statement for error messages."""
    shown = []
    for word in redact_tokens(words, path):
        if "\n" in word:
            word = word.split("\n", 1)[0] + "…"
        shown.append(word if word == REDACTED else _maybe_quote(word))
    text = " ".join(shown)
    if unterminated:
        text = f'{text} "…' if text else '"…'
    if len(text) > _MAX_SOURCE_LINE:
        text = text[: _MAX_SOURCE_LINE - 1] + "…"
    return text


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_KEYWORDS = "config, edit, set, unset, next, end"


class _Builder:
    def __init__(self) -> None:
        self.top: list[ConfigNode] = []
        self.stack: list[ConfigNode | EditNode] = []
        self.header_comments: list[Comment] = []
        self.comments: list[Comment] = []
        self.seen_statement = False

    # -- errors -------------------------------------------------------------

    def context(self) -> str:
        return " > ".join(_describe(n) for n in self.stack)

    def config_path(self) -> tuple[str, ...]:
        """Path of the open config blocks without the VDOM wrapper and edit names."""
        nodes = self.stack
        if nodes and isinstance(nodes[0], ConfigNode) and nodes[0].path in (["global"], ["vdom"]):
            nodes = nodes[1:]
        return tuple(word for n in nodes if isinstance(n, ConfigNode) for word in n.path)

    def error(self, message: str, stmt: Statement) -> ConfigSyntaxError:
        return ConfigSyntaxError(
            message, stmt.line, self.context(), _render_source(stmt.words, path=self.config_path())
        )

    # -- main loop ----------------------------------------------------------

    def run(self, text: str) -> None:
        try:
            for item in tokenize(text):
                if isinstance(item, Comment):
                    target = self.comments if self.seen_statement else self.header_comments
                    target.append(item)
                    continue
                self.seen_statement = True
                self.handle(item)
        except TokenizeError as exc:
            words = [t.text for t in exc.partial_tokens]
            raise ConfigSyntaxError(
                exc.message,
                exc.line,
                self.context(),
                _render_source(words, unterminated=True, path=self.config_path()),
            ) from None
        if self.stack:
            innermost = self.stack[-1]
            raise ConfigSyntaxError(
                f"Dateiende erreicht, aber der Block '{_describe(innermost)}' "
                f"(Zeile {innermost.line}) ist nicht geschlossen ('next' oder 'end' fehlt).",
                innermost.line,
                self.context(),
            )

    def handle(self, stmt: Statement) -> None:
        first: Token = stmt.tokens[0]
        keyword = None if first.quoted else first.text
        args = stmt.words[1:]
        parent = self.stack[-1] if self.stack else None

        if keyword == "config":
            if not args:
                raise self.error("'config' ohne Pfad.", stmt)
            node = ConfigNode(path=args, line=stmt.line)
            if parent is None:
                self.top.append(node)
            else:
                parent.children.append(node)
            self.stack.append(node)

        elif keyword == "edit":
            # ASSUMPTION(P3): an edit takes exactly one name/id.
            if not args:
                raise self.error("'edit' ohne Namen.", stmt)
            if len(args) > 1:
                raise self.error("'edit' mit mehr als einem Namen.", stmt)
            if isinstance(parent, EditNode):
                raise self.error("'edit' innerhalb eines offenen 'edit' ('next' fehlt?).", stmt)
            if parent is None:
                raise self.error("'edit' außerhalb eines 'config'-Blocks.", stmt)
            node = EditNode(name=args[0], line=stmt.line)
            parent.children.append(node)
            self.stack.append(node)

        elif keyword == "set":
            if parent is None:
                raise self.error("'set' außerhalb eines Blocks.", stmt)
            if not args:
                raise self.error("'set' ohne Schlüssel.", stmt)
            values, redacted = redact_values(args[0], args[1:], self.config_path())
            parent.children.append(SetNode(key=args[0], values=values, line=stmt.line, redacted=redacted))

        elif keyword == "unset":
            if parent is None:
                raise self.error("'unset' außerhalb eines Blocks.", stmt)
            if len(args) != 1:
                raise self.error("'unset' erwartet genau einen Schlüssel.", stmt)
            parent.children.append(UnsetNode(key=args[0], line=stmt.line))

        elif keyword == "next":
            if args:
                raise self.error("'next' erwartet keine Argumente.", stmt)
            if not isinstance(parent, EditNode):
                raise self.error("'next' ohne offenes 'edit'.", stmt)
            parent.end_line = stmt.line
            parent.closed_by = "next"
            self.stack.pop()

        elif keyword == "end":
            if args:
                raise self.error("'end' erwartet keine Argumente.", stmt)
            if isinstance(parent, EditNode):
                # ASSUMPTION(P2): an 'end' directly after an edit closes the edit and its config.
                parent.end_line = stmt.line
                parent.closed_by = "end"
                self.stack.pop()
                parent = self.stack[-1] if self.stack else None
            if not isinstance(parent, ConfigNode):
                raise self.error("'end' ohne offenen 'config'-Block.", stmt)
            parent.end_line = stmt.line
            self.stack.pop()

        else:
            # ASSUMPTION(P1): backups only contain the six keywords; anything else is an error.
            shown = _render_source([first.text])[:40]
            raise self.error(f"Unbekannter Befehl '{shown}'. Erwartet: {_KEYWORDS}.", stmt)


def _assign_vdom(nodes: Iterable[Node], vdom: str | None) -> None:
    for node in iter_nodes(nodes):
        if isinstance(node, (ConfigNode, EditNode)):
            node.vdom = vdom


def _path_label(node: ConfigNode) -> str:
    return " ".join(node.path)


def parse_text(text: str) -> ConfigTree:
    """Parse configuration text into a ConfigTree. Raises ConfigSyntaxError."""
    builder = _Builder()
    builder.run(text)

    header = parse_header(c.text for c in builder.header_comments)
    warnings: list[ParseWarning] = []
    comments = [
        CommentLine(line=c.line, text=REDACTED if is_secret_value([c.text]) or "ENC " in c.text else c.text)
        for c in builder.header_comments + builder.comments
        if not _is_header_line(c.text)
    ]

    if header.raw is None:
        warnings.append(ParseWarning(message="Keine Kopfzeile '#config-version=…' gefunden. Modell und Version sind unbekannt."))
    elif header.model is None:
        warnings.append(ParseWarning(line=1, message="Die Kopfzeile '#config-version' hat ein unbekanntes Format. Modell und Version sind unbekannt."))

    # ASSUMPTION(V1): multi-VDOM files are recognised by top-level 'config vdom'/'config global'.
    multi = any(n.path in (["vdom"], ["global"]) for n in builder.top)
    tree = ConfigTree(header=header, vdom_mode="multi-vdom" if multi else "no-vdom", comments=comments)

    if multi:
        _assemble_multi_vdom(builder.top, tree, warnings)
        if header.vdom_flag == "0":
            warnings.append(ParseWarning(message="Die Kopfzeile meldet vdom=0, die Datei enthält aber VDOM-Blöcke. Die VDOM-Blöcke werden ausgewertet."))
    else:
        # ASSUMPTION(V2): without VDOMs every section belongs to VDOM root (no global split here).
        _assign_vdom(builder.top, "root")
        tree.vdoms = [Vdom(name="root", sections=list(builder.top))]
        if header.vdom_flag not in (None, "0"):
            warnings.append(ParseWarning(message=f"Die Kopfzeile meldet vdom={header.vdom_flag}, die Datei enthält aber keine VDOM-Blöcke. Alle Abschnitte werden dem VDOM root zugeordnet."))

    if not builder.top:
        warnings.append(ParseWarning(message="Die Datei enthält keine 'config'-Abschnitte."))
    tree.warnings = warnings
    return tree


def _is_header_line(text: str) -> bool:
    key, sep, _ = text.strip().partition("=")
    return bool(sep) and " " not in key


def _assemble_multi_vdom(top: list[ConfigNode], tree: ConfigTree, warnings: list[ParseWarning]) -> None:
    vdoms: dict[str, Vdom] = {}
    for block in top:
        if block.path == ["global"]:
            _assign_vdom(block.children, None)
            tree.global_sections.extend(block.children)
        elif block.path == ["vdom"]:
            for child in block.children:
                if not isinstance(child, EditNode):
                    warnings.append(ParseWarning(line=child.line, message="Eintrag in 'config vdom' ohne 'edit <vdom>'. Er wird unter 'außerhalb' geführt."))
                    _assign_vdom([child], None)
                    tree.outside_sections.append(child)
                    continue
                vdom = vdoms.get(child.name)
                if vdom is None:
                    vdom = vdoms[child.name] = Vdom(name=child.name)
                # ASSUMPTION(V1): the declaration is an 'edit <vdom>' without content.
                if not child.children and not vdom.declared:
                    vdom.declared = True
                    vdom.declared_line = child.line
                _assign_vdom(child.children, child.name)
                vdom.sections.extend(child.children)
        else:
            warnings.append(ParseWarning(line=block.line, message=f"Abschnitt 'config {_path_label(block)}' steht außerhalb von 'config global' und 'config vdom'. Er wird unter 'außerhalb' geführt."))
            _assign_vdom([block], None)
            tree.outside_sections.append(block)
    for vdom in vdoms.values():
        if not vdom.declared:
            warnings.append(ParseWarning(message=f"VDOM '{vdom.name}' hat einen Konfigurationsblock, wurde aber nicht mit leerem 'edit {vdom.name}' deklariert."))
    tree.vdoms = list(vdoms.values())


# ---------------------------------------------------------------------------
# Back to CLI text (used to prove the tree is lossless)
# ---------------------------------------------------------------------------


def tree_to_conf(tree: ConfigTree) -> str:
    """Render the tree as FortiOS CLI text. Re-parsing yields the same tree.

    Redacted values are written as ``ENC <placeholder>`` so they stay
    recognisable as secrets; the original value is not available.
    """
    out: list[str] = []
    if tree.header.raw is not None:
        out.append(f"#config-version={tree.header.raw}")
    out.extend(f"#{k}={v}" for k, v in tree.header.extra.items())

    if tree.vdom_mode == "multi-vdom":
        out.append("config vdom")
        for vdom in tree.vdoms:
            if vdom.declared:
                out += [f"edit {_maybe_quote(vdom.name)}", "next"]
        out.append("end")
        if tree.global_sections:
            out.append("config global")
            _render_nodes(tree.global_sections, 0, out)
            out.append("end")
        for vdom in tree.vdoms:
            if vdom.sections:
                out += ["config vdom", f"edit {_maybe_quote(vdom.name)}"]
                _render_nodes(vdom.sections, 0, out)
                out += ["next", "end"]
        _render_nodes(tree.outside_sections, 0, out)
    else:
        for vdom in tree.vdoms:
            _render_nodes(vdom.sections, 0, out)
    return "\n".join(out) + "\n"


def _render_nodes(nodes: Iterable[Node], depth: int, out: list[str]) -> None:
    pad = "    " * depth
    for node in nodes:
        if isinstance(node, SetNode):
            if node.redacted:
                out.append(f"{pad}set {_maybe_quote(node.key)} ENC {_quote(REDACTED)}")
            else:
                values = "".join(" " + _quote(v) for v in node.values)
                out.append(f"{pad}set {_maybe_quote(node.key)}{values}")
        elif isinstance(node, UnsetNode):
            out.append(f"{pad}unset {_maybe_quote(node.key)}")
        elif isinstance(node, EditNode):
            out.append(f"{pad}edit {_edit_label(node.name)}")
            _render_nodes(node.children, depth + 1, out)
            if node.closed_by != "end":
                out.append(f"{pad}next")
            # closed_by == "end": the parent's 'end' closes this edit too.
        else:
            out.append(pad + _describe(node))
            _render_nodes(node.children, depth + 1, out)
            out.append(f"{pad}end")
