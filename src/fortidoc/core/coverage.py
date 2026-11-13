"""Report of what fortidoc does not evaluate ("Nicht verarbeitet").

Counts every config section that is not evaluated and every unknown key in
evaluated sections. Only names and counts are recorded, never values: raw
values of sections that fortidoc does not evaluate must not reach any output.
"""

from __future__ import annotations

from fortidoc.model.schema import Coverage, UnknownKey, UnprocessedSection
from fortidoc.parser.conf_parser import ConfigNode, EditNode


class CoverageCollector:
    def __init__(self) -> None:
        self._sections: list[UnprocessedSection] = []
        self._keys: dict[tuple[str, str], UnknownKey] = {}

    def unprocessed(self, scope: str, node) -> None:
        if isinstance(node, ConfigNode):
            entries = sum(1 for c in node.children if isinstance(c, EditNode))
            path = " ".join(node.path)
        else:  # a stray set/unset/edit at section level
            entries = 0
            path = f"{node.kind} {getattr(node, 'key', None) or getattr(node, 'name', '')}".strip()
        self._sections.append(UnprocessedSection(scope=scope, path=path, entries=entries, line=node.line))

    def unknown_key(self, section: str, key: str, scope: str) -> None:
        entry = self._keys.get((section, key))
        if entry is None:
            entry = self._keys[(section, key)] = UnknownKey(section=section, key=key, count=0)
        entry.count += 1
        if scope not in entry.scopes:
            entry.scopes.append(scope)

    def result(self) -> Coverage:
        keys = sorted(self._keys.values(), key=lambda k: (k.section, k.key))
        return Coverage(unprocessed_sections=list(self._sections), unknown_keys=keys)
