"""Zone diagram: layout for an inline SVG, without a graph library.

Source zones stand in a left column, destination zones in a right column,
both in the order of the zone matrix. Every matrix cell becomes one curve per
kind of rule (accept, deny, other, disabled); the stroke width grows with the
number of rules. The template draws the SVG from this layout, so every text
goes through Jinja's autoescaping.

The same edges feed the Mermaid diagram of the Markdown export.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from fortidoc.model.schema import MatrixCell, ZoneMatrix

KINDS = (("accept", "Accept"), ("deny", "Deny"), ("other", "Sonstige"), ("disabled", "deaktiviert"))

NODE_WIDTH = 190
NODE_HEIGHT = 30
NODE_GAP = 14
COLUMN_GAP = 320
MARGIN = 12
HEADER = 26
LABEL_CHARS = 24
STRAND_GAP = 4


@dataclass
class Node:
    name: str
    label: str
    x: float
    y: float
    width: float = NODE_WIDTH
    height: float = NODE_HEIGHT
    used: bool = True

    @property
    def text_x(self) -> float:
        return self.x + 10

    @property
    def text_y(self) -> float:
        return self.y + self.height / 2 + 4.5


@dataclass
class Edge:
    src: str
    dst: str
    title: str
    parts: list[tuple[str, int]]  # (kind, number of rules)
    paths: list[tuple[str, str]] = field(default_factory=list)  # (kind, SVG path)
    widths: list[tuple[str, float]] = field(default_factory=list)  # (kind, stroke width)


@dataclass
class Diagram:
    vdom: str
    sources: list[Node]
    targets: list[Node]
    edges: list[Edge]
    width: float
    height: float

    @property
    def strands(self) -> list[tuple[str, str, float, str]]:
        """(kind, path, width, title) of every curve, thick ones first so thin ones stay visible."""
        items = [
            (kind, path, width, e.title)
            for e in self.edges
            for (kind, path), (_, width) in zip(e.paths, e.widths)
        ]
        return sorted(items, key=lambda item: -item[2])


def _short(name: str) -> str:
    return name if len(name) <= LABEL_CHARS else name[: LABEL_CHARS - 1] + "…"


def _parts(cell: MatrixCell) -> list[tuple[str, int]]:
    return [(kind, getattr(cell, kind)) for kind, _ in KINDS if getattr(cell, kind)]


def edge_title(cell: MatrixCell) -> str:
    labels = dict(KINDS)
    counts = ", ".join(f"{n} {labels[kind]}" for kind, n in _parts(cell))
    positions = ", ".join(str(p) for p in cell.positions)
    return f"{cell.src} → {cell.dst}: {counts} (Regeln an Position {positions})"


def stroke_width(count: int) -> float:
    return round(1.5 + min(6.0, 1.6 * math.log2(count + 1)), 2)


def _column(names: list[str], x: float) -> list[Node]:
    return [
        Node(name=name, label=_short(name), x=x, y=HEADER + MARGIN + i * (NODE_HEIGHT + NODE_GAP))
        for i, name in enumerate(names)
    ]


def _fmt(value: float) -> str:
    return f"{value:.1f}".rstrip("0").rstrip(".")


def zone_diagram(matrix: ZoneMatrix) -> Diagram:
    used_src = {c.src for c in matrix.cells}
    used_dst = {c.dst for c in matrix.cells}
    sources = _column([z for z in matrix.rows if z in used_src], MARGIN)
    targets = _column([z for z in matrix.cols if z in used_dst], MARGIN + NODE_WIDTH + COLUMN_GAP)
    src_at = {n.name: n for n in sources}
    dst_at = {n.name: n for n in targets}

    # Spread the curves leaving (or entering) one node over its height.
    out_slots: dict[str, int] = {}
    in_slots: dict[str, int] = {}
    strands = [(c, kind) for c in matrix.cells for kind, _ in _parts(c)]
    out_total = {n: sum(1 for c, _ in strands if c.src == n) for n in src_at}
    in_total = {n: sum(1 for c, _ in strands if c.dst == n) for n in dst_at}

    def offset(node: Node, slot: int, total: int) -> float:
        span = min(node.height - 8, STRAND_GAP * (total - 1))
        step = span / (total - 1) if total > 1 else 0
        return node.y + node.height / 2 - span / 2 + slot * step

    edges: list[Edge] = []
    for cell in matrix.cells:
        edge = Edge(src=cell.src, dst=cell.dst, title=edge_title(cell), parts=_parts(cell))
        a, b = src_at[cell.src], dst_at[cell.dst]
        for kind, count in edge.parts:
            y1 = offset(a, out_slots.get(a.name, 0), out_total[a.name])
            y2 = offset(b, in_slots.get(b.name, 0), in_total[b.name])
            out_slots[a.name] = out_slots.get(a.name, 0) + 1
            in_slots[b.name] = in_slots.get(b.name, 0) + 1
            x1, x2 = a.x + a.width, b.x
            bend = (x2 - x1) / 2
            path = (
                f"M {_fmt(x1)} {_fmt(y1)} C {_fmt(x1 + bend)} {_fmt(y1)}, "
                f"{_fmt(x2 - bend)} {_fmt(y2)}, {_fmt(x2)} {_fmt(y2)}"
            )
            edge.paths.append((kind, path))
            edge.widths.append((kind, stroke_width(count)))
        edges.append(edge)

    rows = max(len(sources), len(targets), 1)
    height = HEADER + 2 * MARGIN + rows * NODE_HEIGHT + (rows - 1) * NODE_GAP
    width = 2 * MARGIN + 2 * NODE_WIDTH + COLUMN_GAP
    return Diagram(vdom=matrix.vdom, sources=sources, targets=targets, edges=edges, width=width, height=height)
