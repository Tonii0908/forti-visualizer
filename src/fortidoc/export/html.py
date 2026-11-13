"""HTML export: report.html, one file that works offline.

The page is rendered from a Jinja2 template with autoescaping. All data the
page script needs is embedded as one JSON block; ``encode_json`` escapes
``<``, ``>`` and ``&`` so no text from the backup can close the block or
open a tag. The script and style are embedded too; a Content-Security-Policy
allows only this one script (by its hash) and forbids every load.

The JSON block keeps large lists compact: address values and service entries
are stored once in ``values`` and ``svcs`` and referenced by index from the
policies. Field order of these tuples is documented at ``_value_entry`` and
``_service_entry``.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup

from fortidoc import __version__
from fortidoc.core.analyzer import CATEGORIES, count_by_category, zone_matrix
from fortidoc.core.resolver import value_interval
from fortidoc.export.common import (
    ADDRESS_COLUMNS,
    COVERAGE_COLUMNS,
    FINDING_COLUMNS,
    INTERFACE_COLUMNS,
    NAT_COLUMNS,
    SERVICE_COLUMNS,
    ZONE_COLUMNS,
    address_rows,
    coverage_rows,
    finding_rows,
    interface_rows,
    nat_rows,
    nat_text,
    overview_rows,
    policy_notes,
    profile_lines,
    service_rows,
    status_text,
    users_lines,
    zone_rows,
)
from fortidoc.model.schema import (
    AddressSide,
    Finding,
    ResolvedConfig,
    ResolvedPolicy,
    ResolvedValue,
    ServiceEntry,
    ServiceSide,
    VipMapping,
)

REPORT_NAME = "report.html"
SEARCH_NOTICE = "Die Suche wertet nur das Regelwerk aus, kein Routing."
FIRST_MATCH_NOTICE = (
    "Auf dem Gerät gilt die erste passende Regel. Der Report prüft keine Überdeckung; "
    "die Treffer stehen in Regelreihenfolge."
)

_PORT_PROTOCOLS = ("TCP", "UDP", "SCTP")


# ---------------------------------------------------------------------------
# Embedded assets
# ---------------------------------------------------------------------------


def _asset(name: str) -> str:
    text = resources.files("fortidoc").joinpath("templates", name).read_text(encoding="utf-8")
    return text.replace("\r\n", "\n")


@lru_cache(maxsize=1)
def report_script() -> str:
    return _asset("report.js")


@lru_cache(maxsize=1)
def report_style() -> str:
    return _asset("report.css")


def _sha256_b64(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def content_security_policy() -> str:
    return "; ".join(
        [
            "default-src 'none'",
            f"script-src 'sha256-{_sha256_b64(report_script())}'",
            "style-src 'unsafe-inline'",
            "img-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )


def encode_json(data: object) -> str:
    """JSON for a <script type="application/json"> block.

    '<', '>' and '&' are written as \\u escapes, so '</script>' or '<!--'
    cannot occur; U+2028/U+2029 are escaped for old parsers.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


# ---------------------------------------------------------------------------
# Data for the page script
# ---------------------------------------------------------------------------


def _ip_interval(text: str | None) -> list[object] | None:
    """[version, low, high] of '1.2.3.4' or '1.2.3.4-1.2.3.9' (numbers as decimal strings)."""
    if not text:
        return None
    try:
        if "-" in text:
            lo, hi = (ipaddress.ip_address(p.strip()) for p in text.split("-", 1))
        else:
            lo = hi = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if lo.version != hi.version or lo > hi:
        return None
    return [lo.version, str(int(lo)), str(int(hi))]


def _vip_intervals(vip: VipMapping) -> list[list[object]]:
    """External and mapped addresses of a VIP: both are matched by the search (assumption R1).

    Each interval ends with "extern" or "intern", so a hit can say which side matched.
    """
    found = [(_ip_interval(vip.ext_ip), "extern")] + [(_ip_interval(m), "intern") for m in vip.mapped_ips]
    return [iv + [side] for iv, side in found if iv is not None]


def _value_entry(value: ResolvedValue) -> list[object]:
    """[kind, text, note, reason, from_default (0/1), intervals, ip_version].

    intervals: [[version, low, high], ...] with low/high as decimal strings,
    empty for values the search cannot compare (FQDN, not resolvable). VIP
    intervals carry a fourth element, "extern" or "intern".
    """
    intervals: list[list[object]] = []
    if value.kind in ("network", "range"):
        iv = value_interval(value.value)
        if iv is not None:
            intervals.append([iv[0], str(iv[1]), str(iv[2])])
    elif value.kind == "vip" and value.vip is not None:
        intervals = _vip_intervals(value.vip)
    return [
        value.kind,
        value.value,
        value.note,
        value.reason,
        1 if value.from_default else 0,
        intervals,
        value.ip_version,
    ]


def _port_interval(text: str | None) -> list[int] | None:
    if not text:
        return None
    lo, _, hi = text.partition("-")
    return [int(lo), int(hi or lo)]


def _service_entry(entry: ServiceEntry) -> list[object]:
    """[kind, text, note, protocol, [port_low, port_high] | None, source ports restricted (0/1), protocol_number]."""
    ports = _port_interval(entry.dst_ports) if entry.kind == "ports" else None
    return [
        entry.kind,
        entry.value,
        entry.note,
        entry.protocol,
        ports,
        1 if entry.src_ports else 0,
        entry.protocol_number,
    ]


class _Interner:
    """Stores each distinct entry once and hands out its index."""

    def __init__(self) -> None:
        self.items: list[list[object]] = []
        self._index: dict[str, int] = {}

    def add(self, entry: list[object]) -> int:
        key = json.dumps(entry, ensure_ascii=False)
        index = self._index.get(key)
        if index is None:
            index = self._index[key] = len(self.items)
            self.items.append(entry)
        return index


def _side(side: AddressSide, values: _Interner) -> dict:
    return {
        "o": side.objects,
        "o6": side.objects6,
        "isdb": side.internet_services,
        "neg": side.negate,
        "v": [values.add(_value_entry(v)) for v in side.values],
    }


def _service(service: ServiceSide, services: _Interner) -> dict:
    return {
        "o": service.objects,
        "neg": service.negate,
        "v": [services.add(_service_entry(e)) for e in service.entries],
    }


def _policy(p: ResolvedPolicy, values: _Interner, services: _Interner) -> dict:
    return {
        "vdom": p.vdom,
        "pos": p.position,
        "id": p.policy_id,
        "name": p.name,
        "en": p.enabled,
        "status": status_text(p),
        "action": p.action,
        "ipv": p.ip_version,
        "implicit": p.implicit,
        "sec": p.section,
        "sz": p.src_zones,
        "dz": p.dst_zones,
        "si": [[r.name, r.kind] for r in p.src_interfaces],
        "di": [[r.name, r.kind] for r in p.dst_interfaces],
        "src": _side(p.source, values),
        "dst": _side(p.destination, values),
        "svc": _service(p.service, services),
        "nat": nat_text(p),
        "users": users_lines(p),
        "sched": p.schedule,
        "log": p.logtraffic,
        "prof": profile_lines(p),
        "comment": p.comments,
        "notes": policy_notes(p),
        "line": p.line,
    }


def build_report_data(resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> dict:
    """Everything the page script shows, from the same model and findings as the workbook."""
    values = _Interner()
    services = _Interner()
    policies = [_policy(p, values, services) for vdom in resolved.vdoms for p in vdom.policies]
    matrices = [
        {
            "vdom": m.vdom,
            "rows": m.rows,
            "cols": m.cols,
            "cells": [[c.src, c.dst, c.accept, c.deny, c.other, c.disabled, c.positions] for c in m.cells],
        }
        for m in zone_matrix(resolved)
    ]

    def table(headers: list[str], rows: list[list[object]]) -> dict:
        return {"headers": headers, "rows": rows}

    return {
        "created": _utc(created_at).isoformat(),
        "vdoms": [v.name for v in resolved.vdoms],
        "multiVdom": resolved.device.vdom_mode == "multi-vdom" or len(resolved.vdoms) > 1,
        "categories": CATEGORIES,
        "counts": count_by_category(findings),
        "values": values.items,
        "svcs": services.items,
        "policies": policies,
        "matrices": matrices,
        "tables": {
            "addresses": table(ADDRESS_COLUMNS, address_rows(resolved)),
            "services": table(SERVICE_COLUMNS, service_rows(resolved)),
            "nat": table(NAT_COLUMNS, nat_rows(resolved)),
            "interfaces": table(INTERFACE_COLUMNS, interface_rows(resolved)),
            "zones": table(ZONE_COLUMNS, zone_rows(resolved)),
            "findings": table(FINDING_COLUMNS, finding_rows(findings)),
            "coverage": table(COVERAGE_COLUMNS, coverage_rows(resolved)),
        },
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _utc(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.replace(microsecond=0)


@lru_cache(maxsize=1)
def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("fortidoc", "templates"),
        autoescape=True,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_report(resolved: ResolvedConfig, findings: list[Finding], created_at: datetime) -> str:
    created = _utc(created_at)
    data = build_report_data(resolved, findings, created)
    template = _environment().get_template("report.html.j2")
    device = resolved.device
    return template.render(
        device=device,
        vdoms=[v.name for v in resolved.vdoms],
        created=created.isoformat(),
        tool=f"fortidoc {__version__}",
        overview=overview_rows(resolved, findings, created),
        counts=data["counts"],
        total_findings=len(findings),
        search_notice=SEARCH_NOTICE,
        first_match_notice=FIRST_MATCH_NOTICE,
        csp=Markup(content_security_policy()),
        style=Markup(report_style()),
        script=Markup(report_script()),
        data_json=Markup(encode_json(data)),
    )


def write_report(resolved: ResolvedConfig, findings: list[Finding], path: str | Path, created_at: datetime) -> Path:
    """Write report.html (or the given file name) and return its path."""
    path = Path(path)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_report(resolved, findings, created_at))
    return path
