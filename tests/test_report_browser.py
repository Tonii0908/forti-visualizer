"""Stage 4: report.html in a real browser (Chromium via Playwright).

Optional: runs only when the Python package ``playwright`` and a Chromium
build are available (``pip install playwright`` and ``playwright install
chromium``, or FORTIDOC_CHROMIUM=<path to chrome>). Without them the tests are
skipped; they are not a dependency of fortidoc.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import FIXTURES
from fortidoc.core.analyzer import analyze
from fortidoc.core.resolver import resolve_config
from fortidoc.export.html import REPORT_NAME, write_report
from fortidoc.parser.conf_parser import parse_file

sync_api = pytest.importorskip("playwright.sync_api")

CREATED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        candidates = [None, os.environ.get("FORTIDOC_CHROMIUM"), "/opt/pw-browsers/chromium"]
        last_error = None
        for path in candidates:
            if path is not None and not Path(path).exists():
                continue
            try:
                instance = p.chromium.launch(executable_path=path) if path else p.chromium.launch()
                break
            except Exception as exc:  # noqa: BLE001 - any launch failure means "no browser here"
                last_error = exc
        else:
            pytest.skip(f"Chromium nicht verfügbar: {last_error}")
        yield instance
        instance.close()


def build_report(name: str | Path, out: Path) -> Path:
    path = name if isinstance(name, Path) else FIXTURES / name
    tree = parse_file(path)
    resolved = resolve_config(tree)
    return write_report(resolved, analyze(tree, resolved), out / REPORT_NAME, CREATED)


class Page:
    """A loaded report with collected errors and dialogs."""

    def __init__(self, browser, report: Path):
        self.page = browser.new_page()
        self.errors: list[str] = []
        self.dialogs: list[str] = []
        self.requests: list[str] = []
        self.page.on("console", lambda m: self.errors.append(m.text) if m.type == "error" else None)
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on("request", lambda r: self.requests.append(r.url))

        def on_dialog(dialog):
            self.dialogs.append(dialog.message)
            dialog.dismiss()

        self.page.on("dialog", on_dialog)
        start = time.perf_counter()
        self.page.goto(report.as_uri())
        self.page.wait_for_selector("body[data-ready='1']", timeout=60000)
        self.load_seconds = time.perf_counter() - start

    def view(self, name: str):
        self.page.click(f"nav button[data-view='{name}']")

    def search(self, ip: str = "", side: str = "src", port: str = "", proto: str = "TCP"):
        self.view("rules")
        self.page.select_option("#s-side", side)
        self.page.select_option("#s-proto", proto)
        self.page.fill("#s-ip", ip)
        self.page.fill("#s-port", port)
        self.page.wait_for_timeout(400)

    def ids(self, container: str) -> list[str]:
        """Policy IDs of the rows shown in a result table (column 'ID')."""
        return self.page.eval_on_selector_all(
            f"#{container} table.data tbody tr", "rows => rows.map(r => r.dataset.key.split('|')[2])"
        )

    def close(self):
        self.page.close()


@pytest.fixture
def open_report(browser, tmp_path):
    pages: list[Page] = []

    def _open(name) -> Page:
        page = Page(browser, build_report(name, tmp_path))
        pages.append(page)
        return page

    yield _open
    for page in pages:
        assert page.errors == [], page.errors
        assert page.dialogs == [], page.dialogs
        assert all(url.startswith("file:") for url in page.requests), page.requests
        page.close()


# ---------------------------------------------------------------------------
# Escaping and offline
# ---------------------------------------------------------------------------


def test_xss_texts_are_shown_as_text(open_report):
    page = open_report("res_xss.conf")
    page.view("rules")
    cells = page.page.locator("#rules-main table.data tbody").inner_text()
    assert "</script><img src=x onerror=alert(1)>" in cells
    assert "<img src=x onerror=alert(5)>" in cells
    assert '"><svg onload=alert(2)>' in cells
    assert page.page.locator("img, svg, iframe").count() == 0
    page.view("interfaces")
    assert "<b>{{ 7*7 }}</b>" in page.page.locator("#view-interfaces").inner_text()


def test_every_view_renders(open_report):
    page = open_report("res_vip_central_nat.conf")
    for view in ("overview", "matrix", "rules", "addresses", "services", "interfaces", "nat", "findings", "coverage"):
        page.view(view)
        assert page.page.locator(f"#view-{view}").is_visible()


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

IMPLICIT = "0"


def test_ip_search_separates_sure_and_possible(open_report):
    page = open_report("res_search.conf")
    page.search(ip="10.10.20.15", side="src")
    assert page.ids("rules-main") == ["1", "8", "10", "11", "13", "14", "15", IMPLICIT]
    assert page.ids("rules-possible") == ["2", "3", "4", "5", "6", "12"]
    reasons = page.page.locator("#rules-possible").inner_text()
    for word in ("FQDN", "Negation", "Geo-Adresse", "dynamische Adresse", "Internet Service", "ohne subnet"):
        assert word in reasons, word


def test_ip_and_port_search(open_report):
    page = open_report("res_search.conf")
    page.search(ip="10.10.20.15", side="src", port="443", proto="TCP")
    assert page.ids("rules-main") == ["1", "8", "13", "14", "15", IMPLICIT]
    assert page.ids("rules-possible") == ["2", "3", "4", "5", "6", "10", "11", "12"]


def test_port_search_by_protocol(open_report):
    page = open_report("res_search.conf")
    page.search(port="443", proto="UDP")
    assert page.ids("rules-main") == ["8", IMPLICIT]
    assert page.ids("rules-possible") == ["10"]
    page.search(port="53", proto="any")
    assert page.ids("rules-main") == ["7", "8", "14", "15", IMPLICIT]


def test_destination_search_matches_vip_external_and_mapped(open_report):
    page = open_report("res_search.conf")
    page.search(ip="203.0.113.10", side="dst")
    sure = page.ids("rules-main")
    assert "13" in sure and "1" not in sure
    page.search(ip="192.168.50.10", side="dst")
    sure = page.ids("rules-main")
    assert "1" in sure and "13" in sure


def test_network_search_partial_overlap_is_possible(open_report):
    page = open_report("res_search.conf")
    page.search(ip="10.10.20.0/24", side="src")
    assert page.ids("rules-main") == ["1", "13", "14", IMPLICIT]
    possible = page.ids("rules-possible")
    assert "8" in possible and "10" in possible
    assert "teilweise" in page.page.locator("#rules-possible").inner_text()


def test_ipv6_search(open_report):
    page = open_report("res_search.conf")
    page.search(ip="2001:db8::1", side="src")
    assert page.ids("rules-main") == ["9", IMPLICIT]
    page.search(ip="2001:db8:0:0:0:0:0:1", side="both")
    assert "9" in page.ids("rules-main")


def test_invalid_search_input_is_reported(open_report):
    page = open_report("res_search.conf")
    page.search(ip="10.10.300.1")
    assert "Keine gültige IP-Adresse" in page.page.locator("#s-error").inner_text()


def test_routing_notice_is_shown_with_the_search(open_report):
    page = open_report("res_search.conf")
    page.view("rules")
    assert "kein Routing" in page.page.locator("#view-rules").inner_text()


# ---------------------------------------------------------------------------
# Matrix and filters
# ---------------------------------------------------------------------------


def test_matrix_cell_lists_its_rules(open_report):
    page = open_report("res_matrix.conf")
    page.view("matrix")
    cell = page.page.locator("td[data-src-zone='lan'][data-dst-zone='port4']")
    assert cell.inner_text().split() == ["2", "1"]
    cell.click()
    assert page.ids("matrix-rules") == ["10", "20", "60"]
    page.page.click("#matrix-rules button.more")
    assert page.page.locator("#view-rules").is_visible()
    assert page.ids("rules-main") == ["10", "20", "60"]
    assert "lan → port4" in page.page.locator("#cell-filter").inner_text()


def test_matrix_disabled_count_is_grey(open_report):
    page = open_report("res_matrix.conf")
    page.view("matrix")
    cell = page.page.locator("td[data-src-zone='lan'][data-dst-zone='any']")
    assert cell.locator(".n-disabled").inner_text() == "(1)"
    assert page.page.locator("td[data-src-zone='any'][data-dst-zone='any']").count() == 0


def test_filters_by_action_status_and_zone(open_report):
    page = open_report("res_matrix.conf")
    page.view("rules")
    page.page.select_option("#f-status", "disabled")
    assert page.ids("rules-main") == ["40"]
    page.page.select_option("#f-status", "")
    page.page.select_option("#f-action", "other")
    assert page.ids("rules-main") == ["70"]
    page.page.select_option("#f-action", "")
    page.page.select_option("#f-srczone", "lan")
    assert page.ids("rules-main") == ["10", "20", "40", "60"]


def test_vdom_filter(open_report):
    page = open_report("res_two_vdoms.conf")
    page.view("rules")
    options = page.page.eval_on_selector_all("#f-vdom option", "o => o.map(x => x.value)")
    assert options[1:] == [v.name for v in resolve_config(parse_file(FIXTURES / "res_two_vdoms.conf")).vdoms]
    page.page.select_option("#f-vdom", options[2])
    keys = page.page.eval_on_selector_all("#rules-main tbody tr", "rows => rows.map(r => r.dataset.key)")
    assert keys and all(k.startswith(options[2] + "|") for k in keys)


# ---------------------------------------------------------------------------
# Large backups: paging and load time
# ---------------------------------------------------------------------------


def test_tables_are_paged(open_report, tmp_path):
    from large_backup import write_large_backup

    conf = write_large_backup(tmp_path / "medium.conf", 1_500_000)
    page = open_report(conf)
    page.view("rules")
    rows = page.page.locator("#rules-main table.data tbody tr")
    assert rows.count() == 100
    total = len(resolve_config(parse_file(conf)).vdoms[0].policies)
    info = page.page.locator("#rules-main .page-info").first.inner_text()
    assert f"von {total}" in info
    page.page.locator("#rules-main .pager button.next").first.click()
    assert "Einträge 101–200" in page.page.locator("#rules-main .page-info").first.inner_text()
    page.view("addresses")
    assert page.page.locator("#view-addresses table.data tbody tr").count() == 100


def test_print_builds_the_complete_document(open_report):
    page = open_report("res_findings.conf")
    page.page.emulate_media(media="print")
    page.page.evaluate("window.dispatchEvent(new Event('beforeprint'))")
    area = page.page.locator("#print-area")
    text = area.inner_text()
    for title in ("Zonen-Matrix", "Regeln", "Adressen", "Dienste", "Interfaces", "Zonen", "NAT", "Auffälligkeiten",
                  "Nicht verarbeitet"):  # fmt: skip
        assert title in text, title
    rows = area.locator("section.pr-section").nth(1).locator("tbody tr").count()
    assert rows == len(resolve_config(parse_file(FIXTURES / "res_findings.conf")).vdoms[0].policies)
    assert page.page.locator("#cover").is_visible()
    pdf = page.page.pdf(format="A4", landscape=True)
    assert pdf[:4] == b"%PDF"


@pytest.mark.skipif(not os.environ.get("FORTIDOC_PERF"), reason="Lasttest nur mit FORTIDOC_PERF=1")
def test_large_backup_opens_quickly(browser, tmp_path):
    """Richtwert: ein 8-MB-Backup öffnet sich in etwa 3 Sekunden."""
    from large_backup import write_large_backup

    conf = write_large_backup(tmp_path / "large.conf", 8_000_000)
    report = build_report(conf, tmp_path)
    page = Page(browser, report)
    try:
        start = time.perf_counter()
        page.view("rules")
        page.page.wait_for_selector("#rules-main table.data tbody tr")
        rules_seconds = time.perf_counter() - start
        start = time.perf_counter()
        page.search(ip="10.0.1.5", side="src", port="1030")
        search_seconds = time.perf_counter() - start - 0.4
        print(
            f"\nBackup {conf.stat().st_size / 1e6:.1f} MB, report {report.stat().st_size / 1e6:.1f} MB: "
            f"geladen {page.load_seconds:.2f} s, Regeln {rules_seconds:.2f} s, Suche {search_seconds:.2f} s"
        )
        assert page.errors == []
        assert page.load_seconds < 6
        assert rules_seconds < 3
    finally:
        page.close()
