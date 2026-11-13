"""Stage 3: findings ("Auffälligkeiten") on the resolved rule set."""

from __future__ import annotations

import pytest

from conftest import FIXTURES
from fortidoc.core.analyzer import (
    CAT_ALL,
    CAT_DISABLED,
    CAT_NO_LOGGING,
    CAT_NO_SUBNET,
    CAT_UNUSED,
    analyze,
)
from fortidoc.core.resolver import resolve_config
from fortidoc.parser.conf_parser import parse_file


def findings_for(name: str):
    tree = parse_file(FIXTURES / name)
    return analyze(tree, resolve_config(tree))


@pytest.fixture(scope="module")
def findings():
    return findings_for("res_findings.conf")


def by_category(findings, category):
    return [f for f in findings if f.category == category]


def test_disabled_rules(findings):
    assert [f.ref for f in by_category(findings, CAT_DISABLED)] == ["4"]


def test_all_is_checked_on_resolved_values(findings):
    hits = {f.ref: f.detail for f in by_category(findings, CAT_ALL)}
    assert set(hits) == {"1", "2", "5"}
    assert "Quelle: 0.0.0.0/0 (all)" in hits["1"]
    assert "Dienst: IP alle Protokolle (ALL)" in hits["2"]
    assert "::/0" in hits["5"]


def test_disabled_deny_and_negated_all_are_not_all_findings(findings):
    refs = {f.ref for f in by_category(findings, CAT_ALL)}
    assert "4" not in refs  # deny
    assert "6" not in refs  # "alles außer all"


def test_address_without_subnet_is_its_own_finding(findings):
    hits = by_category(findings, CAT_NO_SUBNET)
    assert [f.ref for f in hits] == ["3"]
    assert "FABRIC_DEVICE" in hits[0].detail
    assert "3" not in {f.ref for f in by_category(findings, CAT_ALL)}


def test_accept_without_logging(findings):
    assert [f.ref for f in by_category(findings, CAT_NO_LOGGING)] == ["2"]


def test_unused_objects_search_the_whole_tree(findings):
    unused = {(f.object_kind, f.ref) for f in by_category(findings, CAT_UNUSED)}
    assert unused == {
        ("Adresse", "net-unused"),
        ("Adresse", "net-commented"),
        ("Adressgruppe", "grp-unused"),
        ("Dienst", "svc-unused"),
        ("IP-Pool", "pool-unused"),
        ("VIP", "vip-unused"),
    }


def test_findings_never_contain_raw_values_of_unevaluated_sections(findings):
    text = " ".join(f.detail for f in findings)
    assert "local-in-policy" not in text
    assert "intf" not in text


def test_central_nat_vips_are_not_unused():
    unused = {f.ref for f in by_category(findings_for("res_vip_central_nat.conf"), CAT_UNUSED)}
    assert "vip-web" not in unused
    assert "pool-1to1" in unused


def test_implicit_deny_has_no_findings(findings):
    assert all(f.ref != "0" for f in findings if f.object_kind == "Regel")


def test_findings_are_deterministic():
    a = [f.model_dump() for f in findings_for("res_findings.conf")]
    b = [f.model_dump() for f in findings_for("res_findings.conf")]
    assert a == b


def test_predefined_all_without_subnet_is_all_not_missing_subnet(tmp_path):
    conf = tmp_path / "all_no_subnet.conf"
    conf.write_text(
        """#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
config firewall address
    edit "all"
    next
end
config firewall address6
    edit "all6"
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set srcaddr6 "all6"
        set dstaddr6 "all6"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
""",
        encoding="utf-8",
    )
    tree = parse_file(conf)
    found = analyze(tree, resolve_config(tree))
    hits = by_category(found, CAT_ALL)
    assert [f.ref for f in hits] == ["1"]
    assert "0.0.0.0/0 (all)" in hits[0].detail and "::/0 (all6)" in hits[0].detail
    assert by_category(found, CAT_NO_SUBNET) == []
