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
    CAT_UNUSED_FACTORY,
    CATEGORIES,
    analyze,
    count_by_category,
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
    assert "shaping-policy" not in text
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


# ---------------------------------------------------------------------------
# Factory-default objects (Stage 3 follow-up)
# ---------------------------------------------------------------------------


def test_unused_factory_objects_are_their_own_check():
    found = findings_for("res_factory_objects.conf")
    factory = {(f.object_kind, f.ref) for f in by_category(found, CAT_UNUSED_FACTORY)}
    assert factory == {
        ("Adresse", "none"),
        ("Adresse", "FABRIC_DEVICE"),
        ("Adressgruppe", "G Suite"),
        ("IPv6-Adresse", "SSLVPN_TUNNEL_IPv6_ADDR1"),
        ("Dienst", "ALL"),
        ("Dienst", "AFS3"),
        ("Dienst", "GOPHER"),
        ("Dienst", "QUAKE"),
        ("Dienstgruppe", "Web Access"),
    }
    # References are compared by name (X4): the IPv6 'all' counts as used because
    # the policy uses the IPv4 'all'.
    own = {(f.object_kind, f.ref) for f in by_category(found, CAT_UNUSED)}
    # Names are compared case-sensitively: 'gopher' is not the factory 'GOPHER'.
    assert own == {("Adresse", "net-own-unused"), ("Dienst", "svc-own-unused"), ("Dienst", "gopher")}


def test_used_factory_objects_are_not_reported():
    found = findings_for("res_factory_objects.conf")
    refs = {f.ref for f in found if f.category in (CAT_UNUSED, CAT_UNUSED_FACTORY)}
    assert "HTTPS" not in refs  # used by policy 1 and by 'Web Access'
    assert "all" not in {f.ref for f in found if f.object_kind == "Adresse"}  # IPv4 'all' is used
    assert "gmail.com" not in refs  # member of the factory group 'G Suite'


def test_factory_finding_says_it_is_a_factory_object():
    found = findings_for("res_factory_objects.conf")
    hit = next(f for f in by_category(found, CAT_UNUSED_FACTORY) if f.ref == "QUAKE")
    assert "werkseitig" in hit.detail


def test_factory_list_is_kept_per_object_kind():
    from fortidoc.model.defaults import FACTORY_OBJECTS

    assert "QUAKE" in FACTORY_OBJECTS["firewall service custom"]
    assert "gmail.com" in FACTORY_OBJECTS["firewall address"]
    assert "QUAKE" not in FACTORY_OBJECTS["firewall address"]


def test_count_by_category_lists_every_check_in_fixed_order():
    found = findings_for("res_findings.conf")
    counts = count_by_category(found)
    assert list(counts) == CATEGORIES
    assert sum(counts.values()) == len(found)
    assert counts[CAT_DISABLED] == 1
    assert counts[CAT_UNUSED_FACTORY] == 0
