"""Stage 5: shadowed rules ("Überdeckte Regel")."""

from __future__ import annotations

import pytest

from conftest import FIXTURES
from fortidoc.core.analyzer import CAT_SHADOWED, CATEGORIES, analyze
from fortidoc.core.resolver import resolve_config
from fortidoc.core.shadow import find_shadowed
from fortidoc.parser.conf_parser import parse_file


@pytest.fixture(scope="module")
def shadowed():
    resolved = resolve_config(parse_file(FIXTURES / "res_shadow.conf"))
    return {s.shadowed.policy_id: s for s in find_shadowed(resolved)}


def test_rule_inside_an_earlier_broader_rule_is_shadowed(shadowed):
    hit = shadowed["2"]
    assert hit.by.policy_id == "1"
    assert hit.different_action  # accept before deny: the deny never applies


def test_other_network_is_not_shadowed(shadowed):
    assert "3" not in shadowed


def test_negation_and_fqdn_are_not_checked(shadowed):
    assert "4" not in shadowed
    assert "5" not in shadowed


def test_disabled_rule_schedule_and_groups_do_not_shadow(shadowed):
    # 10 is disabled, 11 only applies in the office schedule, 12 only for a group:
    # none of them takes all traffic of 13.
    assert "13" not in shadowed


def test_any_interface_and_all_tcp_cover_later_rules(shadowed):
    # 14 (srcintf any, ALL_TCP) comes after 13; 15 and 16 are inside 13 or 14.
    assert "14" not in shadowed
    assert shadowed["15"].by.policy_id == "13"  # HTTPS with source ports inside HTTPS
    assert shadowed["16"].by.policy_id == "14"  # SSH via port2 inside any/ALL_TCP
    assert not shadowed["16"].different_action


def test_only_earlier_rules_shadow_and_the_first_is_reported(shadowed):
    assert "13" not in shadowed  # 14 is broader but comes later
    assert shadowed["15"].by.policy_id == "13"  # 14 also covers 15, 13 is the first


def test_union_of_values_covers(shadowed):
    assert shadowed["21"].by.policy_id == "20"


def test_source_port_restriction_does_not_cover_all_source_ports(shadowed):
    assert "22" not in shadowed


def test_shadowed_rules_are_a_finding():
    tree = parse_file(FIXTURES / "res_shadow.conf")
    findings = analyze(tree, resolve_config(tree))
    hits = {f.ref: f.detail for f in findings if f.category == CAT_SHADOWED}
    assert set(hits) == {"2", "15", "16", "21"}
    assert "ID 1" in hits["2"] and "nie" in hits["2"]
    assert CAT_SHADOWED in CATEGORIES


def test_rules_of_other_vdoms_are_not_compared():
    resolved = resolve_config(parse_file(FIXTURES / "res_two_vdoms.conf"))
    for s in find_shadowed(resolved):
        assert s.shadowed.vdom == s.by.vdom


def test_implicit_deny_is_never_shadowed_or_shadowing():
    for name in ("res_shadow.conf", "res_findings.conf", "res_matrix.conf"):
        for s in find_shadowed(resolve_config(parse_file(FIXTURES / name))):
            assert not s.shadowed.implicit and not s.by.implicit


def test_large_rule_set_is_fast(tmp_path):
    import time

    from large_backup import write_large_backup

    resolved = resolve_config(parse_file(write_large_backup(tmp_path / "m.conf", 2_000_000)))
    start = time.perf_counter()
    find_shadowed(resolved)
    assert time.perf_counter() - start < 10


# ---------------------------------------------------------------------------
# Keys that restrict the earlier rule (assumption U6)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def restricting():
    resolved = resolve_config(parse_file(FIXTURES / "res_shadow_restricting.conf"))
    return {(s.shadowed.section, s.shadowed.policy_id): s for s in find_shadowed(resolved)}


def test_restricting_keys_are_listed():
    from fortidoc.core.shadow import RESTRICTING_KEYS

    for key in (
        "fsso-groups", "devices", "src-vendor-mac", "ztna-ems-tag", "ztna-geo-tag",
        "ztna-status", "tos", "ha-mgmt-intf-only",
    ):  # fmt: skip
        assert key in RESTRICTING_KEYS


def test_earlier_rule_with_restricting_key_does_not_shadow(restricting):
    assert ("firewall policy", "2") not in restricting  # 1 only for FSSO groups
    assert ("firewall policy", "4") not in restricting  # 3 only for ZTNA tags
    assert ("firewall local-in-policy", "2") not in restricting  # 1 only on the HA management interface


def test_other_unknown_keys_still_shadow_with_a_note(restricting):
    hit = restricting[("firewall policy", "6")]
    assert hit.by.policy_id == "5"
    assert any("synthetic-unknown-key" in note for note in hit.notes)
