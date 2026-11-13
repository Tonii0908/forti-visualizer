"""Stage 2: resolve() yields the expected result for every rule of the fixtures."""

from __future__ import annotations

import ipaddress
import json

import pytest

from conftest import FIXTURES, SECRET_MARKER, valid_fixtures
from fortidoc.core.resolver import resolve_config
from fortidoc.parser.conf_parser import parse_file


def load(name: str):
    return resolve_config(parse_file(FIXTURES / name))


def vals(side) -> list[str]:
    return [v.value for v in side.values]


def kinds(side) -> list[str]:
    return [v.kind for v in side.values]


def svc(policy) -> list[str]:
    return [e.value for e in policy.service.entries]


def ids(vdom) -> list[tuple[str, str]]:
    return [(p.section, p.policy_id) for p in vdom.policies]


# --- device without VDOMs -----------------------------------------------------


@pytest.fixture(scope="module")
def no_vdom():
    return load("res_no_vdom.conf")


def test_device_info(no_vdom):
    d = no_vdom.device
    assert (d.model, d.version, d.build, d.vdom_mode) == ("FGT60F", "7.2.5", "1517", "no-vdom")
    assert d.input_name == "res_no_vdom.conf"
    assert len(d.input_sha256) == 64
    assert [v.name for v in no_vdom.vdoms] == ["root"]


def test_policies_in_file_order_with_implicit_deny_last(no_vdom):
    root = no_vdom.vdom("root")
    assert [p.policy_id for p in root.policies] == ["10", "3", "7", "0"]
    assert [p.position for p in root.policies] == [1, 2, 3, 4]
    implicit = root.policies[-1]
    assert implicit.implicit
    assert implicit.action == "deny"
    assert implicit.name == "Implizites Deny"
    assert implicit.src_zones == ["any"] and implicit.dst_zones == ["any"]
    assert not any(p.implicit for p in root.policies[:-1])


def test_policy_resolution_full(no_vdom):
    p = no_vdom.vdom("root").policy("10")
    assert p.name == "clients-web"
    assert p.uuid == "bbbbbbbb-0000-0000-0000-000000000010"
    assert p.action == "accept" and p.status == "enable" and p.enabled
    assert p.ip_version == "4"
    assert [(i.name, i.kind, i.zone) for i in p.src_interfaces] == [("LAN", "zone", "LAN")]
    assert p.src_zones == ["LAN"]
    assert p.dst_zones == ["wan1"]
    assert p.source.objects == ["grp-clients"]
    assert vals(p.source) == ["10.10.10.0/24", "10.20.0.0/24"]
    assert p.source.values[0].origin == ["grp-clients", "net-lan"]
    assert kinds(p.source) == ["network", "network"]
    assert vals(p.destination) == ["0.0.0.0/0"]
    assert svc(p) == ["TCP/443", "TCP/53", "UDP/53"]
    assert p.nat.enabled and p.nat.mode == "interface"
    assert p.logtraffic == "all"
    assert p.profiles == {"av-profile": "default", "ssl-ssh-profile": "certificate-inspection"}
    assert p.comments == "outbound web"
    assert p.schedule == "always"
    assert "status" in p.defaults_applied
    assert "action" not in p.defaults_applied


def test_unknown_policy_key_is_kept(no_vdom):
    p = no_vdom.vdom("root").policy("3")
    assert p.unknown_keys == {"some-future-setting": ["kept"]}
    assert not p.nat.enabled and p.nat.mode == "none"
    assert p.logtraffic == "utm" and "logtraffic" in p.defaults_applied


def test_users_groups_and_interface_zone(no_vdom):
    p = no_vdom.vdom("root").policy("7")
    assert p.users == ["alice"] and p.groups == ["staff"]
    assert [(i.name, i.kind, i.zone) for i in p.src_interfaces] == [("lag1", "interface", "lag1")]
    assert svc(p) == ["IP alle Protokolle"]


def test_interfaces(no_vdom):
    by_name = {i.name: i for i in no_vdom.interfaces}
    assert by_name["wan1"].type == "physical" and by_name["wan1"].type_label == "physisch"
    assert by_name["wan1"].ip == "192.0.2.1/24"
    assert by_name["wan1"].zone == "wan1"
    assert by_name["internal"].type_label == "Switch" and by_name["internal"].zone == "LAN"
    vlan = by_name["vlan20"]
    assert (vlan.type, vlan.type_label, vlan.parent, vlan.vlan_id, vlan.zone) == ("vlan", "VLAN", "internal", 20, "LAN")
    assert by_name["lag1"].type_label == "Aggregat" and by_name["lag1"].members == ["port3", "port4"]
    assert by_name["lo-mgmt"].type_label == "Loopback"
    assert all(i.vdom == "root" for i in no_vdom.interfaces)


def test_zones(no_vdom):
    zones = {z.name: z for z in no_vdom.vdom("root").zones}
    assert zones["LAN"].kind == "zone"
    assert zones["LAN"].interfaces == ["internal", "vlan20"]
    assert zones["LAN"].intrazone == "deny"
    assert zones["wan1"].kind == "interface" and zones["wan1"].interfaces == ["wan1"]
    assert "internal" not in zones


def test_coverage(no_vdom):
    sections = {(s.scope, s.path) for s in no_vdom.coverage.unprocessed_sections}
    assert ("root", "system global") in sections
    assert ("root", "log setting") in sections
    assert not any(path == "firewall policy" for _, path in sections)
    keys = {(k.section, k.key): k.count for k in no_vdom.coverage.unknown_keys}
    assert keys[("firewall policy", "some-future-setting")] == 1
    assert keys[("system interface", "role")] == 1
    assert keys[("system interface", "config ipv6")] == 1


def test_only_evaluated_sections_reach_the_model(no_vdom):
    data = no_vdom.model_dump_json()
    assert "fw-res-01" not in data  # hostname from 'system global' (not evaluated)
    assert "2001:db8:10::1" not in data  # nested 'config ipv6' (not evaluated)
    assert "kept" in data  # unknown key of an evaluated section stays in the model


# --- two VDOMs ----------------------------------------------------------------


@pytest.fixture(scope="module")
def two_vdoms():
    return load("res_two_vdoms.conf")


def test_interface_vdom_comes_from_set_vdom(two_vdoms):
    by_name = {i.name: i for i in two_vdoms.interfaces}
    assert by_name["port1"].vdom == "root"
    assert by_name["port2"].vdom == "dmz"
    assert by_name["port3"].vdom == "root"
    assert "vdom" in by_name["port3"].defaults_applied


def test_each_vdom_has_its_policies_and_implicit_deny(two_vdoms):
    root, dmz = two_vdoms.vdoms
    assert [p.policy_id for p in root.policies] == ["1", "2", "0"]
    assert [p.policy_id for p in dmz.policies] == ["1", "0"]
    assert all(p.vdom == "dmz" for p in dmz.policies)
    assert vals(dmz.policy("1").destination) == ["172.16.20.10/32"]


def test_interface_of_other_vdom_is_flagged(two_vdoms):
    p = two_vdoms.vdom("root").policy("2")
    ref = p.src_interfaces[0]
    assert (ref.name, ref.kind, ref.vdom) == ("port2", "interface", "dmz")
    assert any("dmz" in n for n in p.notes)
    assert not two_vdoms.vdom("root").policy("1").notes


# --- defaults -----------------------------------------------------------------


@pytest.fixture(scope="module")
def defaults():
    return load("res_policy_defaults.conf")


def test_policy_without_action_and_status(defaults):
    p = defaults.vdom("root").policy("1")
    assert p.action == "deny"
    assert p.status == "enable" and p.enabled
    assert {"action", "status"} <= set(p.defaults_applied)


def test_disabled_policy(defaults):
    p = defaults.vdom("root").policy("2")
    assert p.status == "disable" and not p.enabled and p.action == "accept"


def test_unset_restores_default_and_missing_schedule_is_noted(defaults):
    p = defaults.vdom("root").policy("3")
    assert p.action == "deny" and "action" in p.defaults_applied
    assert p.schedule is None
    assert any("Schedule" in n for n in p.notes)


# --- address groups -------------------------------------------------------------


@pytest.fixture(scope="module")
def groups():
    return load("res_addrgrp_nested.conf")


def test_nested_groups_resolve_depth_first(groups):
    p = groups.vdom("root").policy("1")
    assert vals(p.source) == ["10.1.0.0/24", "10.3.0.1-10.3.0.20", "10.2.0.0/24", "10.1.0.10/32"]
    assert kinds(p.source) == ["network", "range", "network", "network"]
    assert p.source.values[0].origin == ["grp-outer", "grp-middle", "grp-inner", "net-a"]


def test_circular_group_is_marked(groups):
    p = groups.vdom("root").policy("1")
    assert vals(p.destination)[:2] == ["10.1.0.0/24", "10.2.0.0/24"]
    loop = p.destination.values[2]
    assert loop.kind == "unresolvable"
    assert "Zirkelbezug" in loop.note
    assert loop.origin == ["grp-loop-a", "grp-loop-b", "grp-loop-a"]


def test_exclude_member_is_subtracted(groups):
    p = groups.vdom("root").policy("2")
    assert vals(p.source) == ["10.0.0.0/16", "10.1.1.0-10.3.0.0", "10.3.0.21-10.255.255.255"]
    assert kinds(p.source) == ["network", "range", "range"]
    total = sum(
        int(ipaddress.ip_address(v.split("-")[1])) - int(ipaddress.ip_address(v.split("-")[0])) + 1
        if "-" in v
        else ipaddress.ip_network(v).num_addresses
        for v in vals(p.source)
    )
    assert total == 2**24 - 256 - 20


def test_exclusion_with_fqdn_and_disabled_exclude(groups):
    p = groups.vdom("root").policy("2")
    assert vals(p.destination) == [
        "10.1.0.0-10.1.0.9",
        "10.1.0.11-10.1.0.255",
        "x.example.com",
        "10.1.0.0/24",
    ]
    notes = " ".join(v.note or "" for v in p.destination.values)
    assert "FQDN" in notes
    assert "exclude" in notes


def test_missing_object_is_marked(groups):
    p = groups.vdom("root").policy("3")
    assert vals(p.source) == ["10.1.0.0/24", "does-not-exist"]
    missing = p.source.values[1]
    assert missing.kind == "unresolvable" and "nicht gefunden" in missing.note


# --- address types --------------------------------------------------------------


@pytest.fixture(scope="module")
def types():
    return load("res_address_types.conf")


def test_address_types_source(types):
    p = types.vdom("root").policy("1")
    assert [(v.kind, v.value) for v in p.source.values] == [
        ("network", "10.0.1.0/24"),
        ("network", "10.0.1.0/24"),
        ("range", "10.0.9.1-10.0.9.50"),
        ("network", "10.8.0.0/16"),
        ("unresolvable", "10.0.0.5/255.0.255.255"),
    ]
    assert "Hostbits" in p.source.values[1].note
    assert "Wildcard" in p.source.values[4].note


def test_address_types_destination(types):
    p = types.vdom("root").policy("1")
    got = [(v.kind, v.value) for v in p.destination.values]
    assert got == [
        ("fqdn", "www.example.com"),
        ("unresolvable", "DE"),
        ("unresolvable", "a-dynamic"),
        ("network", "10.0.2.0/24"),
        ("unresolvable", "a-ifsubnet-unknown"),
        ("unresolvable", "00:11:22:33:44:55"),
        ("unresolvable", "a-future-type"),
    ]
    notes = [v.note for v in p.destination.values]
    assert "Geo" in notes[1]
    assert "cloud-connector" in notes[2]
    assert "no-such-port" in notes[4]
    assert "MAC" in notes[5]
    assert "something-new" in notes[6]


def test_address_object_tables(types):
    root = types.vdom("root")
    objs = {(a.category, a.name): a for a in root.addresses}
    assert vals(objs[("address6", "a6-prefix")]) == ["2001:db8:1::/48"]
    assert objs[("address6", "a6-prefix")].values[0].ip_version == 6
    assert vals(objs[("address6", "a6-range")]) == ["2001:db8:2::1-2001:db8:2::ff"]
    assert vals(objs[("addrgrp6", "g6")]) == ["2001:db8:1::/48", "2001:db8:2::1-2001:db8:2::ff"]
    assert objs[("addrgrp6", "g6")].members == ["a6-prefix", "a6-range"]
    assert vals(objs[("address", "all")]) == ["0.0.0.0/0"]
    assert objs[("address", "a-iprange")].type == "iprange"


# --- services -----------------------------------------------------------------


@pytest.fixture(scope="module")
def services():
    return load("res_services.conf")


def test_service_multiple_ranges_and_source_ports(services):
    p = services.vdom("root").policy("1")
    assert svc(p) == [
        "TCP/22 (Quellport 1024-65535)",
        "TCP/2222 (Quellport 40000)",
        "UDP/514 (Quellport 514)",
        "SCTP/2905",
    ]
    first = p.service.entries[0]
    assert (first.protocol, first.dst_ports, first.src_ports) == ("TCP", "22", "1024-65535")
    assert first.origin == ["SRC-PORTS"]


def test_service_groups_nested_and_circular(services):
    p = services.vdom("root").policy("2")
    assert svc(p)[:6] == ["TCP/80", "TCP/443", "TCP/8080-8090", "ICMP Typ 8", "IP-Protokoll 47", "ICMP Typ 8"]
    loop = p.service.entries[6]
    assert loop.kind == "unresolvable" and "Zirkelbezug" in loop.note
    assert p.service.entries[0].origin == ["grp-nested", "grp-web", "WEB-MULTI"]


def test_icmp_ip_and_broken_services(services):
    p = services.vdom("root").policy("3")
    entries = p.service.entries
    assert [e.value for e in entries[:4]] == [
        "ICMP Typ 3 Code 4",
        "ICMP alle Typen",
        "ICMP6 Typ 128",
        "IP alle Protokolle",
    ]
    assert (entries[0].icmp_type, entries[0].icmp_code) == (3, 4)
    broken = entries[4:6]
    assert all(e.kind == "unresolvable" for e in broken)
    assert [e.value for e in broken] == ["TCP 70000", "TCP abc"]
    assert entries[6].kind == "unresolvable" and "keine Ports" in entries[6].note
    assert entries[7].value == "NO-SUCH-SERVICE" and "nicht gefunden" in entries[7].note
    assert len(entries) == 8


# --- VIP and NAT ---------------------------------------------------------------


@pytest.fixture(scope="module")
def vip_classic():
    return load("res_vip_classic.conf")


def test_vip_port_forward_in_policy(vip_classic):
    p = vip_classic.vdom("root").policy("1")
    (value,) = p.destination.values
    assert value.kind == "vip"
    assert value.value == "203.0.113.10:8443/TCP (wan1) → 10.0.2.10:443"
    assert value.vip.mapped_ips == ["10.0.2.10"]
    assert value.vip.portforward


def test_vip_group_and_ranges(vip_classic):
    p = vip_classic.vdom("root").policy("2")
    assert vals(p.destination) == [
        "203.0.113.10:8443/TCP (wan1) → 10.0.2.10:443",
        "203.0.113.11 (any) → 10.0.2.11",
        "203.0.113.12-203.0.113.13:5000-5010/UDP (wan1) → 10.0.2.20-10.0.2.21:6000-6010",
    ]
    assert p.destination.values[1].origin == ["vipgrp-dmz", "vip-static"]


def test_classic_vip_table_and_static_default(vip_classic):
    root = vip_classic.vdom("root")
    assert not root.central_nat
    vips = {v.name: v for v in root.vips}
    assert set(vips) == {"vip-web", "vip-static", "vip-udp-range"}
    assert vips["vip-static"].ext_intf == "any"
    assert "extintf" in vips["vip-static"].defaults_applied


def test_ippool_nat(vip_classic):
    p = vip_classic.vdom("root").policy("3")
    assert p.nat.enabled and p.nat.ippool and p.nat.mode == "pool"
    assert [(pool.name, pool.value) for pool in p.nat.pools] == [
        ("pool-out", "203.0.113.20-203.0.113.25 (overload)")
    ]


@pytest.fixture(scope="module")
def central():
    return load("res_vip_central_nat.conf")


def test_central_nat_detected(central):
    root = central.vdom("root")
    assert root.central_nat
    assert any("Central NAT" in n for n in root.notes)


def test_central_nat_vip_hint_in_policy(central):
    root = central.vdom("root")
    inbound = root.policy("1")
    assert vals(inbound.destination) == ["10.0.2.10/32"]
    assert any("vip-web" in n and "203.0.113.10" in n for n in inbound.notes)
    assert inbound.nat.mode == "central"
    assert not any("vip-web" in n for n in root.policy("2").notes)


def test_central_snat_table(central):
    root = central.vdom("root")
    assert [r.rule_id for r in root.snat] == ["1", "2"]
    first, second = root.snat
    assert first.enabled and vals(first.orig_addr) == ["10.0.2.0/24"]
    assert [pool.name for pool in first.pools] == ["pool-out"]
    assert first.src_interfaces[0].name == "port2"
    assert not second.enabled and second.nat
    assert second.pools == []
    pools = {p.name: p for p in root.ippools}
    assert pools["pool-1to1"].type == "one-to-one"
    assert pools["pool-out"].type == "overload" and "type" in pools["pool-out"].defaults_applied


# --- negation and internet services --------------------------------------------


@pytest.fixture(scope="module")
def negate():
    return load("res_negate_isdb.conf")


def test_negation_and_internet_service_in_one_policy(negate):
    p = negate.vdom("root").policy("1")
    assert p.source.negate
    assert vals(p.source) == ["10.0.1.128/25"]  # not inverted
    assert p.destination.internet_services == ["Microsoft-Office365", "Amazon-AWS"]
    assert vals(p.destination) == ["Microsoft-Office365", "Amazon-AWS"]
    assert all(v.kind == "unresolvable" and "Internet Service" in v.note for v in p.destination.values)
    assert p.service.entries == []
    assert any("Internet Service" in n for n in p.notes)


def test_negated_destination_and_service(negate):
    p = negate.vdom("root").policy("2")
    assert p.destination.negate and p.service.negate
    assert not p.source.negate
    assert vals(p.destination) == ["192.0.2.0/24"]
    assert svc(p) == ["TCP/443"]


def test_internet_service_as_source(negate):
    p = negate.vdom("root").policy("3")
    assert p.source.internet_services == ["Botnet-C&C.Server"]
    assert kinds(p.source) == ["unresolvable"]
    assert p.action == "deny"


# --- IPv6 ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def policy6():
    return load("res_policy6.conf")


def test_policy6_is_a_policy_marked_ipv6(policy6):
    root = policy6.vdom("root")
    assert ids(root) == [
        ("firewall policy", "1"),
        ("firewall policy6", "1"),
        ("firewall policy6", "2"),
        ("implicit", "0"),
    ]
    p = root.policy("1", section="firewall policy6")
    assert p.ip_version == "6"
    assert vals(p.source) == ["2001:db8:10::/64", "2001:db8:20::1-2001:db8:20::ff"]
    assert all(v.ip_version == 6 for v in p.source.values)
    assert vals(p.destination) == ["::/0"]
    assert root.policy("1").ip_version == "4"


def test_policy6_defaults(policy6):
    p = policy6.vdom("root").policy("2", section="firewall policy6")
    assert p.action == "deny" and "action" in p.defaults_applied
    assert [(v.kind, v.value) for v in p.source.values] == [("fqdn", "v6.example.com")]


def test_implicit_deny_covers_both_families(policy6):
    implicit = policy6.vdom("root").policies[-1]
    assert implicit.ip_version == "4+6"
    assert vals(implicit.source) == ["0.0.0.0/0", "::/0"]


def test_dual_stack_policy():
    root = load("res_policy_dualstack.conf").vdom("root")
    p = root.policy("1")
    assert p.ip_version == "4+6"
    assert p.source.objects == ["net-lan"] and p.source.objects6 == ["v6-lan"]
    assert vals(p.source) == ["10.10.10.0/24", "2001:db8:10::/64"]
    assert vals(p.destination) == ["0.0.0.0/0", "::/0"]
    assert root.policy("2").ip_version == "6"


# --- SD-WAN and tunnels ---------------------------------------------------------


@pytest.fixture(scope="module")
def sdwan():
    return load("res_sdwan_tunnel.conf")


def test_sdwan_zone_as_srcintf(sdwan):
    p = sdwan.vdom("root").policy("1")
    assert [(i.name, i.kind, i.zone) for i in p.src_interfaces] == [
        ("virtual-wan-link", "sdwan-zone", "virtual-wan-link")
    ]
    assert p.src_zones == ["virtual-wan-link"]


def test_tunnel_as_srcintf(sdwan):
    p = sdwan.vdom("root").policy("2")
    assert [(i.name, i.kind, i.zone) for i in p.src_interfaces] == [("tun-hq", "interface", "tun-hq")]
    tun = {i.name: i for i in sdwan.interfaces}["tun-hq"]
    assert (tun.type, tun.type_label, tun.parent) == ("tunnel", "Tunnel", "wan1")


def test_unknown_interface_stays_visible(sdwan):
    p = sdwan.vdom("root").policy("3")
    assert [(i.name, i.kind) for i in p.src_interfaces] == [("ghost-if", "unknown"), ("internal", "interface")]
    assert p.src_zones == ["ghost-if", "internal"]
    assert any("ghost-if" in n for n in p.notes)
    assert [(i.name, i.kind) for i in p.dst_interfaces] == [("SASE", "sdwan-zone")]


def test_any_interface(sdwan):
    p = sdwan.vdom("root").policy("4")
    assert [(i.name, i.kind) for i in p.src_interfaces] == [("any", "any")]
    assert p.src_zones == ["any"] and p.dst_zones == ["any"]


def test_sdwan_members_and_zones(sdwan):
    by_name = {i.name: i for i in sdwan.interfaces}
    assert by_name["wan1"].zone == "virtual-wan-link"
    assert by_name["wan2"].zone == "SASE"
    assert by_name["virtual-wan-link"].type == "sdwan-zone"
    assert by_name["virtual-wan-link"].type_label == "SD-WAN-Zone"
    assert by_name["virtual-wan-link"].members == ["wan1"]
    zones = {z.name: z for z in sdwan.vdom("root").zones}
    assert zones["SASE"].kind == "sdwan-zone" and zones["SASE"].interfaces == ["wan2"]
    keys = {(k.section, k.key) for k in sdwan.coverage.unknown_keys}
    assert ("system sdwan", "config health-check") in keys
    assert ("system sdwan > members", "gateway") in keys


# --- cross-cutting -------------------------------------------------------------


@pytest.mark.parametrize("path", valid_fixtures(), ids=lambda p: p.name)
def test_every_fixture_resolves_without_secrets(path):
    resolved = resolve_config(parse_file(path))
    data = resolved.model_dump_json()
    assert SECRET_MARKER not in data
    json.loads(data)


def test_resolution_is_deterministic():
    a = load("res_vip_central_nat.conf").model_dump_json()
    b = load("res_vip_central_nat.conf").model_dump_json()
    assert a == b


def test_resolve_single_policy_object():
    from fortidoc.core.resolver import Resolver
    from fortidoc.model.loader import load

    loaded = load(parse_file(FIXTURES / "res_policy_defaults.conf"))
    resolver = Resolver(loaded)
    policy = loaded.vdoms[0].objects("firewall policy")[0]
    result = resolver.resolve(policy)
    assert (result.policy_id, result.action, result.status) == ("1", "deny", "enable")
