"""Secrets (ENC values, password/PSK/key fields, PEM blocks) never leave the parser."""

from __future__ import annotations

import pytest

from conftest import SECRET_MARKER
from fortidoc.parser.conf_parser import SetNode, iter_nodes, parse_file
from fortidoc.redaction import REDACTED, is_secret_key, redact_values


@pytest.fixture
def tree(fixture_path):
    return parse_file(fixture_path("secrets.conf"))


def test_no_secret_in_serialized_tree(tree):
    assert SECRET_MARKER not in tree.model_dump_json()


def test_secret_keys_stay_visible(tree):
    root = tree.vdoms[0]
    pw = root.config("system", "admin").edit("admin").get("password")
    assert pw.values == [REDACTED]
    assert pw.redacted is True
    psk = root.config("vpn", "ipsec", "phase1-interface").edit("tun-hq").get("psksecret")
    assert psk.values == [REDACTED] and psk.redacted
    assert root.config("system", "ha").get("password").redacted


def test_plaintext_secret_fields_are_redacted(tree):
    root = tree.vdoms[0]
    assert root.config("user", "ldap").edit("ldap1").get("password").redacted
    ospf = root.config("router", "ospf").config("ospf-interface").edit("o1")
    assert ospf.get("md5-keys").redacted


def test_pem_blocks_are_redacted(tree):
    cert = tree.vdoms[0].config("vpn", "certificate", "local").edit("srv-cert")
    assert cert.get("private-key").redacted
    assert cert.get("certificate").redacted


def test_non_secret_values_are_untouched(tree):
    root = tree.vdoms[0]
    bob = root.config("user", "local").edit("bob")
    assert bob.get("type").values == ["password"]
    assert not bob.get("type").redacted
    tun = root.config("vpn", "ipsec", "phase1-interface").edit("tun-hq")
    assert tun.get("keylife").values == ["28800"]
    assert tun.get("remote-gw").values == ["203.0.113.5"]
    policy = root.config("firewall", "policy").edit("1")
    assert policy.get("comments").values == ["rule mentions password and psk in plain text"]
    assert policy.get("name").values == ["password-reset-portal"]
    cert = root.config("vpn", "certificate", "local").edit("srv-cert")
    assert cert.get("comments").values == ["certificate with password protection"]


def test_every_redacted_node_has_placeholder_only(tree):
    for node in iter_nodes(tree.vdoms[0].sections):
        if isinstance(node, SetNode) and node.redacted:
            assert node.values == [REDACTED]


@pytest.mark.parametrize(
    "key",
    ["password", "passwd", "psksecret", "secret", "private-key", "key", "key-string",
     "md5-keys", "authkey", "passphrase", "ppk-secret", "auth-pwd", "keytab", "sso-password"],
)
def test_secret_key_names(key):
    assert is_secret_key(key)


@pytest.mark.parametrize(
    "key",
    ["type", "keylife", "keepalive", "keyword", "comments", "name", "certificate", "member"],
)
def test_non_secret_key_names(key):
    assert not is_secret_key(key)


def test_enc_value_under_any_key_is_redacted():
    values, redacted = redact_values("some-new-field", ["ENC", "S3CR3Tabc"])
    assert redacted and values == [REDACTED]


def test_pem_value_under_any_key_is_redacted():
    values, redacted = redact_values("certificate", ["-----BEGIN CERTIFICATE-----\nS3CR3T\n-----END CERTIFICATE-----"])
    assert redacted and values == [REDACTED]


def test_certificate_name_reference_is_not_redacted():
    values, redacted = redact_values("certificate", ["Fortinet_Factory"])
    assert not redacted and values == ["Fortinet_Factory"]


# --- path rules ---------------------------------------------------------------


def test_snmp_community_name_is_redacted(fixture_path):
    tree = parse_file(fixture_path("snmp_community.conf"))
    root = tree.vdoms[0]
    community = root.config("system", "snmp", "community").edit("1")
    assert community.get("name").redacted
    assert community.get("name").values == [REDACTED]
    host = community.config("hosts").edit("1")
    assert host.get("ip").values == ["10.0.0.50", "255.255.255.255"]
    assert root.config("system", "snmp", "sysinfo").get("contact-info").values == ["noc team"]
    assert SECRET_MARKER not in tree.model_dump_json()


def test_snmp_community_name_is_redacted_in_multi_vdom_global():
    from fortidoc.parser.conf_parser import parse_text

    text = (
        "config vdom\nedit root\nnext\nend\n"
        "config global\nconfig system snmp community\nedit 1\nset name S3CR3Tglobal\nnext\nend\nend\n"
    )
    tree = parse_text(text)
    community = tree.global_sections[0].edit("1")
    assert community.get("name").redacted


def test_name_outside_snmp_community_is_not_redacted():
    values, redacted = redact_values("name", ["visible"], ("firewall", "policy"))
    assert not redacted and values == ["visible"]


def test_path_rule_needs_exact_path():
    assert redact_values("name", ["x"], ("system", "snmp", "community"))[1]
    assert not redact_values("name", ["x"], ("system", "snmp", "community", "hosts"))[1]
