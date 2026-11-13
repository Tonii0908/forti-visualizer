"""Parser: generic tree, order, nesting, header, VDOM handling, round trip."""

from __future__ import annotations

import pytest

from conftest import strip_positions, valid_fixtures
from fortidoc.parser.conf_parser import (
    ConfigNode,
    EditNode,
    SetNode,
    UnsetNode,
    iter_nodes,
    parse_file,
    parse_header,
    parse_text,
    tree_to_conf,
)

# --- header ---------------------------------------------------------------


def test_header_fields(fixture_path):
    tree = parse_file(fixture_path("no_vdom.conf"))
    h = tree.header
    assert h.model == "FGT60F"
    assert h.version == "7.2.5"
    assert h.firmware_type == "FW"
    assert h.build == "1517"
    assert h.build_date == "230606"
    assert h.opmode == "0"
    assert h.vdom_flag == "0"
    assert h.user == "admin"
    assert h.extra == {
        "conf_file_ver": "1111111111111111111",
        "buildno": "1517",
        "global_vdom": "1",
    }


@pytest.mark.parametrize(
    ("line", "model", "version", "build"),
    [
        ("#config-version=FGT60E-6.0.4-FW-build0231-190107:opmode=0:vdom=0:user=admin", "FGT60E", "6.0.4", "0231"),
        ("#config-version=FGVM64-7.4.3-FW-build2573-240201:opmode=0:vdom=1:user=admin", "FGVM64", "7.4.3", "2573"),
        ("#config-version=FG-TEST-X-7.0.12-FW-build0523-230612:opmode=0:vdom=0:user=a", "FG-TEST-X", "7.0.12", "0523"),
    ],
)
def test_header_variants(line, model, version, build):
    h = parse_header([line])
    assert (h.model, h.version, h.build) == (model, version, build)


def test_header_fortios_5_two_part_version(fixture_path):
    tree = parse_file(fixture_path("header_v5.conf"))
    h = tree.header
    assert (h.model, h.version, h.build) == ("FGT60D", "5.06", "1638")
    assert h.version_tuple() == (5, 6)
    assert not tree.warnings


def test_version_tuple_three_parts(fixture_path):
    assert parse_file(fixture_path("no_vdom.conf")).header.version_tuple() == (7, 2, 5)


def test_unparseable_header_is_a_warning_not_an_error():
    tree = parse_text("#config-version=garbage\nconfig a\nend\n")
    assert tree.header.raw == "garbage"
    assert tree.header.model is None
    assert any("Kopfzeile" in w.message for w in tree.warnings)


def test_missing_header_is_a_warning(fixture_path):
    tree = parse_file(fixture_path("no_header.conf"))
    assert tree.header.raw is None
    assert any("config-version" in w.message for w in tree.warnings)
    assert tree.vdoms[0].config("firewall", "address").edit("no-header") is not None


# --- VDOM handling ----------------------------------------------------------


def test_device_without_vdoms_is_single_root_vdom(fixture_path):
    tree = parse_file(fixture_path("no_vdom.conf"))
    assert tree.vdom_mode == "no-vdom"
    assert [v.name for v in tree.vdoms] == ["root"]
    assert tree.global_sections == []
    root = tree.vdoms[0]
    assert [s.path for s in root.sections] == [
        ["system", "global"],
        ["system", "interface"],
        ["firewall", "address"],
        ["firewall", "policy"],
    ]
    for node in iter_nodes(root.sections):
        if isinstance(node, (ConfigNode, EditNode)):
            assert node.vdom == "root"


def test_two_vdoms_are_detected_and_merged(fixture_path):
    tree = parse_file(fixture_path("two_vdoms.conf"))
    assert tree.vdom_mode == "multi-vdom"
    assert [v.name for v in tree.vdoms] == ["root", "dmz"]
    assert all(v.declared for v in tree.vdoms)
    assert [s.path for s in tree.global_sections] == [
        ["system", "global"],
        ["system", "interface"],
    ]
    root, dmz = tree.vdoms
    assert [s.path for s in root.sections] == [
        ["system", "settings"],
        ["firewall", "address"],
        ["firewall", "policy"],
    ]
    assert [s.path for s in dmz.sections] == [["firewall", "address"], ["firewall", "policy"]]
    assert dmz.config("firewall", "address").edit("dmz-web") is not None
    assert root.config("firewall", "address").edit("dmz-web") is None


def test_every_node_carries_its_vdom(fixture_path):
    tree = parse_file(fixture_path("two_vdoms.conf"))
    for node in iter_nodes(tree.global_sections):
        if isinstance(node, (ConfigNode, EditNode)):
            assert node.vdom is None
    for vdom in tree.vdoms:
        for node in iter_nodes(vdom.sections):
            if isinstance(node, (ConfigNode, EditNode)):
                assert node.vdom == vdom.name


def test_vdom_blocks_for_same_vdom_are_concatenated_in_file_order():
    text = (
        "config vdom\nedit root\nnext\nend\n"
        "config vdom\nedit root\nconfig a\nend\nnext\nend\n"
        "config global\nconfig g\nend\nend\n"
        "config vdom\nedit root\nconfig b\nend\nnext\nend\n"
    )
    tree = parse_text(text)
    assert [s.path for s in tree.vdoms[0].sections] == [["a"], ["b"]]
    assert [s.path for s in tree.global_sections] == [["g"]]


def test_vdom_without_declaration_is_kept_and_flagged():
    tree = parse_text("config vdom\nedit root\nnext\nend\nconfig vdom\nedit extra\nconfig a\nend\nnext\nend\n")
    names = {v.name: v.declared for v in tree.vdoms}
    assert names == {"root": True, "extra": False}
    assert any("extra" in w.message for w in tree.warnings)


def test_header_vdom_flag_mismatch_is_a_warning():
    text = "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=1:user=admin\nconfig a\nend\n"
    tree = parse_text(text)
    assert tree.vdom_mode == "no-vdom"
    assert any("VDOM" in w.message for w in tree.warnings)


# --- grammar ------------------------------------------------------------------


def test_nested_config_inside_edit(fixture_path):
    tree = parse_file(fixture_path("nested_config.conf"))
    root = tree.vdoms[0]
    bgp = root.config("router", "bgp")
    assert bgp.get("as").values == ["65001"]
    neighbor = bgp.config("neighbor").edit("192.0.2.2")
    assert neighbor.get("remote-as").values == ["65002"]
    sla = root.config("system", "sdwan").config("health-check").edit("ping-check").config("sla").edit("1")
    assert sla.get("latency-threshold").values == ["100"]


def test_unset_is_kept(fixture_path):
    tree = parse_file(fixture_path("nested_config.conf"))
    policy = tree.vdoms[0].config("firewall", "policy").edit("7")
    kinds = [(type(c).__name__, getattr(c, "key", None)) for c in policy.children]
    assert kinds == [("SetNode", "name"), ("UnsetNode", "schedule"), ("SetNode", "action")]
    assert isinstance(policy.children[1], UnsetNode)


def test_edit_closed_directly_by_end(fixture_path):
    tree = parse_file(fixture_path("edit_closed_by_end.conf"))
    root = tree.vdoms[0]
    category = root.config("firewall", "service", "category")
    assert [e.name for e in category.children] == ["General", "Web Access"]
    assert [e.closed_by for e in category.children] == ["next", "end"]
    assert root.config("firewall", "address").edit("after") is not None
    grp = root.config("user", "group").edit("grp-with-match")
    assert grp.closed_by == "end"
    match = grp.config("match").edit("1")
    assert match.closed_by == "end"
    assert match.get("group-name").values == ["cn=staff"]


def test_order_of_entries_follows_file_not_id(fixture_path):
    tree = parse_file(fixture_path("order.conf"))
    policy = tree.vdoms[0].config("firewall", "policy")
    assert [e.name for e in policy.children] == ["5", "2", "10", "1"]
    assert [c.key for c in policy.edit("5").children] == ["name", "status", "action"]


def test_duplicate_keys_are_kept_in_order():
    tree = parse_text("config a\nedit x\nset k 1\nset k 2\nnext\nend\n")
    edit = tree.vdoms[0].config("a").edit("x")
    assert [c.values for c in edit.children] == [["1"], ["2"]]


def test_quotes_and_multiple_values(fixture_path):
    tree = parse_file(fixture_path("quotes_escapes.conf"))
    root = tree.vdoms[0]
    grp = root.config("firewall", "addrgrp").edit('grp "quoted" name')
    assert grp.get("member").values == ["a", "b c", "d\\e"]
    assert grp.get("comment").values == ['path C:\\temp and "q" here']
    addr = root.config("firewall", "address")
    assert addr.edit("plain").get("comment").values == [""]
    apostrophe = addr.edit("apostrophe")
    assert apostrophe.get("comment").values == ["Bob's rule # not a comment"]
    assert apostrophe.get("fqdn").values == ["host#1.example.com"]
    assert apostrophe.get("associated-interface").values == ["tab-separated"]


def test_quoted_config_path(fixture_path):
    tree = parse_file(fixture_path("multiline_string.conf"))
    assert tree.vdoms[0].sections[0].path == ["system", "replacemsg", "http", "url-block"]


def test_multiline_string_with_command_like_lines(fixture_path):
    tree = parse_file(fixture_path("multiline_string.conf"))
    root = tree.vdoms[0]
    msg = root.config("system", "replacemsg", "http", "url-block")
    buffer = msg.get("buffer").values[0]
    assert buffer.startswith("<html><body>\nconfig firewall policy\n    edit 99\n")
    assert 'set note "escaped quote inside"' in buffer
    assert buffer.endswith("unset everything\n</body></html>")
    assert msg.get("header").values == ["http"]
    policy = root.config("firewall", "policy")
    assert [e.name for e in policy.children] == ["1"]
    assert policy.edit("1").get("comments").values == ["line one\nline two"]
    assert policy.edit("1").get("action").line == 22


def test_line_numbers(fixture_path):
    tree = parse_file(fixture_path("no_vdom.conf"))
    policy = tree.vdoms[0].config("firewall", "policy")
    assert policy.line == 29
    assert policy.end_line == 42
    assert policy.edit("1").line == 30
    assert policy.edit("1").get("service").line == 39


def test_crlf_file(fixture_path):
    tree = parse_file(fixture_path("crlf.conf"))
    addr = tree.vdoms[0].config("firewall", "address").edit("crlf")
    assert addr.get("comment").values == ["multi\nline"]
    assert tree.header.model == "FGT60F"


def test_utf8_bom_is_ignored(fixture_path):
    tree = parse_file(fixture_path("utf8_bom.conf"))
    assert tree.header.model == "FGT60F"


def test_unknown_sections_parse_generically(fixture_path):
    tree = parse_file(fixture_path("unknown_sections.conf"))
    section = tree.vdoms[0].config("totally", "made-up", "section")
    assert section.get("some-new-setting").values == ["x", "y"]
    assert section.config("deeper").edit("z").get("brand-new").values == ["1"]


def test_source_info(fixture_path):
    import hashlib

    path = fixture_path("no_vdom.conf")
    tree = parse_file(path)
    assert tree.source.name == "no_vdom.conf"
    assert tree.source.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert tree.source.size_bytes == path.stat().st_size


# --- lossless round trip ------------------------------------------------------


@pytest.mark.parametrize("path", valid_fixtures(), ids=lambda p: p.name)
def test_round_trip_is_lossless(path):
    tree = parse_file(path)
    again = parse_text(tree_to_conf(tree))
    first = strip_positions(tree.model_dump(exclude={"source", "warnings", "comments"}))
    second = strip_positions(again.model_dump(exclude={"source", "warnings", "comments"}))
    assert first == second


def test_parsing_is_deterministic(fixture_path):
    path = fixture_path("two_vdoms.conf")
    assert parse_file(path).model_dump_json() == parse_file(path).model_dump_json()


def test_node_types_are_tagged(fixture_path):
    tree = parse_file(fixture_path("nested_config.conf"))
    kinds = {n.kind for n in iter_nodes(tree.vdoms[0].sections)}
    assert kinds == {"config", "edit", "set", "unset"}
    assert all(isinstance(n, SetNode) for n in iter_nodes(tree.vdoms[0].sections) if n.kind == "set")
