"""Load the evaluated sections of the parser tree into ConfigObjects.

Effective settings follow the file order: a later ``set`` replaces an earlier
one, ``unset`` removes the key so that the default applies again
(ASSUMPTION(P4), see ANNAHMEN.md). Unknown keys stay in the object and are
counted for the coverage report; nested config blocks that are not evaluated
are only counted, their values are not taken over.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fortidoc.core.coverage import CoverageCollector
from fortidoc.model.defaults import PROFILE_KEYS
from fortidoc.model.schema import ConfigObject, Coverage
from fortidoc.parser.conf_parser import ConfigNode, ConfigTree, EditNode, SetNode, UnsetNode

# Config path -> section label.
EVALUATED_SECTIONS: dict[tuple[str, ...], str] = {
    ("system", "interface"): "system interface",
    ("system", "zone"): "system zone",
    ("system", "sdwan"): "system sdwan",
    ("system", "settings"): "system settings",
    ("firewall", "address"): "firewall address",
    ("firewall", "addrgrp"): "firewall addrgrp",
    ("firewall", "address6"): "firewall address6",
    ("firewall", "addrgrp6"): "firewall addrgrp6",
    ("firewall", "vip"): "firewall vip",
    ("firewall", "vipgrp"): "firewall vipgrp",
    ("firewall", "ippool"): "firewall ippool",
    ("firewall", "service", "custom"): "firewall service custom",
    ("firewall", "service", "group"): "firewall service group",
    ("firewall", "policy"): "firewall policy",
    ("firewall", "policy6"): "firewall policy6",
    ("firewall", "central-snat-map"): "firewall central-snat-map",
}

# Sections evaluated when they appear under 'config global'.
GLOBAL_SECTIONS = frozenset({"system interface"})

# Sections that are one settings block instead of a table of edits.
SETTINGS_SECTIONS = frozenset({"system settings", "system sdwan"})

# Evaluated nested blocks: section -> nested path -> label.
SUBSECTIONS: dict[str, dict[tuple[str, ...], str]] = {
    "system sdwan": {
        ("zone",): "system sdwan > zone",
        ("members",): "system sdwan > members",
    },
}

_POLICY_KEYS = frozenset(
    {
        "name", "uuid", "comments", "srcintf", "dstintf", "srcaddr", "dstaddr",
        "srcaddr6", "dstaddr6", "service", "action", "status", "schedule", "nat",
        "ippool", "poolname", "users", "groups", "logtraffic", "srcaddr-negate",
        "dstaddr-negate", "service-negate", "internet-service", "internet-service-name",
        "internet-service-id", "internet-service-group", "internet-service-custom",
        "internet-service-custom-group", "internet-service-src", "internet-service-src-name",
        "internet-service-src-id", "internet-service-src-group", "internet-service-src-custom",
        "internet-service-src-custom-group", "utm-status",
    }
) | frozenset(PROFILE_KEYS)

# Keys the resolver evaluates; everything else is reported as unknown.
KNOWN_KEYS: dict[str, frozenset[str]] = {
    "system interface": frozenset(
        {"vdom", "ip", "type", "interface", "vlanid", "member", "alias", "description", "status"}
    ),
    "system zone": frozenset({"interface", "intrazone", "description"}),
    "system sdwan": frozenset({"status"}),
    "system sdwan > zone": frozenset(),
    "system sdwan > members": frozenset({"interface", "zone"}),
    "system settings": frozenset({"central-nat", "opmode"}),
    "firewall address": frozenset(
        {"uuid", "type", "subnet", "start-ip", "end-ip", "fqdn", "wildcard", "country",
         "sub-type", "sdn", "filter", "interface", "macaddr", "comment"}
    ),
    "firewall address6": frozenset(
        {"uuid", "type", "ip6", "start-ip", "end-ip", "fqdn", "country", "sub-type", "sdn", "comment"}
    ),
    "firewall addrgrp": frozenset({"uuid", "member", "exclude", "exclude-member", "comment"}),
    "firewall addrgrp6": frozenset({"uuid", "member", "exclude", "exclude-member", "comment"}),
    "firewall vip": frozenset(
        {"uuid", "type", "extip", "mappedip", "extintf", "portforward", "protocol",
         "extport", "mappedport", "comment"}
    ),
    "firewall vipgrp": frozenset({"uuid", "interface", "member", "comments"}),
    "firewall ippool": frozenset(
        {"type", "startip", "endip", "source-startip", "source-endip", "comments"}
    ),
    "firewall service custom": frozenset(
        {"protocol", "tcp-portrange", "udp-portrange", "sctp-portrange", "icmptype",
         "icmpcode", "protocol-number", "category", "comment"}
    ),
    "firewall service group": frozenset({"member", "comment"}),
    "firewall policy": _POLICY_KEYS,
    "firewall policy6": _POLICY_KEYS,
    "firewall central-snat-map": frozenset(
        {"uuid", "status", "srcintf", "dstintf", "orig-addr", "dst-addr", "protocol",
         "orig-port", "nat", "nat-ippool", "nat-port", "comments"}
    ),
}


@dataclass
class LoadedVdom:
    name: str
    sections: dict[str, list[ConfigObject]] = field(default_factory=dict)

    def objects(self, section: str) -> list[ConfigObject]:
        return self.sections.get(section, [])


@dataclass
class LoadedConfig:
    tree: ConfigTree
    vdoms: list[LoadedVdom]
    interfaces: list[ConfigObject]
    coverage: Coverage


def load(tree: ConfigTree) -> LoadedConfig:
    collector = CoverageCollector()
    interfaces: list[ConfigObject] = []
    vdoms: list[LoadedVdom] = []

    def handle(node, scope: str, vdom: str | None, allowed) -> list[ConfigObject] | None:
        if not isinstance(node, ConfigNode):
            collector.unprocessed(scope, node)
            return None
        label = EVALUATED_SECTIONS.get(tuple(node.path))
        if label is None or (allowed is not None and label not in allowed):
            collector.unprocessed(scope, node)
            return None
        objects = _load_section(node, label, vdom, scope, collector)
        if label == "system interface":
            interfaces.extend(objects)
            return None
        return objects

    for node in tree.global_sections:
        handle(node, "global", None, GLOBAL_SECTIONS)
    for vdom in tree.vdoms:
        loaded = LoadedVdom(name=vdom.name)
        for node in vdom.sections:
            objects = handle(node, vdom.name, vdom.name, None)
            if objects is not None:
                label = EVALUATED_SECTIONS[tuple(node.path)]
                loaded.sections.setdefault(label, []).extend(objects)
        vdoms.append(loaded)
    for node in tree.outside_sections:
        collector.unprocessed("außerhalb", node)

    return LoadedConfig(tree=tree, vdoms=vdoms, interfaces=interfaces, coverage=collector.result())


def _load_section(
    node: ConfigNode, label: str, vdom: str | None, scope: str, collector: CoverageCollector
) -> list[ConfigObject]:
    if label in SETTINGS_SECTIONS:
        return [_load_object(node, label, None, vdom, scope, collector)]
    objects = []
    for child in node.children:
        if isinstance(child, EditNode):
            objects.append(_load_object(child, label, child.name, vdom, scope, collector))
        elif isinstance(child, ConfigNode):
            collector.unknown_key(label, "config " + " ".join(child.path), scope)
        else:
            collector.unknown_key(label, child.key, scope)
    return objects


def _load_object(
    node: ConfigNode | EditNode,
    label: str,
    name: str | None,
    vdom: str | None,
    scope: str,
    collector: CoverageCollector,
) -> ConfigObject:
    obj = ConfigObject(section=label, name=name, vdom=vdom, line=node.line)
    nested = SUBSECTIONS.get(label, {})
    for child in node.children:
        if isinstance(child, SetNode):
            obj.settings[child.key] = list(child.values)
        elif isinstance(child, UnsetNode):
            obj.settings.pop(child.key, None)
        elif isinstance(child, ConfigNode):
            sub_label = nested.get(tuple(child.path))
            if sub_label is None:
                collector.unknown_key(label, "config " + " ".join(child.path), scope)
                continue
            obj.subsections[sub_label] = [
                _load_object(e, sub_label, e.name, vdom, scope, collector)
                for e in child.children
                if isinstance(e, EditNode)
            ]
        # An EditNode directly inside an edit cannot occur (parser rejects it).
    known = KNOWN_KEYS.get(label, frozenset())
    for key, values in obj.settings.items():
        if key not in known:
            obj.unknown_keys[key] = values
            collector.unknown_key(label, key, scope)
    return obj
