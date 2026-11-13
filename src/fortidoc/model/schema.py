"""Pydantic models of the data model and of the resolved result.

``ConfigObject`` is one entry of an evaluated section, loaded from the parser
tree (effective settings, unknown keys kept). All other models describe the
resolved result that the exports use. Field names are English; text meant
for readers (``value``, ``note``, ``notes``, labels) is German.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Loaded objects
# ---------------------------------------------------------------------------


class ConfigObject(BaseModel):
    """One entry (``edit``) or settings block of an evaluated section."""

    section: str
    name: str | None = None
    vdom: str | None = None
    line: int
    settings: dict[str, list[str]] = Field(default_factory=dict)
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)
    # Evaluated nested config blocks, e.g. 'zone' and 'members' of 'system sdwan'.
    subsections: dict[str, list[ConfigObject]] = Field(default_factory=dict)

    def raw(self, key: str) -> list[str] | None:
        return self.settings.get(key)


# ---------------------------------------------------------------------------
# Resolved values
# ---------------------------------------------------------------------------

ValueKind = Literal["network", "range", "fqdn", "vip", "unresolvable"]
# Why a value is "nicht auflösbar"; the report search uses it to explain
# "möglicherweise" hits.
UnresolvedReason = Literal[
    "invalid", "circular", "not-found", "wildcard", "geo", "dynamic", "interface", "mac", "unknown-type", "isdb",
    "exclude",
]


class VipMapping(BaseModel):
    name: str
    vdom: str | None = None
    type: str
    ext_ip: str | None = None
    ext_intf: str | None = None
    mapped_ips: list[str] = Field(default_factory=list)
    portforward: bool = False
    protocol: str | None = None
    ext_port: str | None = None
    mapped_port: str | None = None
    value: str  # "extern → intern"
    comment: str | None = None
    notes: list[str] = Field(default_factory=list)
    defaults_applied: list[str] = Field(default_factory=list)
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


class ResolvedValue(BaseModel):
    """One effective address value with its kind and where it came from."""

    kind: ValueKind
    value: str
    ip_version: int | None = None
    origin: list[str] = Field(default_factory=list)  # object chain, outermost first
    note: str | None = None
    vip: VipMapping | None = None
    # True when the value is the FortiOS default because the backup has no
    # subnet/ip6 for the object (e.g. 'all' or special objects like FABRIC_DEVICE).
    from_default: bool = False
    reason: UnresolvedReason | None = None  # only for kind "unresolvable"


class AddressSide(BaseModel):
    objects: list[str] = Field(default_factory=list)  # IPv4 object names
    objects6: list[str] = Field(default_factory=list)  # IPv6 object names
    negate: bool = False  # "alles außer …", values are NOT inverted
    internet_services: list[str] = Field(default_factory=list)
    values: list[ResolvedValue] = Field(default_factory=list)


class ServiceEntry(BaseModel):
    kind: Literal["ports", "icmp", "ip", "unresolvable"]
    protocol: str | None = None
    value: str
    dst_ports: str | None = None
    src_ports: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    protocol_number: int | None = None
    origin: list[str] = Field(default_factory=list)
    note: str | None = None


class ServiceSide(BaseModel):
    objects: list[str] = Field(default_factory=list)
    negate: bool = False
    entries: list[ServiceEntry] = Field(default_factory=list)


class IpPoolInfo(BaseModel):
    name: str
    vdom: str | None = None
    type: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None
    source_start_ip: str | None = None
    source_end_ip: str | None = None
    value: str
    comment: str | None = None
    notes: list[str] = Field(default_factory=list)
    defaults_applied: list[str] = Field(default_factory=list)
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


class NatInfo(BaseModel):
    enabled: bool = False
    ippool: bool = False
    pools: list[IpPoolInfo] = Field(default_factory=list)
    # none: no NAT; interface: egress interface address; pool: IP pool;
    # central: the VDOM uses central NAT (policy does not decide).
    mode: Literal["none", "interface", "pool", "central"] = "none"


class InterfaceRef(BaseModel):
    name: str
    kind: Literal["interface", "zone", "sdwan-zone", "any", "unknown"]
    zone: str | None = None
    vdom: str | None = None


# ---------------------------------------------------------------------------
# Interfaces and zones
# ---------------------------------------------------------------------------


class InterfaceInfo(BaseModel):
    name: str
    vdom: str | None = None
    type: str
    type_label: str
    ip: str | None = None
    vlan_id: int | None = None
    parent: str | None = None
    members: list[str] = Field(default_factory=list)
    zone: str | None = None
    alias: str | None = None
    description: str | None = None
    status: str | None = None
    notes: list[str] = Field(default_factory=list)
    defaults_applied: list[str] = Field(default_factory=list)
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


class ZoneInfo(BaseModel):
    name: str
    vdom: str | None = None
    kind: Literal["zone", "sdwan-zone", "interface"]
    interfaces: list[str] = Field(default_factory=list)
    intrazone: str | None = None


# ---------------------------------------------------------------------------
# Objects tables
# ---------------------------------------------------------------------------


class ResolvedAddress(BaseModel):
    name: str
    vdom: str | None = None
    category: Literal["address", "addrgrp", "address6", "addrgrp6", "vip", "vipgrp"]
    type: str | None = None
    members: list[str] = Field(default_factory=list)
    exclude_members: list[str] = Field(default_factory=list)
    values: list[ResolvedValue] = Field(default_factory=list)
    comment: str | None = None
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


class ResolvedService(BaseModel):
    name: str
    vdom: str | None = None
    category: Literal["custom", "group"]
    protocol: str | None = None
    members: list[str] = Field(default_factory=list)
    entries: list[ServiceEntry] = Field(default_factory=list)
    comment: str | None = None
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Policies and NAT rules
# ---------------------------------------------------------------------------


class ResolvedPolicy(BaseModel):
    vdom: str
    section: Literal["firewall policy", "firewall policy6", "implicit"]
    position: int  # 1-based, file order within the VDOM
    policy_id: str
    implicit: bool = False
    name: str | None = None
    uuid: str | None = None
    status: str
    enabled: bool
    action: str
    ip_version: Literal["4", "6", "4+6"]
    src_interfaces: list[InterfaceRef] = Field(default_factory=list)
    dst_interfaces: list[InterfaceRef] = Field(default_factory=list)
    src_zones: list[str] = Field(default_factory=list)
    dst_zones: list[str] = Field(default_factory=list)
    source: AddressSide = Field(default_factory=AddressSide)
    destination: AddressSide = Field(default_factory=AddressSide)
    service: ServiceSide = Field(default_factory=ServiceSide)
    nat: NatInfo = Field(default_factory=NatInfo)
    users: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    schedule: str | None = None
    logtraffic: str | None = None
    profiles: dict[str, str] = Field(default_factory=dict)
    comments: str | None = None
    line: int | None = None
    notes: list[str] = Field(default_factory=list)
    defaults_applied: list[str] = Field(default_factory=list)
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


class SnatRule(BaseModel):
    vdom: str
    position: int
    rule_id: str
    status: str
    enabled: bool
    src_interfaces: list[InterfaceRef] = Field(default_factory=list)
    dst_interfaces: list[InterfaceRef] = Field(default_factory=list)
    orig_addr: AddressSide = Field(default_factory=AddressSide)
    dst_addr: AddressSide = Field(default_factory=AddressSide)
    protocol: str | None = None
    orig_port: str | None = None
    nat: bool
    pools: list[IpPoolInfo] = Field(default_factory=list)
    comments: str | None = None
    notes: list[str] = Field(default_factory=list)
    defaults_applied: list[str] = Field(default_factory=list)
    unknown_keys: dict[str, list[str]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Findings ("Auffälligkeiten")
# ---------------------------------------------------------------------------


class MatrixCell(BaseModel):
    """Rules of one source zone -> destination zone combination."""

    src: str
    dst: str
    accept: int = 0  # active rules
    deny: int = 0
    other: int = 0  # active rules with another action (e.g. ipsec)
    disabled: int = 0  # disabled rules, any action
    positions: list[int] = Field(default_factory=list)  # all rules of the cell, file order


class ZoneMatrix(BaseModel):
    vdom: str
    rows: list[str]  # source zones, "any" first
    cols: list[str]  # destination zones, "any" first
    cells: list[MatrixCell] = Field(default_factory=list)


class Finding(BaseModel):
    category: str
    vdom: str | None = None
    object_kind: str  # "Regel", "Adresse", "Dienst", ...
    position: int | None = None
    ref: str  # policy ID or object name
    name: str | None = None
    detail: str


# ---------------------------------------------------------------------------
# Coverage ("Nicht verarbeitet")
# ---------------------------------------------------------------------------


class UnprocessedSection(BaseModel):
    scope: str  # "global", a VDOM name, or "außerhalb"
    path: str
    entries: int
    line: int


class UnknownKey(BaseModel):
    section: str
    key: str
    count: int
    scopes: list[str] = Field(default_factory=list)


class Coverage(BaseModel):
    unprocessed_sections: list[UnprocessedSection] = Field(default_factory=list)
    unknown_keys: list[UnknownKey] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Whole result
# ---------------------------------------------------------------------------


class DeviceInfo(BaseModel):
    model: str | None = None
    version: str | None = None
    build: str | None = None
    firmware_type: str | None = None
    vdom_mode: str
    input_name: str | None = None
    input_sha256: str | None = None
    input_size_bytes: int | None = None


class ResolvedVdom(BaseModel):
    name: str
    central_nat: bool = False
    opmode: str | None = None
    notes: list[str] = Field(default_factory=list)
    zones: list[ZoneInfo] = Field(default_factory=list)
    policies: list[ResolvedPolicy] = Field(default_factory=list)
    addresses: list[ResolvedAddress] = Field(default_factory=list)
    services: list[ResolvedService] = Field(default_factory=list)
    vips: list[VipMapping] = Field(default_factory=list)
    ippools: list[IpPoolInfo] = Field(default_factory=list)
    snat: list[SnatRule] = Field(default_factory=list)

    def policy(self, policy_id: str, section: str = "firewall policy") -> ResolvedPolicy | None:
        for p in self.policies:
            if p.section == section and p.policy_id == policy_id:
                return p
        return None


class ResolvedConfig(BaseModel):
    device: DeviceInfo
    interfaces: list[InterfaceInfo] = Field(default_factory=list)
    vdoms: list[ResolvedVdom] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    notes: list[str] = Field(default_factory=list)

    def vdom(self, name: str) -> ResolvedVdom | None:
        for v in self.vdoms:
            if v.name == name:
                return v
        return None
