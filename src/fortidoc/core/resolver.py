"""Resolve policies into effective sources, destinations, services and zones.

Entry points:
- ``resolve_config(tree)`` resolves a whole parsed configuration.
- ``Resolver(loaded).resolve(policy)`` resolves a single policy object.

Principles: nothing is dropped silently and nothing is guessed. Whatever
cannot be resolved becomes a value of kind ``unresolvable`` with a German
reason. Negations are flagged, never inverted. Defaults come from
``fortidoc.model.defaults`` and are recorded in ``defaults_applied``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from fortidoc.model.defaults import (
    IMPLICIT_DENY_ID,
    INTERFACE_TYPE_LABELS,
    PROFILE_KEYS,
    default_for,
)
from fortidoc.model.loader import LoadedConfig, LoadedVdom, load
from fortidoc.model.schema import (
    AddressSide,
    ConfigObject,
    DeviceInfo,
    InterfaceInfo,
    InterfaceRef,
    IpPoolInfo,
    NatInfo,
    ResolvedAddress,
    ResolvedConfig,
    ResolvedPolicy,
    ResolvedService,
    ResolvedValue,
    ResolvedVdom,
    ServiceEntry,
    ServiceSide,
    SnatRule,
    VipMapping,
    ZoneInfo,
)
from fortidoc.parser.conf_parser import ConfigTree

_NOT_FOUND = "Objekt '{name}' nicht gefunden (in den ausgewerteten Abschnitten)."
_ISDB_NOTE = "Internet Service: Die zugehörigen Adressen und Dienste stehen nur in der Datenbank auf dem Gerät."
_PORT_RANGE = re.compile(r"^(\d+)(?:-(\d+))?$")

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _get(obj: ConfigObject, key: str, used: list[str]) -> list[str] | None:
    """Effective value of ``key``: the configured one, else the FortiOS default."""
    values = obj.raw(key)
    if values is not None:
        return values
    default = default_for(obj.section, key)
    if default is not None and key not in used:
        used.append(key)
    return default


def _one(values: list[str] | None) -> str | None:
    return values[0] if values else None


def _text(values: list[str] | None) -> str | None:
    return " ".join(values) if values else None


def _add_note(value: ResolvedValue, note: str) -> None:
    value.note = f"{value.note} {note}" if value.note else note


def _mark_default(value: ResolvedValue, note: str) -> None:
    """Flag a value that only exists because the backup leaves the key out."""
    value.from_default = True
    _add_note(
        value,
        f"{note}. Sonderobjekte wie FABRIC_DEVICE stehen ebenfalls ohne Netz im Backup; "
        "der tatsächliche Inhalt ist nur auf dem Gerät sichtbar.",
    )


def _unresolvable(value: str, origin: list[str], note: str, ip_version: int | None = None) -> ResolvedValue:
    return ResolvedValue(kind="unresolvable", value=value, origin=list(origin), note=note, ip_version=ip_version)


def _network_value(values: list[str], origin: list[str]) -> ResolvedValue:
    """'10.0.0.0 255.255.255.0', '10.0.0.0/24' or '2001:db8::/32' -> network value."""
    text = values[0] if len(values) == 1 else f"{values[0]}/{values[1]}"
    try:
        iface = ipaddress.ip_interface(text)
    except ValueError:
        return _unresolvable(" ".join(values), origin, "Ungültige Netzangabe.")
    network = iface.network
    note = None
    if iface.ip != network.network_address and network.prefixlen != network.max_prefixlen:
        # ASSUMPTION(A1): host bits are ignored, the object stands for the whole network.
        note = f"Hostbits gesetzt ({iface.with_prefixlen}); als Netz {network} ausgewertet."
    return ResolvedValue(kind="network", value=str(network), ip_version=network.version, origin=list(origin), note=note)


def _range_value(start: str | None, end: str | None, origin: list[str], name: str) -> ResolvedValue:
    try:
        lo, hi = ipaddress.ip_address(start), ipaddress.ip_address(end)
    except ValueError:
        return _unresolvable(name, origin, f"Ungültiger Adressbereich ({start} bis {end}).")
    if lo.version != hi.version or lo > hi:
        return _unresolvable(name, origin, f"Ungültiger Adressbereich ({start} bis {end}).")
    return ResolvedValue(kind="range", value=f"{lo}-{hi}", ip_version=lo.version, origin=list(origin))


def _interval(value: ResolvedValue) -> tuple[int, int, int] | None:
    """(version, low, high) of a network or range value."""
    if value.kind == "network":
        net = ipaddress.ip_network(value.value)
        return net.version, int(net.network_address), int(net.broadcast_address)
    if value.kind == "range":
        lo, hi = (ipaddress.ip_address(p) for p in value.value.split("-", 1))
        return lo.version, int(lo), int(hi)
    return None


def _merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def _minus(base: list[tuple[int, int]], cut: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result = []
    for lo, hi in base:
        segments = [(lo, hi)]
        for c_lo, c_hi in cut:
            new = []
            for s, e in segments:
                if c_hi < s or c_lo > e:
                    new.append((s, e))
                    continue
                if s < c_lo:
                    new.append((s, c_lo - 1))
                if c_hi < e:
                    new.append((c_hi + 1, e))
            segments = new
        result.extend(segments)
    return result


def _interval_value(version: int, lo: int, hi: int, origin: list[str], note: str) -> ResolvedValue:
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    first, last = cls(lo), cls(hi)
    nets = list(ipaddress.summarize_address_range(first, last))
    if len(nets) == 1:
        return ResolvedValue(kind="network", value=str(nets[0]), ip_version=version, origin=list(origin), note=note)
    return ResolvedValue(kind="range", value=f"{first}-{last}", ip_version=version, origin=list(origin), note=note)


def _parse_ports(text: str) -> str | None:
    match = _PORT_RANGE.match(text)
    if not match:
        return None
    lo = int(match[1])
    hi = int(match[2]) if match[2] is not None else lo
    if not (0 <= lo <= hi <= 65535):
        return None
    return str(lo) if lo == hi else f"{lo}-{hi}"


def _parse_portrange(token: str) -> tuple[str, str | None] | None:
    """'443', '80-90', '22:1024-65535' -> (dst, src)."""
    dst_text, sep, src_text = token.partition(":")
    dst = _parse_ports(dst_text)
    if dst is None:
        return None
    if not sep:
        return dst, None
    src = _parse_ports(src_text)
    if src is None:
        return None
    return dst, src


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


# ---------------------------------------------------------------------------
# Per-VDOM lookup tables
# ---------------------------------------------------------------------------


class _VdomContext:
    def __init__(self, loaded: LoadedVdom) -> None:
        self.name = loaded.name
        self.loaded = loaded

        def table(section: str) -> dict[str, ConfigObject]:
            result: dict[str, ConfigObject] = {}
            for obj in loaded.objects(section):
                result.setdefault(obj.name, obj)
            return result

        self.address = table("firewall address")
        self.addrgrp = table("firewall addrgrp")
        self.address6 = table("firewall address6")
        self.addrgrp6 = table("firewall addrgrp6")
        self.vip_objects = table("firewall vip")
        self.vipgrp = table("firewall vipgrp")
        self.services = table("firewall service custom")
        self.service_groups = table("firewall service group")
        self.ippool_objects = table("firewall ippool")
        settings = loaded.objects("system settings")
        self.settings = settings[0] if settings else ConfigObject(section="system settings", line=0)
        used: list[str] = []
        self.central_nat = _one(_get(self.settings, "central-nat", used)) == "enable"
        self.opmode = _one(_get(self.settings, "opmode", used))
        self.zones: dict[str, ZoneInfo] = {}
        self.sdwan_zones: dict[str, ZoneInfo] = {}
        self.vips: dict[str, VipMapping] = {}
        self.ippools: dict[str, IpPoolInfo] = {}


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class Resolver:
    def __init__(self, loaded: LoadedConfig) -> None:
        self.loaded = loaded
        self.contexts: dict[str, _VdomContext] = {v.name: _VdomContext(v) for v in loaded.vdoms}
        self.interfaces: list[InterfaceInfo] = [self._interface(obj) for obj in loaded.interfaces]
        self.iface_by_name: dict[str, InterfaceInfo] = {}
        for iface in self.interfaces:
            self.iface_by_name.setdefault(iface.name, iface)
        for ctx in self.contexts.values():
            self._build_zones(ctx)
            ctx.vips = {name: self._vip(obj) for name, obj in ctx.vip_objects.items()}
            ctx.ippools = {name: self._ippool(obj) for name, obj in ctx.ippool_objects.items()}
        self._assign_interface_zones()

    # -- interfaces and zones ------------------------------------------------

    def _interface(self, obj: ConfigObject) -> InterfaceInfo:
        used: list[str] = []
        notes: list[str] = []
        vdom = _one(_get(obj, "vdom", used))
        if "vdom" in used:
            notes.append("Kein 'set vdom' am Interface; es wird VDOM root angenommen.")
        iface_type = _one(obj.raw("type"))
        if iface_type is None:
            if obj.raw("vlanid"):
                # ASSUMPTION(A2): an interface with vlanid but without type is a VLAN.
                iface_type = "vlan"
                notes.append("Typ nicht gesetzt; wegen 'vlanid' als VLAN geführt.")
            else:
                iface_type = "unknown"
        label = INTERFACE_TYPE_LABELS.get(iface_type, f"sonstiger ({iface_type})")
        ip = None
        raw_ip = obj.raw("ip")
        if raw_ip:
            try:
                parsed = ipaddress.ip_interface(raw_ip[0] if len(raw_ip) == 1 else f"{raw_ip[0]}/{raw_ip[1]}")
                if int(parsed.ip) != 0:
                    ip = parsed.with_prefixlen
            except ValueError:
                notes.append(f"IP-Angabe nicht lesbar: {' '.join(raw_ip)}")
        vlan_text = _one(obj.raw("vlanid"))
        return InterfaceInfo(
            name=obj.name or "",
            vdom=vdom,
            type=iface_type,
            type_label=label,
            ip=ip,
            vlan_id=int(vlan_text) if vlan_text and vlan_text.isdigit() else None,
            parent=_one(obj.raw("interface")),
            members=list(obj.raw("member") or []),
            alias=_text(obj.raw("alias")),
            description=_text(obj.raw("description")),
            status=_one(obj.raw("status")),
            notes=notes,
            defaults_applied=used,
            unknown_keys=dict(obj.unknown_keys),
        )

    def _build_zones(self, ctx: _VdomContext) -> None:
        for obj in ctx.loaded.objects("system zone"):
            used: list[str] = []
            ctx.zones.setdefault(
                obj.name,
                ZoneInfo(
                    name=obj.name,
                    vdom=ctx.name,
                    kind="zone",
                    interfaces=list(obj.raw("interface") or []),
                    intrazone=_one(_get(obj, "intrazone", used)),
                ),
            )
        for vwl in ctx.loaded.objects("system virtual-wan-link"):
            # ASSUMPTION(A7): before 6.4 all members form the interface 'virtual-wan-link'.
            zone = ctx.sdwan_zones.setdefault(
                "virtual-wan-link", ZoneInfo(name="virtual-wan-link", vdom=ctx.name, kind="sdwan-zone")
            )
            for member in vwl.subsections.get("system virtual-wan-link > members", []):
                interface = _one(member.raw("interface"))
                if interface is not None:
                    zone.interfaces.append(interface)
        for sdwan in ctx.loaded.objects("system sdwan"):
            for zone in sdwan.subsections.get("system sdwan > zone", []):
                ctx.sdwan_zones.setdefault(zone.name, ZoneInfo(name=zone.name, vdom=ctx.name, kind="sdwan-zone"))
            for member in sdwan.subsections.get("system sdwan > members", []):
                used: list[str] = []
                interface = _one(member.raw("interface"))
                zone_name = _one(_get(member, "zone", used))
                if interface is None or zone_name is None:
                    continue
                zone = ctx.sdwan_zones.setdefault(
                    zone_name, ZoneInfo(name=zone_name, vdom=ctx.name, kind="sdwan-zone")
                )
                zone.interfaces.append(interface)

    def _assign_interface_zones(self) -> None:
        member_of: dict[tuple[str, str], str] = {}
        for ctx in self.contexts.values():
            for zone in list(ctx.zones.values()) + list(ctx.sdwan_zones.values()):
                for name in zone.interfaces:
                    member_of.setdefault((ctx.name, name), zone.name)
        for iface in self.interfaces:
            iface.zone = member_of.get((iface.vdom, iface.name), iface.name)
        # SD-WAN zones are listed as interfaces of type "SD-WAN-Zone".
        for ctx in self.contexts.values():
            for zone in ctx.sdwan_zones.values():
                if any(i.name == zone.name and i.vdom == ctx.name for i in self.interfaces):
                    continue
                self.interfaces.append(
                    InterfaceInfo(
                        name=zone.name,
                        vdom=ctx.name,
                        type="sdwan-zone",
                        type_label=INTERFACE_TYPE_LABELS["sdwan-zone"],
                        members=list(zone.interfaces),
                        zone=zone.name,
                    )
                )

    def _zone_list(self, ctx: _VdomContext) -> list[ZoneInfo]:
        zones = list(ctx.zones.values()) + list(ctx.sdwan_zones.values())
        in_zone = {name for z in zones for name in z.interfaces}
        for iface in self.interfaces:
            if iface.vdom == ctx.name and iface.type != "sdwan-zone" and iface.name not in in_zone:
                zones.append(ZoneInfo(name=iface.name, vdom=ctx.name, kind="interface", interfaces=[iface.name]))
        return zones

    def _intf_ref(self, ctx: _VdomContext, name: str, notes: list[str]) -> InterfaceRef:
        if name == "any":
            return InterfaceRef(name=name, kind="any", zone="any")
        if name in ctx.zones:
            return InterfaceRef(name=name, kind="zone", zone=name, vdom=ctx.name)
        if name in ctx.sdwan_zones:
            return InterfaceRef(name=name, kind="sdwan-zone", zone=name, vdom=ctx.name)
        iface = self.iface_by_name.get(name)
        if iface is not None:
            if iface.vdom != ctx.name:
                notes.append(
                    f"Interface '{name}' gehört zu VDOM '{iface.vdom}', die Regel steht in VDOM '{ctx.name}'."
                )
            return InterfaceRef(name=name, kind="interface", zone=iface.zone, vdom=iface.vdom)
        notes.append(f"Interface oder Zone '{name}' ist unbekannt.")
        return InterfaceRef(name=name, kind="unknown", zone=name)

    # -- addresses -----------------------------------------------------------

    def _addr_values(self, ctx: _VdomContext, name: str, family: int, chain: list[str]) -> list[ResolvedValue]:
        path = chain + [name]
        if name in chain:
            return [_unresolvable(name, path, "Zirkelbezug: " + " > ".join(path), family)]
        if family == 4:
            if name in ctx.address:
                return self._address4(ctx.address[name], path)
            if name in ctx.addrgrp:
                return self._group(ctx, ctx.addrgrp[name], 4, path)
            if name in ctx.vips:
                vip = ctx.vips[name]
                return [ResolvedValue(kind="vip", value=vip.value, ip_version=4, origin=path, vip=vip)]
            if name in ctx.vipgrp:
                members = ctx.vipgrp[name].raw("member") or []
                return [v for m in members for v in self._addr_values(ctx, m, 4, path)]
        else:
            if name in ctx.address6:
                return self._address6(ctx.address6[name], path)
            if name in ctx.addrgrp6:
                return self._group(ctx, ctx.addrgrp6[name], 6, path)
        return [_unresolvable(name, path, _NOT_FOUND.format(name=name), family)]

    def _address4(self, obj: ConfigObject, origin: list[str]) -> list[ResolvedValue]:
        used: list[str] = []
        kind = _one(_get(obj, "type", used))
        name = obj.name or ""
        if kind == "ipmask":
            value = _network_value(_get(obj, "subnet", used) or [], origin)
            if "subnet" in used:
                _mark_default(value, "kein subnet im Backup, FortiOS-Default 0.0.0.0/0")
            return [value]
        if kind == "iprange":
            return [_range_value(_one(obj.raw("start-ip")), _one(obj.raw("end-ip")), origin, name)]
        if kind == "fqdn":
            fqdn = _one(obj.raw("fqdn"))
            if not fqdn:
                return [_unresolvable(name, origin, "FQDN-Adresse ohne FQDN.", 4)]
            return [ResolvedValue(kind="fqdn", value=fqdn, ip_version=4, origin=list(origin))]
        if kind == "wildcard":
            raw = obj.raw("wildcard") or []
            if len(raw) == 2:
                try:
                    # ASSUMPTION(A3): set bits in the wildcard mask are compared bits.
                    net = ipaddress.ip_network(f"{raw[0]}/{raw[1]}", strict=False)
                    return [
                        ResolvedValue(
                            kind="network",
                            value=str(net),
                            ip_version=4,
                            origin=list(origin),
                            note="Wildcard mit zusammenhängender Maske, als Netz dargestellt.",
                        )
                    ]
                except ValueError:
                    pass
            return [
                _unresolvable(
                    "/".join(raw) or name,
                    origin,
                    "Wildcard-Maske ist nicht zusammenhängend und lässt sich nicht als Netz oder Bereich darstellen.",
                    4,
                )
            ]
        if kind == "geography":
            country = _one(obj.raw("country")) or name
            return [
                _unresolvable(
                    country,
                    origin,
                    f"Geo-Adresse (Land {country}): Die Zuordnung zu IP-Adressen liegt nur in der Datenbank auf dem Gerät.",
                    4,
                )
            ]
        if kind == "dynamic":
            details = ", ".join(
                f"{key} {_text(obj.raw(key))}" for key in ("sub-type", "sdn", "filter") if obj.raw(key)
            )
            return [
                _unresolvable(
                    name,
                    origin,
                    f"Dynamische Adresse ({details or 'ohne Angaben'}) wird erst auf dem Gerät aufgelöst.",
                    4,
                )
            ]
        if kind == "interface-subnet":
            intf = _one(obj.raw("interface"))
            iface = self.iface_by_name.get(intf or "")
            if iface is not None and iface.ip:
                net = ipaddress.ip_interface(iface.ip).network
                return [
                    ResolvedValue(
                        kind="network",
                        value=str(net),
                        ip_version=4,
                        origin=list(origin),
                        note=f"Netz des Interfaces {intf}.",
                    )
                ]
            return [_unresolvable(name, origin, f"Interface '{intf}' nicht gefunden oder ohne IP-Adresse.", 4)]
        if kind == "mac":
            macs = obj.raw("macaddr") or []
            return [
                _unresolvable(
                    ", ".join(macs) or name,
                    origin,
                    "MAC-Adresse: kein IP-Wert, die Zuordnung erfolgt auf dem Gerät.",
                    4,
                )
            ]
        return [_unresolvable(name, origin, f"Unbekannter Adresstyp '{kind}'.", 4)]

    def _address6(self, obj: ConfigObject, origin: list[str]) -> list[ResolvedValue]:
        used: list[str] = []
        kind = _one(_get(obj, "type", used))
        name = obj.name or ""
        if kind == "ipprefix":
            value = _network_value(_get(obj, "ip6", used) or [], origin)
            if "ip6" in used:
                _mark_default(value, "kein ip6 im Backup, FortiOS-Default ::/0")
            return [value]
        if kind == "iprange":
            return [_range_value(_one(obj.raw("start-ip")), _one(obj.raw("end-ip")), origin, name)]
        if kind == "fqdn":
            fqdn = _one(obj.raw("fqdn"))
            if fqdn:
                return [ResolvedValue(kind="fqdn", value=fqdn, ip_version=6, origin=list(origin))]
            return [_unresolvable(name, origin, "FQDN-Adresse ohne FQDN.", 6)]
        if kind == "geography":
            country = _one(obj.raw("country")) or name
            return [_unresolvable(country, origin, f"Geo-Adresse (Land {country}): nur auf dem Gerät auflösbar.", 6)]
        if kind == "dynamic":
            return [_unresolvable(name, origin, "Dynamische Adresse wird erst auf dem Gerät aufgelöst.", 6)]
        return [_unresolvable(name, origin, f"Unbekannter Adresstyp '{kind}'.", 6)]

    def _group(self, ctx: _VdomContext, obj: ConfigObject, family: int, path: list[str]) -> list[ResolvedValue]:
        used: list[str] = []
        values = [v for m in obj.raw("member") or [] for v in self._addr_values(ctx, m, family, path)]
        excluded_members = obj.raw("exclude-member") or []
        if not excluded_members:
            return values
        if _one(_get(obj, "exclude", used)) != "enable":
            for value in values:
                _add_note(
                    value,
                    f"In Gruppe '{obj.name}' ist exclude-member gesetzt, aber 'exclude' ist nicht aktiviert; "
                    "der Ausschluss wird nicht angewendet.",
                )
            return values
        excluded = [v for m in excluded_members for v in self._addr_values(ctx, m, family, path)]
        return self._subtract(values, excluded, path)

    def _subtract(self, values: list[ResolvedValue], excluded: list[ResolvedValue], path: list[str]) -> list[ResolvedValue]:
        base: dict[int, list[tuple[int, int]]] = {}
        cut: dict[int, list[tuple[int, int]]] = {}
        others: list[ResolvedValue] = []
        for value in values:
            iv = _interval(value)
            if iv is None:
                others.append(value)
            else:
                base.setdefault(iv[0], []).append((iv[1], iv[2]))
        not_computable: list[ResolvedValue] = []
        for value in excluded:
            iv = _interval(value)
            if iv is None:
                not_computable.append(value)
            else:
                cut.setdefault(iv[0], []).append((iv[1], iv[2]))
        note = f"Ergebnis nach Ausschluss (exclude-member) in Gruppe '{path[-1]}'."
        result: list[ResolvedValue] = []
        for version in sorted(base):
            remaining = _minus(_merge(base[version]), _merge(cut.get(version, [])))
            result.extend(_interval_value(version, lo, hi, path, note) for lo, hi in remaining)
        for value in others:
            _add_note(value, "Der Ausschluss (exclude-member) ist auf FQDN- und nicht auflösbare Werte nicht anwendbar.")
        result.extend(others)
        for value in not_computable:
            result.append(
                _unresolvable(
                    f"ausgenommen: {value.value}",
                    value.origin,
                    "Ausschluss nicht berechenbar, weil der ausgenommene Wert keine IP-Adresse ist.",
                    value.ip_version,
                )
            )
        return result

    # -- VIPs and pools --------------------------------------------------------

    def _vip(self, obj: ConfigObject) -> VipMapping:
        used: list[str] = []
        notes: list[str] = []
        vip_type = _one(_get(obj, "type", used)) or "static-nat"
        ext_ip = _one(obj.raw("extip"))
        ext_intf = _one(_get(obj, "extintf", used))
        portforward = _one(_get(obj, "portforward", used)) == "enable"
        protocol = _one(_get(obj, "protocol", used)) if portforward else None
        ext_port = _one(obj.raw("extport"))
        mapped_port = _one(obj.raw("mappedport"))
        mapped = list(obj.raw("mappedip") or [])
        external = ext_ip or "?"
        if portforward:
            external += f":{ext_port or '?'}/{(protocol or '?').upper()}"
        external += f" ({ext_intf})"
        targets = [f"{m}:{mapped_port}" if portforward and mapped_port else m for m in mapped]
        if vip_type != "static-nat":
            notes.append(f"VIP-Typ '{vip_type}' wird nur teilweise ausgewertet.")
        if not mapped:
            notes.append("Keine mappedip gesetzt.")
        return VipMapping(
            name=obj.name or "",
            vdom=obj.vdom,
            type=vip_type,
            ext_ip=ext_ip,
            ext_intf=ext_intf,
            mapped_ips=mapped,
            portforward=portforward,
            protocol=protocol,
            ext_port=ext_port,
            mapped_port=mapped_port,
            value=f"{external} → {', '.join(targets) or '?'}",
            comment=_text(obj.raw("comment")),
            notes=notes,
            defaults_applied=used,
            unknown_keys=dict(obj.unknown_keys),
        )

    def _ippool(self, obj: ConfigObject) -> IpPoolInfo:
        used: list[str] = []
        pool_type = _one(_get(obj, "type", used))
        start, end = _one(obj.raw("startip")), _one(obj.raw("endip"))
        return IpPoolInfo(
            name=obj.name or "",
            vdom=obj.vdom,
            type=pool_type,
            start_ip=start,
            end_ip=end,
            source_start_ip=_one(obj.raw("source-startip")),
            source_end_ip=_one(obj.raw("source-endip")),
            value=f"{start or '?'}-{end or '?'} ({pool_type})",
            comment=_text(obj.raw("comments")),
            defaults_applied=used,
            unknown_keys=dict(obj.unknown_keys),
        )

    def _pools(self, ctx: _VdomContext, names: list[str]) -> list[IpPoolInfo]:
        pools = []
        for name in names:
            pool = ctx.ippools.get(name)
            if pool is None:
                pool = IpPoolInfo(name=name, vdom=ctx.name, value=f"{name} (nicht gefunden)", notes=[_NOT_FOUND.format(name=name)])
            pools.append(pool)
        return pools

    # -- services ----------------------------------------------------------------

    def _svc_entries(self, ctx: _VdomContext, name: str, chain: list[str]) -> list[ServiceEntry]:
        path = chain + [name]
        if name in chain:
            return [ServiceEntry(kind="unresolvable", value=name, origin=path, note="Zirkelbezug: " + " > ".join(path))]
        if name in ctx.services:
            return self._custom_service(ctx.services[name], path)
        if name in ctx.service_groups:
            members = ctx.service_groups[name].raw("member") or []
            return [e for m in members for e in self._svc_entries(ctx, m, path)]
        return [
            ServiceEntry(
                kind="unresolvable",
                value=name,
                origin=path,
                note=f"Dienst '{name}' nicht gefunden (in den ausgewerteten Abschnitten).",
            )
        ]

    def _custom_service(self, obj: ConfigObject, origin: list[str]) -> list[ServiceEntry]:
        used: list[str] = []
        protocol = (_one(_get(obj, "protocol", used)) or "").upper()
        name = obj.name or ""
        if protocol == "TCP/UDP/SCTP":
            entries: list[ServiceEntry] = []
            for key, label in (("tcp-portrange", "TCP"), ("udp-portrange", "UDP"), ("sctp-portrange", "SCTP")):
                for token in obj.raw(key) or []:
                    parsed = _parse_portrange(token)
                    if parsed is None:
                        entries.append(
                            ServiceEntry(
                                kind="unresolvable",
                                protocol=label,
                                value=f"{label} {token}",
                                origin=list(origin),
                                note="Ungültiger Portbereich.",
                            )
                        )
                        continue
                    dst, src = parsed
                    value = f"{label}/{dst}" + (f" (Quellport {src})" if src else "")
                    entries.append(
                        ServiceEntry(kind="ports", protocol=label, value=value, dst_ports=dst, src_ports=src, origin=list(origin))
                    )
            if not entries:
                entries.append(
                    ServiceEntry(
                        kind="unresolvable",
                        protocol=protocol,
                        value=name,
                        origin=list(origin),
                        note="Protokoll TCP/UDP/SCTP, aber keine Ports definiert.",
                    )
                )
            return entries
        if protocol in ("ICMP", "ICMP6"):
            icmp_type, icmp_code = _one(obj.raw("icmptype")), _one(obj.raw("icmpcode"))
            if (icmp_type and not icmp_type.isdigit()) or (icmp_code and not icmp_code.isdigit()):
                return [ServiceEntry(kind="unresolvable", protocol=protocol, value=name, origin=list(origin), note="Ungültiger ICMP-Typ oder -Code.")]
            if icmp_type is None:
                value = f"{protocol} alle Typen"
            else:
                value = f"{protocol} Typ {icmp_type}" + (f" Code {icmp_code}" if icmp_code is not None else "")
            return [
                ServiceEntry(
                    kind="icmp",
                    protocol=protocol,
                    value=value,
                    icmp_type=int(icmp_type) if icmp_type else None,
                    icmp_code=int(icmp_code) if icmp_code else None,
                    origin=list(origin),
                )
            ]
        if protocol == "IP":
            number_text = _one(_get(obj, "protocol-number", used)) or "0"
            if not number_text.isdigit():
                return [ServiceEntry(kind="unresolvable", protocol=protocol, value=name, origin=list(origin), note="Ungültige Protokollnummer.")]
            number = int(number_text)
            value = "IP alle Protokolle" if number == 0 else f"IP-Protokoll {number}"
            return [ServiceEntry(kind="ip", protocol="IP", value=value, protocol_number=number, origin=list(origin))]
        return [
            ServiceEntry(
                kind="unresolvable",
                protocol=protocol or None,
                value=name,
                origin=list(origin),
                note=f"Unbekanntes Dienstprotokoll '{protocol}'.",
            )
        ]

    # -- policies --------------------------------------------------------------

    def resolve(self, policy: ConfigObject, position: int = 0) -> ResolvedPolicy:
        """Resolve one policy of 'firewall policy' or 'firewall policy6'."""
        ctx = self.contexts[policy.vdom]
        used: list[str] = []
        notes: list[str] = []
        is6 = policy.section == "firewall policy6"

        def is_on(key: str) -> bool:
            return _one(_get(policy, key, used)) == "enable"

        src_refs = [self._intf_ref(ctx, n, notes) for n in policy.raw("srcintf") or []]
        dst_refs = [self._intf_ref(ctx, n, notes) for n in policy.raw("dstintf") or []]

        def side(addr_key: str, addr6_key: str, negate_key: str, isdb_key: str, isdb_prefix: str) -> AddressSide:
            result = AddressSide(negate=is_on(negate_key))
            if is6:
                result.objects6 = list(policy.raw(addr_key) or [])
            else:
                result.objects = list(policy.raw(addr_key) or [])
                result.objects6 = list(policy.raw(addr6_key) or [])
            for name in result.objects:
                result.values.extend(self._addr_values(ctx, name, 4, []))
            for name in result.objects6:
                result.values.extend(self._addr_values(ctx, name, 6, []))
            if is_on(isdb_key):
                for suffix in ("name", "id", "group", "custom", "custom-group"):
                    result.internet_services.extend(policy.raw(f"{isdb_prefix}-{suffix}") or [])
                for name in result.internet_services:
                    result.values.append(_unresolvable(name, [name], _ISDB_NOTE))
            return result

        source = side("srcaddr", "srcaddr6", "srcaddr-negate", "internet-service-src", "internet-service-src")
        destination = side("dstaddr", "dstaddr6", "dstaddr-negate", "internet-service", "internet-service")

        service = ServiceSide(objects=list(policy.raw("service") or []), negate=is_on("service-negate"))
        for name in service.objects:
            service.entries.extend(self._svc_entries(ctx, name, []))
        if (source.internet_services or destination.internet_services) and not service.objects:
            notes.append("Dienste und Ziele bestimmt der Internet Service; sie sind nur auf dem Gerät auflösbar.")

        has4 = bool(source.objects or destination.objects)
        has6 = is6 or bool(source.objects6 or destination.objects6)
        ip_version = "4+6" if has4 and has6 else ("6" if has6 else "4")

        nat = NatInfo(enabled=is_on("nat"))
        if ctx.central_nat:
            nat.mode = "central"
        elif nat.enabled:
            nat.ippool = is_on("ippool")
            if nat.ippool:
                nat.mode = "pool"
                nat.pools = self._pools(ctx, list(policy.raw("poolname") or []))
            else:
                nat.mode = "interface"

        schedule = _one(policy.raw("schedule"))
        if schedule is None:
            notes.append("Kein Schedule gesetzt.")

        if ctx.central_nat:
            if any(v.kind == "vip" for v in destination.values):
                notes.append("Die Regel verweist auf eine VIP, obwohl Central NAT aktiv ist.")
            matching = [vip for vip in ctx.vips.values() if self._vip_intf_matches(vip, src_refs)]
            any_dst = any(
                v.kind == "network" and v.ip_version == 4 and v.value.endswith("/0") for v in destination.values
            )
            if any_dst and matching:
                names = ", ".join(vip.name for vip in matching[:10])
                if len(matching) > 10:
                    names += f" und {len(matching) - 10} weitere"
                notes.append(
                    "Central NAT: Das Ziel 0.0.0.0/0 umfasst alle VIPs mit passendem extintf "
                    f"({len(matching)}: {names}); sie wirken auf diese Regel ohne Verweis in der Policy."
                )
            else:
                for vip in matching:
                    if self._vip_overlaps(vip, destination.values):
                        notes.append(
                            f"Central NAT: VIP '{vip.name}' ({vip.value}) übersetzt auf ein Ziel dieser Regel; "
                            "die Übersetzung wirkt ohne Verweis in der Policy."
                        )

        action = _one(_get(policy, "action", used)) or ""
        status = _one(_get(policy, "status", used)) or ""
        logtraffic = _one(_get(policy, "logtraffic", used))
        return ResolvedPolicy(
            vdom=ctx.name,
            section=policy.section,
            position=position,
            policy_id=policy.name or "",
            name=_text(policy.raw("name")),
            uuid=_one(policy.raw("uuid")),
            status=status,
            enabled=status != "disable",
            action=action,
            ip_version=ip_version,
            src_interfaces=src_refs,
            dst_interfaces=dst_refs,
            src_zones=_dedupe(r.zone or r.name for r in src_refs),
            dst_zones=_dedupe(r.zone or r.name for r in dst_refs),
            source=source,
            destination=destination,
            service=service,
            nat=nat,
            users=list(policy.raw("users") or []),
            groups=list(policy.raw("groups") or []),
            schedule=schedule,
            logtraffic=logtraffic,
            profiles={key: _text(policy.raw(key)) for key in PROFILE_KEYS if policy.raw(key)},
            comments=_text(policy.raw("comments")),
            line=policy.line,
            notes=notes,
            defaults_applied=used,
            unknown_keys=dict(policy.unknown_keys),
        )

    @staticmethod
    def _vip_intf_matches(vip: VipMapping, src_refs: list[InterfaceRef]) -> bool:
        return vip.ext_intf in (None, "any") or any(
            r.kind == "any" or r.name == vip.ext_intf or r.zone == vip.ext_intf for r in src_refs
        )

    @staticmethod
    def _vip_overlaps(vip: VipMapping, dst_values: list[ResolvedValue]) -> bool:
        mapped: list[tuple[int, int]] = []
        for text in vip.mapped_ips:
            try:
                if "-" in text:
                    lo, hi = (ipaddress.ip_address(p) for p in text.split("-", 1))
                else:
                    lo = hi = ipaddress.ip_address(text)
            except ValueError:
                continue
            if lo.version == 4:
                mapped.append((int(lo), int(hi)))
        for value in dst_values:
            iv = _interval(value)
            if iv is None or iv[0] != 4:
                continue
            if value.kind == "network" and ipaddress.ip_network(value.value).prefixlen == 0:
                continue  # 'all' would match every VIP
            if any(lo <= iv[2] and iv[1] <= hi for lo, hi in mapped):
                return True
        return False

    def _implicit_deny(self, ctx: _VdomContext, position: int, with_v6: bool) -> ResolvedPolicy:
        values = [ResolvedValue(kind="network", value="0.0.0.0/0", ip_version=4)]
        if with_v6:
            values.append(ResolvedValue(kind="network", value="::/0", ip_version=6))
        any_ref = [InterfaceRef(name="any", kind="any", zone="any")]
        return ResolvedPolicy(
            vdom=ctx.name,
            section="implicit",
            position=position,
            policy_id=IMPLICIT_DENY_ID,
            implicit=True,
            name="Implizites Deny",
            status="enable",
            enabled=True,
            action="deny",
            ip_version="4+6" if with_v6 else "4",
            src_interfaces=any_ref,
            dst_interfaces=list(any_ref),
            src_zones=["any"],
            dst_zones=["any"],
            source=AddressSide(values=values),
            destination=AddressSide(values=[v.model_copy() for v in values]),
            service=ServiceSide(entries=[ServiceEntry(kind="ip", protocol="IP", value="IP alle Protokolle", protocol_number=0)]),
            notes=["Implizite Regel am Ende des VDOMs: Verkehr, den keine Regel davor erlaubt, wird verworfen."],
        )

    # -- central SNAT --------------------------------------------------------

    def _snat(self, ctx: _VdomContext, obj: ConfigObject, position: int) -> SnatRule:
        used: list[str] = []
        notes: list[str] = []
        status = _one(_get(obj, "status", used)) or ""
        nat = _one(_get(obj, "nat", used)) == "enable"

        def side(key: str) -> AddressSide:
            names = list(obj.raw(key) or [])
            return AddressSide(objects=names, values=[v for n in names for v in self._addr_values(ctx, n, 4, [])])

        pools = self._pools(ctx, list(obj.raw("nat-ippool") or []))
        if nat and not pools:
            notes.append("NAT auf die Adresse des Ausgangs-Interfaces.")
        return SnatRule(
            vdom=ctx.name,
            position=position,
            rule_id=obj.name or "",
            status=status,
            enabled=status != "disable",
            src_interfaces=[self._intf_ref(ctx, n, notes) for n in obj.raw("srcintf") or []],
            dst_interfaces=[self._intf_ref(ctx, n, notes) for n in obj.raw("dstintf") or []],
            orig_addr=side("orig-addr"),
            dst_addr=side("dst-addr"),
            protocol=_one(obj.raw("protocol")),
            orig_port=_one(obj.raw("orig-port")),
            nat=nat,
            pools=pools,
            comments=_text(obj.raw("comments")),
            notes=notes,
            defaults_applied=used,
            unknown_keys=dict(obj.unknown_keys),
        )

    # -- object tables -----------------------------------------------------------

    def _address_table(self, ctx: _VdomContext) -> list[ResolvedAddress]:
        rows: list[ResolvedAddress] = []
        for category, table, family in (
            ("address", ctx.address, 4),
            ("addrgrp", ctx.addrgrp, 4),
            ("address6", ctx.address6, 6),
            ("addrgrp6", ctx.addrgrp6, 6),
            ("vip", ctx.vip_objects, 4),
            ("vipgrp", ctx.vipgrp, 4),
        ):
            for name, obj in table.items():
                used: list[str] = []
                is_group = category in ("addrgrp", "addrgrp6", "vipgrp")
                rows.append(
                    ResolvedAddress(
                        name=name,
                        vdom=ctx.name,
                        category=category,
                        type=None if is_group else _one(_get(obj, "type", used)),
                        members=list(obj.raw("member") or []) if is_group else [],
                        exclude_members=list(obj.raw("exclude-member") or []),
                        values=self._addr_values(ctx, name, family, []),
                        comment=_text(obj.raw("comment") or obj.raw("comments")),
                        unknown_keys=dict(obj.unknown_keys),
                    )
                )
        return rows

    def _service_table(self, ctx: _VdomContext) -> list[ResolvedService]:
        rows: list[ResolvedService] = []
        for name, obj in ctx.services.items():
            used: list[str] = []
            rows.append(
                ResolvedService(
                    name=name,
                    vdom=ctx.name,
                    category="custom",
                    protocol=_one(_get(obj, "protocol", used)),
                    entries=self._svc_entries(ctx, name, []),
                    comment=_text(obj.raw("comment")),
                    unknown_keys=dict(obj.unknown_keys),
                )
            )
        for name, obj in ctx.service_groups.items():
            rows.append(
                ResolvedService(
                    name=name,
                    vdom=ctx.name,
                    category="group",
                    members=list(obj.raw("member") or []),
                    entries=self._svc_entries(ctx, name, []),
                    comment=_text(obj.raw("comment")),
                    unknown_keys=dict(obj.unknown_keys),
                )
            )
        return rows

    # -- whole configuration -------------------------------------------------------

    def resolve_vdom(self, ctx: _VdomContext) -> ResolvedVdom:
        policies: list[ResolvedPolicy] = []
        for section in ("firewall policy", "firewall policy6"):
            for obj in ctx.loaded.objects(section):
                policies.append(self.resolve(obj, position=len(policies) + 1))
        with_v6 = any("6" in p.ip_version for p in policies)
        policies.append(self._implicit_deny(ctx, len(policies) + 1, with_v6))
        notes = []
        if ctx.central_nat:
            notes.append(
                "Central NAT ist aktiv: VIPs wirken ohne Verweis in der Policy. "
                "DNAT (VIPs) und Central-SNAT stehen in eigenen Tabellen."
            )
        return ResolvedVdom(
            name=ctx.name,
            central_nat=ctx.central_nat,
            opmode=ctx.opmode,
            notes=notes,
            zones=self._zone_list(ctx),
            policies=policies,
            addresses=self._address_table(ctx),
            services=self._service_table(ctx),
            vips=list(ctx.vips.values()),
            ippools=list(ctx.ippools.values()),
            snat=[
                self._snat(ctx, obj, i + 1)
                for i, obj in enumerate(ctx.loaded.objects("firewall central-snat-map"))
            ],
        )

    def resolve_all(self) -> ResolvedConfig:
        tree = self.loaded.tree
        header = tree.header
        source = tree.source
        device = DeviceInfo(
            model=header.model,
            version=header.version,
            build=header.build,
            firmware_type=header.firmware_type,
            vdom_mode=tree.vdom_mode,
            input_name=source.name if source else None,
            input_sha256=source.sha256 if source else None,
            input_size_bytes=source.size_bytes if source else None,
        )
        notes = [f"Zeile {w.line}: {w.message}" if w.line else w.message for w in tree.warnings]
        return ResolvedConfig(
            device=device,
            interfaces=self.interfaces,
            vdoms=[self.resolve_vdom(ctx) for ctx in self.contexts.values()],
            coverage=self.loaded.coverage,
            notes=notes,
        )


def resolve_config(tree: ConfigTree) -> ResolvedConfig:
    """Load and resolve a parsed configuration."""
    return Resolver(load(tree)).resolve_all()
