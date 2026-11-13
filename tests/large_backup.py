"""Synthetic large backup for load tests of report.html.

Writes a made-up configuration of about the requested size with many
interfaces, addresses, groups, services and policies. It contains no real
data. Usable as a script:

    python tests/large_backup.py big.conf 8000000
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

HEADER = "#config-version=FG3H0F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin\n"


def _ip(i: int, base: int = 10) -> str:
    return f"{base}.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"


def build_large_backup(target_bytes: int = 8_000_000, seed: int = 4711) -> str:
    rnd = random.Random(seed)
    # Scale every table with the target size (about 8 MB -> factor 1).
    f = max(target_bytes / 10_400_000, 0.01)
    n_vlans = max(int(300 * f), 4)
    n_zones = max(int(40 * f), 2)
    n_addr = max(int(30000 * f), 50)
    n_groups = max(int(2500 * f), 5)
    n_svc = max(int(1500 * f), 10)
    n_svc_groups = max(int(200 * f), 2)
    n_policies = max(int(9000 * f), 20)

    out: list[str] = [HEADER, "config system interface\n"]
    for i in range(1, 9):
        out.append(f'    edit "port{i}"\n        set vdom "root"\n        set type physical\n    next\n')
    vlans = []
    for i in range(n_vlans):
        name = f"vl{100 + i}"
        vlans.append(name)
        out.append(
            f'    edit "{name}"\n        set vdom "root"\n        set ip {_ip(i * 256 + 1, 172)} 255.255.255.0\n'
            f'        set alias "Segment {i}"\n        set interface "port{1 + i % 8}"\n'
            f"        set vlanid {100 + i}\n    next\n"
        )
    out.append("end\nconfig system zone\n")
    per_zone = max(len(vlans) // n_zones, 1)
    zones = []
    for z in range(n_zones):
        members = vlans[z * per_zone : (z + 1) * per_zone]
        if not members:
            break
        zones.append(f"zone-{z:02d}")
        out.append(f'    edit "zone-{z:02d}"\n        set interface {" ".join(chr(34) + m + chr(34) for m in members)}\n    next\n')
    out.append("end\n")
    intf_names = zones + ["port1", "port2", "any"]

    out.append('config firewall address\n    edit "all"\n    next\n')
    addrs = []
    for i in range(n_addr):
        name = f"h-{i:06d}"
        addrs.append(name)
        kind = i % 20
        if kind == 0:
            body = f'        set type fqdn\n        set fqdn "host{i}.example.test"\n'
        elif kind == 1:
            body = f"        set type iprange\n        set start-ip {_ip(i * 4)}\n        set end-ip {_ip(i * 4 + 3)}\n"
        elif kind < 6:
            body = f"        set subnet {_ip(i * 256)} 255.255.255.0\n"
        else:
            body = f"        set subnet {_ip(i)} 255.255.255.255\n"
        out.append(f'    edit "{name}"\n        set uuid {rnd.getrandbits(128):032x}\n{body}'
                   f'        set comment "Synthetisches Objekt {i}"\n    next\n')  # fmt: skip
    out.append("end\nconfig firewall addrgrp\n")
    groups = []
    for g in range(n_groups):
        name = f"grp-{g:05d}"
        groups.append(name)
        members = rnd.sample(addrs, rnd.randint(3, 40))
        out.append(f'    edit "{name}"\n        set member {" ".join(chr(34) + m + chr(34) for m in members)}\n    next\n')
    out.append("end\n")

    out.append('config firewall service custom\n    edit "ALL"\n        set protocol IP\n    next\n')
    services = []
    for s in range(n_svc):
        name = f"svc-{s:05d}"
        services.append(name)
        port = 1024 + s
        out.append(f'    edit "{name}"\n        set tcp-portrange {port} {port + 10000}-{port + 10005}\n'
                   f"        set udp-portrange {port}\n    next\n")  # fmt: skip
    out.append("end\nconfig firewall service group\n")
    svc_groups = []
    for s in range(n_svc_groups):
        name = f"svcgrp-{s:04d}"
        svc_groups.append(name)
        out.append(f'    edit "{name}"\n        set member {" ".join(chr(34) + m + chr(34) for m in rnd.sample(services, 8))}\n    next\n')
    out.append("end\n")

    out.append("config firewall policy\n")
    for p in range(1, n_policies + 1):
        src = rnd.sample(addrs, rnd.randint(1, 4)) + rnd.sample(groups, rnd.randint(0, 2))
        dst = rnd.sample(addrs, rnd.randint(1, 3)) + rnd.sample(groups, rnd.randint(0, 1))
        svc = rnd.sample(services, rnd.randint(1, 3)) + rnd.sample(svc_groups, rnd.randint(0, 1))
        srcintf = rnd.sample(intf_names, rnd.randint(1, 2))
        dstintf = rnd.sample(intf_names, 1)
        q = chr(34)
        lines = [
            f"    edit {p}\n",
            f'        set name "regel-{p}"\n',
            f"        set uuid {rnd.getrandbits(128):032x}\n",
            f"        set srcintf {' '.join(q + i + q for i in srcintf)}\n",
            f"        set dstintf {' '.join(q + i + q for i in dstintf)}\n",
            f"        set srcaddr {' '.join(q + a + q for a in src)}\n",
            f"        set dstaddr {' '.join(q + a + q for a in dst)}\n",
            "        set action accept\n" if p % 4 else "",
            "        set status disable\n" if p % 17 == 0 else "",
            '        set schedule "always"\n',
            f"        set service {' '.join(q + s + q for s in svc)}\n",
            "        set logtraffic all\n" if p % 3 else "",
            "        set nat enable\n" if p % 5 == 0 else "",
            f'        set comments "Ticket CHG-{100000 + p}: synthetische Regel"\n',
            "    next\n",
        ]
        out.append("".join(lines))
    out.append("end\n")
    return "".join(out)


def write_large_backup(path: Path, target_bytes: int = 8_000_000) -> Path:
    path.write_text(build_large_backup(target_bytes), encoding="utf-8")
    return path


if __name__ == "__main__":  # pragma: no cover
    target = int(sys.argv[2]) if len(sys.argv) > 2 else 8_000_000
    written = write_large_backup(Path(sys.argv[1]), target)
    print(f"{written}: {written.stat().st_size} Bytes")
