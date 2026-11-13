"""FortiOS defaults, in one place.

A backup only contains values that differ from the default. Whenever the
resolver needs a key that is missing, it takes the value from here and
records the key in ``defaults_applied`` of the result.

Every default that is not confirmed by the specification is an assumption:
see the ``ASSUMPTION(D…)`` markers and ANNAHMEN.md.
"""

from __future__ import annotations

# Section label -> key -> default values (as the parser would produce them).
DEFAULTS: dict[str, dict[str, list[str]]] = {
    "firewall policy": {
        "action": ["deny"],  # given by the specification
        "status": ["enable"],  # given by the specification
        "nat": ["disable"],  # ASSUMPTION(D1)
        "ippool": ["disable"],  # ASSUMPTION(D1)
        "logtraffic": ["utm"],  # ASSUMPTION(D2)
        "srcaddr-negate": ["disable"],  # ASSUMPTION(D1)
        "dstaddr-negate": ["disable"],  # ASSUMPTION(D1)
        "service-negate": ["disable"],  # ASSUMPTION(D1)
        "internet-service": ["disable"],  # ASSUMPTION(D1)
        "internet-service-src": ["disable"],  # ASSUMPTION(D1)
        "utm-status": ["disable"],  # ASSUMPTION(D1)
    },
    "firewall address": {
        "type": ["ipmask"],  # ASSUMPTION(D3)
        "subnet": ["0.0.0.0", "0.0.0.0"],  # ASSUMPTION(D3)
    },
    "firewall address6": {
        "type": ["ipprefix"],  # ASSUMPTION(D4)
        "ip6": ["::/0"],  # ASSUMPTION(D4)
    },
    "firewall addrgrp": {"exclude": ["disable"]},  # ASSUMPTION(D5)
    "firewall addrgrp6": {"exclude": ["disable"]},  # ASSUMPTION(D5)
    "firewall service custom": {
        "protocol": ["TCP/UDP/SCTP"],  # ASSUMPTION(D6)
        "protocol-number": ["0"],  # ASSUMPTION(D6): 0 = every IP protocol
    },
    "firewall vip": {
        "type": ["static-nat"],  # ASSUMPTION(D7)
        "extintf": ["any"],  # ASSUMPTION(D7)
        "portforward": ["disable"],  # ASSUMPTION(D7)
        "protocol": ["tcp"],  # ASSUMPTION(D7)
    },
    "firewall ippool": {"type": ["overload"]},  # ASSUMPTION(D8)
    "firewall central-snat-map": {
        "status": ["enable"],  # ASSUMPTION(D9)
        "nat": ["enable"],  # ASSUMPTION(D9)
    },
    "system settings": {
        "central-nat": ["disable"],  # ASSUMPTION(D10)
        "opmode": ["nat"],  # ASSUMPTION(D10)
    },
    "system zone": {"intrazone": ["deny"]},  # ASSUMPTION(D11)
    "system interface": {"vdom": ["root"]},  # ASSUMPTION(D12)
    "system sdwan > members": {"zone": ["virtual-wan-link"]},  # ASSUMPTION(D13)
}

# Policy sections share their defaults.
DEFAULTS["firewall policy6"] = DEFAULTS["firewall policy"]

# Name of the policy row that stands for the implicit deny at the end of a VDOM.
# ASSUMPTION(D14): FortiOS reports the implicit deny as policy ID 0.
IMPLICIT_DENY_ID = "0"

# Interface types -> German label for the documentation.
INTERFACE_TYPE_LABELS: dict[str, str] = {
    "physical": "physisch",
    "vlan": "VLAN",
    "aggregate": "Aggregat",
    "redundant": "Aggregat",
    "tunnel": "Tunnel",
    "loopback": "Loopback",
    "hard-switch": "Switch",
    "switch": "Switch",
    "vap-switch": "Switch",
    "sdwan-zone": "SD-WAN-Zone",
    "unknown": "nicht gesetzt",
}

# Policy keys that name a security profile.
PROFILE_KEYS: tuple[str, ...] = (
    "profile-type",
    "profile-group",
    "profile-protocol-options",
    "ssl-ssh-profile",
    "av-profile",
    "webfilter-profile",
    "dnsfilter-profile",
    "emailfilter-profile",
    "spamfilter-profile",
    "dlp-profile",
    "dlp-sensor",
    "file-filter-profile",
    "ips-sensor",
    "application-list",
    "voip-profile",
    "waf-profile",
    "icap-profile",
    "videofilter-profile",
    "ssh-filter-profile",
    "casb-profile",
    "virtual-patch-profile",
    "sctp-filter-profile",
    "diameter-filter-profile",
    "cifs-profile",
)


def default_for(section: str, key: str) -> list[str] | None:
    values = DEFAULTS.get(section, {}).get(key)
    return list(values) if values is not None else None
