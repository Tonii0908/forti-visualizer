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
# ASSUMPTION(N2): security policies share the defaults of firewall policies (action deny).
DEFAULTS["firewall security-policy"] = DEFAULTS["firewall policy"]
# ASSUMPTION(L2): a local-in policy without action denies; negation and Internet Service are off.
DEFAULTS["firewall local-in-policy"] = {
    "action": ["deny"],
    "status": ["enable"],
    "srcaddr-negate": ["disable"],
    "dstaddr-negate": ["disable"],
    "service-negate": ["disable"],
    "internet-service-src": ["disable"],
}
DEFAULTS["firewall local-in-policy6"] = DEFAULTS["firewall local-in-policy"]

# Name of the policy row that stands for the implicit deny at the end of a VDOM.
# ASSUMPTION(D14): FortiOS reports the implicit deny as policy ID 0.
IMPLICIT_DENY_ID = "0"

# Predefined address objects that stand for "every address" even though the
# backup lists them without subnet/ip6. They are not flagged as "kein subnet".
# ASSUMPTION(D15): FortiOS defines 'all' (IPv4 and IPv6) as 0.0.0.0/0 and ::/0;
# 'all6' is treated the same (decided by Toni).
PREDEFINED_ANY_ADDRESSES = frozenset({"all", "all6"})

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

# ASSUMPTION(X7): names of objects that FortiOS creates on a factory-default
# device (FortiOS 6.x/7.x, partly older). Compiled from experience, not from a
# checked default configuration. Names are case-sensitive. An object with one
# of these names that nothing references is reported as "Unbenutztes
# Werksobjekt" instead of "Unbenutztes Objekt". A self-made object that happens
# to carry such a name is treated the same way.
FACTORY_OBJECTS: dict[str, frozenset[str]] = {
    "firewall address": frozenset(
        {
            "all", "none", "FIREWALL_AUTH_PORTAL_ADDRESS", "FABRIC_DEVICE", "SSLVPN_TUNNEL_ADDR1",
            "EMS_ALL_UNKNOWN_CLIENTS", "EMS_ALL_UNMANAGEABLE_CLIENTS", "FCTEMS_ALL_FORTICLOUD_SERVERS",
            "login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "gmail.com",
            "wildcard.google.com", "wildcard.dropbox.com",
            # Older releases (5.6/6.0): exemptions of the SSL inspection profiles.
            "apple", "appstore", "auth.gfx.ms", "citrix", "dropbox.com", "eease", "fortinet",
            "google-drive", "google-play", "google-play2", "google-play3", "Gotomeeting", "icloud",
            "itunes", "android", "skype", "swscan.apple.com", "update.microsoft.com", "microsoft",
            "adobe", "Adobe Login", "outlook", "verisign", "Windows update 2", "*.live.com",
        }
    ),
    "firewall addrgrp": frozenset({"G Suite", "Microsoft Office 365"}),
    "firewall address6": frozenset({"all", "none", "SSLVPN_TUNNEL_IPv6_ADDR1"}),
    "firewall addrgrp6": frozenset(),
    "firewall service custom": frozenset(
        {
            "ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6", "GRE", "AH", "ESP", "AOL", "BGP",
            "DHCP", "DNS", "FINGER", "FTP", "FTP_GET", "FTP_PUT", "GOPHER", "H323", "HTTP", "HTTPS",
            "IKE", "IMAP", "IMAPS", "Internet-Locator-Service", "IRC", "L2TP", "LDAP", "NetMeeting",
            "NFS", "NNTP", "NTP", "OSPF", "PC-Anywhere", "PING", "TIMESTAMP", "INFO_REQUEST",
            "INFO_ADDRESS", "ONC-RPC", "DCE-RPC", "POP3", "POP3S", "PPTP", "QUAKE", "RAUDIO",
            "REXEC", "RIP", "RLOGIN", "RSH", "SCCP", "SIP", "SIP-MSNmessenger", "SAMBA", "SMTP",
            "SMTPS", "SNMP", "SSH", "SYSLOG", "TALK", "TELNET", "TFTP", "MGCP", "UUCP", "VDOLIVE",
            "WAIS", "WINFRAME", "X-WINDOWS", "PING6", "MS-SQL", "MYSQL", "RDP", "VNC", "DHCP6",
            "SQUID", "SOCKS", "WINS", "RADIUS", "RADIUS-OLD", "CVSPSERVER", "AFS3", "TRACEROUTE",
            "RTSP", "MMS", "KERBEROS", "LDAP_UDP", "SMB", "NONE", "webproxy",
        }
    ),
    "firewall service group": frozenset({"Email Access", "Web Access", "Windows AD", "Exchange Server"}),
    "firewall vip": frozenset(),
    "firewall vipgrp": frozenset(),
    "firewall ippool": frozenset(),
}
