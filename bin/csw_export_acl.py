#!/usr/bin/env python3
"""CSW → Cisco ACL export. Read-only. stdlib only.

Exports a CSW workspace's policies to NX-OS, IOS-XR, or classic IOS ACL
syntax. Pulls policies live, resolves the referenced inventory filters against
live cluster inventory, expands them to concrete addresses, summarizes, and
renders device config text to stdout.

IRON LAW: read-only. Emits text only; never pushes config to a device and
issues zero mutating CSW calls (the only POST is the read-style
inventory/search). No write-gate applies.
"""
import argparse
import ipaddress
import os
import re
import sys

MAX_NAME = 60
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


def sanitize_name(raw):
    """Uppercase, keep [A-Za-z0-9_-], collapse the rest to '_', clamp length."""
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", (raw or "").strip()).strip("_").upper()
    return (s[:MAX_NAME] or "UNNAMED")


def proto_name(num):
    return PROTO.get(num, "ip")


def parse_l4(l4):
    """CSW l4_param -> (proto_name, [PortSpec]).
    port is an inclusive [lo, hi] range; lo==hi -> eq. Missing/empty -> no port."""
    proto = proto_name(l4.get("proto"))
    port = l4.get("port")
    if not port:
        return proto, []
    lo, hi = port[0], port[-1]
    if lo == hi:
        return proto, [{"op": "eq", "val": lo}]
    return proto, [{"op": "range", "lo": lo, "hi": hi}]


def _address_query_cidr(query):
    """If the query is a single address term, return its CIDR string, else None."""
    if not isinstance(query, dict):
        return None
    field = query.get("field")
    if field not in ("ip", "address"):
        return None
    val = query.get("value")
    if query.get("type") == "subnet":
        return val
    if query.get("type") == "eq" and val is not None:
        return f"{val}/32" if ":" not in str(val) else f"{val}/128"
    return None


def _addrset(entries, total, large, source, v6_dropped=0, truncated=False):
    return {"entries": entries, "total": total, "large": large, "source": source,
            "v6_dropped": v6_dropped, "truncated": truncated}


def build_addrset(ips, query, warn_members, search_limit=None):
    cidr = _address_query_cidr(query)
    if cidr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:  # v6 subnet cannot go in a v4 ACL — fall through
                return _addrset([net], 1, False, "subnet_query")
        except ValueError:
            pass
    v4, v6 = [], 0
    for ip in ips:
        try:
            net = ipaddress.ip_network(f"{ip}/32" if ":" not in ip else f"{ip}/128",
                                       strict=False)
        except ValueError:
            continue
        if net.version == 4:
            v4.append(net)
        else:
            v6 += 1
    truncated = bool(search_limit) and len(ips) >= search_limit
    total = len(v4)
    if total == 0:
        return _addrset([], 0, False, "empty", v6_dropped=v6, truncated=truncated)
    entries = list(ipaddress.collapse_addresses(v4))
    return _addrset(entries, total, total > warn_members, "expanded",
                    v6_dropped=v6, truncated=truncated)
