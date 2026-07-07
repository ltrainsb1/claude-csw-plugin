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
