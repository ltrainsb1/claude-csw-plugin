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


# Cluster hard cap on inventory/search limit ("limit must be 50,000 or less").
# Mirrors bin/csw_compliance.py:216-221. A full-cap result is treated as
# possibly-truncated rather than silently complete (pre-flight #1).
SEARCH_LIMIT = 50000


def _extract_ips(data):
    """Accept a bare list or a {'results': [...]} envelope of inventory rows."""
    rows = data.get("results", []) if isinstance(data, dict) else data
    ips = []
    if isinstance(rows, list):
        for row in rows:
            ip = row.get("ip") if isinstance(row, dict) else None
            if ip:
                ips.append(ip)
    return ips


def resolve_filter(fetch, filter_id, warn_members):
    got = fetch("GET", f"/openapi/v1/inventory_filters/{filter_id}")
    fdata = (got["data"] if got.get("status") == 200
             and isinstance(got.get("data"), dict) else None)
    if fdata is None:
        # Fall back: the id may be a scope, not an inventory filter (pre-flight #2).
        sc = fetch("GET", f"/openapi/v1/scopes/{filter_id}")
        if sc.get("status") == 200 and isinstance(sc.get("data"), dict):
            fdata = sc["data"]
    if fdata is None:
        return {"id": filter_id, "name": filter_id,
                "addrset": build_addrset([], None, warn_members),
                "error": (f"id {filter_id} is neither an inventory filter nor a "
                          f"scope (may be an ADM cluster) — not exportable in v1")}
    query = fdata.get("query")
    name = fdata.get("name", filter_id)
    # Address-only queries short-circuit — no inventory call needed.
    if _address_query_cidr(query):
        return {"id": filter_id, "name": name,
                "addrset": build_addrset([], query, warn_members), "error": None}
    body = {"filter": query, "dimensions": ["ip"], "limit": SEARCH_LIMIT}
    res = fetch("POST", "/openapi/v1/inventory/search", body)
    if res.get("status") != 200:
        return {"id": filter_id, "name": name,
                "addrset": build_addrset([], None, warn_members),
                "error": f"inventory search failed for {name} (status {res.get('status')})"}
    ips = _extract_ips(res.get("data"))
    return {"id": filter_id, "name": name,
            "addrset": build_addrset(ips, query, warn_members, search_limit=SEARCH_LIMIT),
            "error": None}


def build_ir(policies, resolved):
    aces, fidelity, has_errors = [], [], False
    for pol in sorted(policies, key=lambda p: (p.get("priority", 0), str(p.get("id")))):
        pid_ = pol.get("id")
        cid, pid = pol.get("consumer_filter_id"), pol.get("provider_filter_id")
        cons, prov = resolved.get(cid), resolved.get(pid)
        bad = [r for r in (cons, prov) if r is None or r.get("error")]
        if bad:
            reason = "; ".join(r["error"] for r in bad if r and r.get("error")) or "missing filter"
            fidelity.append(f"policy {pid_} skipped: {reason}")
            has_errors = True
            continue
        for side in (cons, prov):
            a = side["addrset"]
            if a["source"] == "empty" and a.get("v6_dropped", 0) == 0:
                fidelity.append(f"policy {pid_}: filter '{side['name']}' matched 0 hosts")
            if a["large"]:
                fidelity.append(f"policy {pid_}: filter '{side['name']}' "
                                f"has {a['total']} members (large)")
            if a.get("v6_dropped"):
                fidelity.append(f"policy {pid_}: filter '{side['name']}' — "
                                f"{a['v6_dropped']} IPv6 members dropped (IPv4 ACL only in v1)")
            if a.get("truncated"):
                fidelity.append(f"policy {pid_}: filter '{side['name']}' matched >= "
                                f"{SEARCH_LIMIT} hosts — ACL INCOMPLETE (narrow the filter "
                                f"or use /inventory/stats)")
                has_errors = True
        action = "deny" if str(pol.get("action", "")).upper() == "DENY" else "permit"
        l4s = pol.get("l4_params") or [{}]
        for l4 in l4s:
            proto, ports = parse_l4(l4) if l4 else ("ip", [])
            aces.append({
                "action": action, "proto": proto, "ports": ports,
                "src": cons["addrset"], "dst": prov["addrset"],
                "priority": pol.get("priority", 0),
                "origin": {"policy_id": pid_,
                           "cons_name": cons["name"], "prov_name": prov["name"]},
            })
    return {"aces": aces, "fidelity": fidelity, "has_errors": has_errors}
