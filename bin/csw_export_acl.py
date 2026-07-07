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


# Format registry: how each Cisco syntax differs. Renderers read this.
FORMATS = {
    "nxos":   {"mask": "wildcard", "acl_open": "ip access-list {name}",
               "objgroup": True},
    "ios-xr": {"mask": "prefix",   "acl_open": "ipv4 access-list {name}",
               "objgroup": True},
    "ios":    {"mask": "wildcard", "acl_open": "ip access-list extended {name}",
               "objgroup": False},
}


def render_addr(net, fmt):
    if net.prefixlen == 0:
        return "any"
    if net.prefixlen == net.max_prefixlen:
        return f"host {net.network_address}"
    if FORMATS[fmt]["mask"] == "prefix":
        return f"{net.network_address}/{net.prefixlen}"
    return f"{net.network_address} {net.hostmask}"


def render_ports(ports):
    if not ports:
        return ""
    p = ports[0]
    if p["op"] == "eq":
        return f"eq {p['val']}"
    return f"range {p['lo']} {p['hi']}"


def _group_name(ws_name, filter_name, side):
    return f"CSW_{sanitize_name(ws_name)}_{side}_{sanitize_name(filter_name)}"[:MAX_NAME]


def _emit_group(fmt, gname, addrset):
    """Object-group declaration lines for NX-OS / IOS-XR."""
    if fmt == "nxos":
        lines = [f"object-group ip address {gname}"]
    else:  # ios-xr
        lines = [f"object-group network ipv4 {gname}"]
    lines += [f"  {e.network_address}/{e.prefixlen}" for e in addrset["entries"]]
    return lines


def _addr_terms(fmt, ws_name, addrset, filter_name, side, groups):
    """Return the list of address-term strings for one ACE side. With
    object-group support and >1 entry, a single 'addrgroup NAME' term is
    returned and the group is registered in `groups`."""
    if not addrset["entries"]:
        return ["any"]
    if FORMATS[fmt]["objgroup"] and len(addrset["entries"]) > 1:
        gname = _group_name(ws_name, filter_name, side)
        if gname not in groups:
            groups[gname] = _emit_group(fmt, gname, addrset)
        term = f"addrgroup {gname}" if fmt == "nxos" else f"net-group {gname}"
        return [term]
    return [render_addr(e, fmt) for e in addrset["entries"]]


def render_acl(ir, fmt, ws_name, log_denies=False, acl_suffix=""):
    groups, body, seq = {}, [], 10
    acl_name = f"CSW_{sanitize_name(ws_name)}" + (f"_{acl_suffix}" if acl_suffix else "")
    for ace in ir["aces"]:
        commented = (ace["src"]["source"] == "empty" or ace["dst"]["source"] == "empty")
        prefix = "! " if commented else ""
        note = ""
        if commented:
            empty_side = "consumer" if ace["src"]["source"] == "empty" else "provider"
            note = f"  ! {empty_side} filter matched 0 hosts"
        src_terms = _addr_terms(fmt, ws_name, ace["src"],
                                ace["origin"]["cons_name"], "SRC", groups)
        dst_terms = _addr_terms(fmt, ws_name, ace["dst"],
                                ace["origin"]["prov_name"], "DST", groups)
        portstr = render_ports(ace["ports"])
        for s in src_terms:
            for d in dst_terms:
                parts = [ace["action"], ace["proto"], s, d]
                if portstr:
                    parts.append(portstr)
                body.append(f"{prefix}{seq} " + " ".join(parts) + note)
                seq += 10
    # Terminal explicit deny (CSW is a whitelist model).
    body.append(f"{seq} deny ip any any" + (" log" if log_denies else ""))
    # Assemble: object-groups first, then the ACL container + body.
    lines = []
    for gname in sorted(groups):
        lines += groups[gname]
    lines.append(FORMATS[fmt]["acl_open"].format(name=acl_name))
    lines += [f" {b}" for b in body]
    return lines


def _reverse_ir(ir):
    """Swap src/dst so the OUT list carries return traffic."""
    rev = []
    for ace in ir["aces"]:
        r = dict(ace, src=ace["dst"], dst=ace["src"])
        r["origin"] = {"policy_id": ace["origin"]["policy_id"],
                       "cons_name": ace["origin"]["prov_name"],
                       "prov_name": ace["origin"]["cons_name"]}
        rev.append(r)
    return {"aces": rev, "fidelity": ir["fidelity"], "has_errors": ir.get("has_errors", False)}


def render_split(ir, fmt, ws_name, log_denies=False):
    header = ["! layout=split — verify orientation: _IN applied inbound on the",
              "! consumer-facing interface, _OUT outbound (return traffic)."]
    inbound = render_acl(ir, fmt, ws_name, log_denies, acl_suffix="IN")
    outbound = render_acl(_reverse_ir(ir), fmt, ws_name, log_denies, acl_suffix="OUT")
    # Reversed TCP permits get 'established' so stateless hardware passes replies.
    outbound = [ln + " established"
                if (" permit tcp " in f" {ln} " and "deny ip any any" not in ln
                    and "access-list" not in ln)
                else ln
                for ln in outbound]
    return header + inbound + [""] + outbound


def render_header(ws_name, ws_id, version, cluster_url, fmt, layout,
                  now_iso, ace_count, host_count):
    return [
        "! ====================================================================",
        "! CSW policy export — generated config, review before applying",
        f"! cluster: {cluster_url}",
        f"! workspace: {ws_name} (id {ws_id})",
        f"! version: {version}   format: {fmt}   layout: {layout}",
        f"! generated: {now_iso}",
        f"! ACEs: {ace_count}   expanded hosts: {host_count}",
        "! Membership is a point-in-time snapshot; re-export after inventory changes.",
        "! ====================================================================",
    ]


def render_fidelity(notes):
    out = ["! ==== FIDELITY NOTES ===="]
    if not notes:
        out.append("! (none)")
    else:
        out += [f"! - {n}" for n in notes]
    return out


def _find_workspace(fetch, ws_query):
    got = fetch("GET", "/openapi/v1/applications")
    if got.get("status") != 200 or not isinstance(got.get("data"), list):
        return None
    for app in got["data"]:
        if str(app.get("id")) == str(ws_query) or app.get("name") == ws_query:
            return app
    return None


def export_acl(fetch, ws_query, fmt, layout, warn_members, log_denies,
               version, cluster_url, now_iso):
    if fmt not in FORMATS:
        return f"! ERROR: unknown format {fmt!r} (choose nxos|ios-xr|ios)", 2
    ws = _find_workspace(fetch, ws_query)
    if ws is None:
        return f"! ERROR: workspace {ws_query!r} not found", 2
    ws_id = ws.get("id")
    ver = version if version is not None else ws.get("latest_adm_version")
    path = f"/openapi/v1/applications/{ws_id}/policies"
    if ver is not None:
        path += f"?version={ver}"
    pres = fetch("GET", path)
    policies = pres.get("data") if pres.get("status") == 200 else None
    if not isinstance(policies, list):
        return f"! ERROR: could not read policies for workspace {ws.get('name')}", 2

    # Resolve every unique filter id once.
    ids = set()
    for p in policies:
        ids.add(p.get("consumer_filter_id"))
        ids.add(p.get("provider_filter_id"))
    resolved = {fid: resolve_filter(fetch, fid, warn_members)
                for fid in ids if fid is not None}

    ir = build_ir(policies, resolved)
    if layout == "split":
        body = render_split(ir, fmt, ws.get("name", str(ws_id)), log_denies)
    else:
        body = render_acl(ir, fmt, ws.get("name", str(ws_id)), log_denies)

    host_count = sum(r["addrset"]["total"] for r in resolved.values())
    header = render_header(ws.get("name", ""), ws_id, ver, cluster_url, fmt, layout,
                           now_iso, ace_count=len(ir["aces"]), host_count=host_count)
    fid = render_fidelity(ir["fidelity"])
    text = "\n".join(header + [""] + body + [""] + fid) + "\n"
    # Non-zero exit on any hard error: skipped policy (unreadable filter) or a
    # truncated (INCOMPLETE) filter expansion. IPv6 drops / empty filters are
    # lossy notes, not errors — they do not fail the run.
    exit_code = 1 if ir["has_errors"] else 0
    return text, exit_code


def build_fetch():
    """Lazy import so tests never need a live cluster. Mirrors csw_compliance."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from csw_api import make_request
    return lambda method, path, body=None: make_request(method, path, body=body)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(
        prog="csw_export_acl.py",
        description="Export a CSW workspace's policies to Cisco ACL syntax (read-only).")
    parser.add_argument("workspace", help="workspace name or id")
    parser.add_argument("--format", required=True, choices=["nxos", "ios-xr", "ios"])
    parser.add_argument("--layout", choices=["single", "split"], default="single")
    parser.add_argument("--warn-members", type=int, default=256)
    parser.add_argument("--log-denies", action="store_true")
    parser.add_argument("--version", type=int, default=None)
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2

    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cluster_url = os.environ.get("CSW_API_URL", "<cluster>")
    text, code = export_acl(build_fetch(), args.workspace, args.format, args.layout,
                            args.warn_members, args.log_denies, args.version,
                            cluster_url, now_iso)
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
