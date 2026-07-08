import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_export_acl as ea


def fake_fetch(routes):
    calls = []
    def _fetch(method, path, body=None):
        calls.append((method, path, body))
        return routes.get((method, path), {"status": 404, "data": None, "error": "no route"})
    _fetch.calls = calls
    return _fetch


class TestHelpers(unittest.TestCase):
    def test_sanitize_name(self):
        self.assertEqual(ea.sanitize_name("Prod App / Tier-1"), "PROD_APP_TIER-1")
        self.assertEqual(ea.sanitize_name(""), "UNNAMED")
        self.assertEqual(len(ea.sanitize_name("x" * 200)), 60)

    def test_proto_name(self):
        self.assertEqual(ea.proto_name(6), "tcp")
        self.assertEqual(ea.proto_name(17), "udp")
        self.assertEqual(ea.proto_name(1), "icmp")
        self.assertEqual(ea.proto_name(999), "ip")

    def test_parse_l4(self):
        proto, ports = ea.parse_l4({"proto": 6, "port": [443, 443]})
        self.assertEqual(proto, "tcp")
        self.assertEqual(ports, [{"op": "eq", "val": 443}])
        proto, ports = ea.parse_l4({"proto": 6, "port": [8000, 8100]})
        self.assertEqual(ports, [{"op": "range", "lo": 8000, "hi": 8100}])
        proto, ports = ea.parse_l4({"proto": 17})
        self.assertEqual((proto, ports), ("udp", []))


class TestAddrSet(unittest.TestCase):
    def test_collapse_contiguous(self):
        ips = [f"10.10.0.{i}" for i in range(256)]
        a = ea.build_addrset(ips, query=None, warn_members=256)
        self.assertEqual([str(e) for e in a["entries"]], ["10.10.0.0/24"])
        self.assertEqual(a["total"], 256)
        self.assertFalse(a["large"])
        self.assertEqual(a["source"], "expanded")

    def test_subnet_shortcircuit(self):
        q = {"type": "subnet", "field": "ip", "value": "10.20.0.0/16"}
        a = ea.build_addrset(["10.20.1.1"], query=q, warn_members=256)
        self.assertEqual([str(e) for e in a["entries"]], ["10.20.0.0/16"])
        self.assertEqual(a["source"], "subnet_query")

    def test_host_eq_shortcircuit(self):
        q = {"type": "eq", "field": "ip", "value": "10.1.1.5"}
        a = ea.build_addrset([], query=q, warn_members=256)
        self.assertEqual([str(e) for e in a["entries"]], ["10.1.1.5/32"])

    def test_empty(self):
        a = ea.build_addrset([], query=None, warn_members=256)
        self.assertEqual(a["entries"], [])
        self.assertEqual(a["source"], "empty")

    def test_large_flag(self):
        ips = [f"10.{i//256}.{i%256}.1" for i in range(300)]  # non-contiguous
        a = ea.build_addrset(ips, query=None, warn_members=256)
        self.assertTrue(a["large"])
        self.assertEqual(a["total"], 300)

    def test_ipv6_partitioned(self):
        a = ea.build_addrset(["10.0.0.1", "2001:db8::1"], query=None, warn_members=256)
        self.assertEqual([str(e) for e in a["entries"]], ["10.0.0.1/32"])
        self.assertEqual(a["total"], 1)
        self.assertEqual(a["v6_dropped"], 1)

    def test_truncation_flag(self):
        ips = [f"10.{i//256}.{i%256}.1" for i in range(10)]
        a = ea.build_addrset(ips, query=None, warn_members=256, search_limit=10)
        self.assertTrue(a["truncated"])
        b = ea.build_addrset(ips, query=None, warn_members=256, search_limit=1000)
        self.assertFalse(b["truncated"])


class TestResolveFilter(unittest.TestCase):
    def test_resolves_and_expands(self):
        routes = {
            ("GET", "/openapi/v1/inventory_filters/F1"):
                {"status": 200, "data": {"id": "F1", "name": "prod-web",
                 "query": {"type": "eq", "field": "os", "value": "linux"}}},
            ("POST", "/openapi/v1/inventory/search"):
                {"status": 200, "data": {"results": [{"ip": "10.10.0.1"}, {"ip": "10.10.0.2"}]}},
        }
        r = ea.resolve_filter(fake_fetch(routes), "F1", warn_members=256)
        self.assertIsNone(r["error"])
        self.assertEqual(r["name"], "prod-web")
        self.assertEqual(r["addrset"]["total"], 2)

    def test_bare_list_envelope(self):
        routes = {
            ("GET", "/openapi/v1/inventory_filters/F2"):
                {"status": 200, "data": {"id": "F2", "name": "n",
                 "query": {"type": "eq", "field": "os", "value": "linux"}}},
            ("POST", "/openapi/v1/inventory/search"):
                {"status": 200, "data": [{"ip": "10.0.0.9"}]},
        }
        r = ea.resolve_filter(fake_fetch(routes), "F2", warn_members=256)
        self.assertEqual(r["addrset"]["total"], 1)

    def test_filter_unreadable(self):
        r = ea.resolve_filter(fake_fetch({}), "F9", warn_members=256)
        self.assertIsNotNone(r["error"])
        self.assertEqual(r["addrset"]["source"], "empty")

    def test_scope_fallback(self):
        # inventory_filters/{id} 404s, but the id is a scope carrying a query.
        routes = {
            ("GET", "/openapi/v1/scopes/S1"):
                {"status": 200, "data": {"id": "S1", "name": "prod-scope",
                 "query": {"type": "subnet", "field": "ip", "value": "10.9.0.0/16"}}},
        }
        r = ea.resolve_filter(fake_fetch(routes), "S1", warn_members=256)
        self.assertIsNone(r["error"])
        self.assertEqual(r["name"], "prod-scope")
        self.assertEqual([str(e) for e in r["addrset"]["entries"]], ["10.9.0.0/16"])

    def test_truncation_flagged(self):
        many = [{"ip": f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"}
                for i in range(ea.SEARCH_LIMIT)]
        routes = {
            ("GET", "/openapi/v1/inventory_filters/F"):
                {"status": 200, "data": {"id": "F", "name": "big",
                 "query": {"type": "eq", "field": "os", "value": "linux"}}},
            ("POST", "/openapi/v1/inventory/search"):
                {"status": 200, "data": {"results": many}},
        }
        r = ea.resolve_filter(fake_fetch(routes), "F", warn_members=256)
        self.assertTrue(r["addrset"]["truncated"])


class TestBuildIR(unittest.TestCase):
    def _resolved(self):
        return {
            "C": {"id": "C", "name": "cons", "error": None,
                  "addrset": ea.build_addrset(["10.0.0.1"], None, 256)},
            "P": {"id": "P", "name": "prov", "error": None,
                  "addrset": ea.build_addrset(["10.0.1.1"], None, 256)},
        }

    def test_orders_by_priority_and_maps_action(self):
        policies = [
            {"id": "p2", "consumer_filter_id": "C", "provider_filter_id": "P",
             "action": "ALLOW", "priority": 200, "l4_params": [{"proto": 6, "port": [443, 443]}]},
            {"id": "p1", "consumer_filter_id": "C", "provider_filter_id": "P",
             "action": "DENY", "priority": 100, "l4_params": []},
        ]
        ir = ea.build_ir(policies, self._resolved())
        self.assertEqual([a["priority"] for a in ir["aces"]], [100, 200])
        self.assertEqual(ir["aces"][0]["action"], "deny")
        self.assertEqual(ir["aces"][0]["proto"], "ip")
        self.assertEqual(ir["aces"][1]["proto"], "tcp")

    def test_unreadable_filter_skips_with_fidelity(self):
        res = self._resolved()
        res["P"]["error"] = "boom"
        policies = [{"id": "p1", "consumer_filter_id": "C", "provider_filter_id": "P",
                     "action": "ALLOW", "priority": 1, "l4_params": []}]
        ir = ea.build_ir(policies, res)
        self.assertEqual(ir["aces"], [])
        self.assertTrue(any("boom" in n for n in ir["fidelity"]))
        self.assertTrue(ir["has_errors"])

    def test_empty_membership_notes(self):
        res = self._resolved()
        res["C"]["addrset"] = ea.build_addrset([], None, 256)
        policies = [{"id": "p1", "consumer_filter_id": "C", "provider_filter_id": "P",
                     "action": "ALLOW", "priority": 1, "l4_params": []}]
        ir = ea.build_ir(policies, res)
        self.assertTrue(any("0 hosts" in n for n in ir["fidelity"]))

    def test_truncation_sets_has_errors(self):
        res = self._resolved()
        res["C"]["addrset"]["truncated"] = True
        policies = [{"id": "p1", "consumer_filter_id": "C", "provider_filter_id": "P",
                     "action": "ALLOW", "priority": 1, "l4_params": []}]
        ir = ea.build_ir(policies, res)
        self.assertTrue(ir["has_errors"])
        self.assertTrue(any("INCOMPLETE" in n for n in ir["fidelity"]))

    def test_ipv6_dropped_note(self):
        res = self._resolved()
        res["C"]["addrset"]["v6_dropped"] = 3
        policies = [{"id": "p1", "consumer_filter_id": "C", "provider_filter_id": "P",
                     "action": "ALLOW", "priority": 1, "l4_params": []}]
        ir = ea.build_ir(policies, res)
        self.assertTrue(any("IPv6" in n for n in ir["fidelity"]))
        self.assertFalse(ir["has_errors"])  # v6 drop is lossy but not an error


class TestRenderHelpers(unittest.TestCase):
    def n(self, s):
        import ipaddress
        return ipaddress.ip_network(s)

    def test_addr_wildcard(self):
        self.assertEqual(ea.render_addr(self.n("10.10.0.0/24"), "nxos"), "10.10.0.0 0.0.0.255")
        self.assertEqual(ea.render_addr(self.n("10.10.0.0/24"), "ios"), "10.10.0.0 0.0.0.255")

    def test_addr_prefix(self):
        self.assertEqual(ea.render_addr(self.n("10.10.0.0/24"), "ios-xr"), "10.10.0.0/24")

    def test_addr_host_and_any(self):
        self.assertEqual(ea.render_addr(self.n("10.1.1.5/32"), "nxos"), "host 10.1.1.5")
        self.assertEqual(ea.render_addr(self.n("0.0.0.0/0"), "ios-xr"), "any")

    def test_ports(self):
        self.assertEqual(ea.render_ports([{"op": "eq", "val": 443}]), "eq 443")
        self.assertEqual(ea.render_ports([{"op": "range", "lo": 80, "hi": 90}]), "range 80 90")
        self.assertEqual(ea.render_ports([]), "")


class TestRenderSingle(unittest.TestCase):
    def _ir_one(self, src_ips, dst_ips, action="permit", proto="tcp", ports=None):
        return {"aces": [{
            "action": action, "proto": proto, "ports": ports or [{"op": "eq", "val": 443}],
            "src": ea.build_addrset(src_ips, None, 256),
            "dst": ea.build_addrset(dst_ips, None, 256),
            "priority": 100,
            "origin": {"policy_id": "p1", "cons_name": "cons", "prov_name": "prov"},
        }], "fidelity": [], "has_errors": False}

    def test_ios_raw_host_ace(self):
        out = "\n".join(ea.render_acl(self._ir_one(["10.0.0.1"], ["10.0.1.1"]), "ios", "WS"))
        self.assertIn("ip access-list extended CSW_WS", out)
        self.assertIn("permit tcp host 10.0.0.1 host 10.0.1.1 eq 443", out)
        self.assertIn("deny ip any any", out)

    def test_nxos_uses_objgroup_for_multi(self):
        ir = self._ir_one(["10.0.0.1", "10.0.2.1"], ["10.0.1.1"])  # 2 non-contiguous src
        out = "\n".join(ea.render_acl(ir, "nxos", "WS"))
        self.assertIn("object-group ip address", out)
        self.assertIn("addrgroup", out)

    def test_empty_membership_commented(self):
        ir = self._ir_one([], ["10.0.1.1"])  # empty consumer
        out = "\n".join(ea.render_acl(ir, "ios", "WS"))
        self.assertTrue(any(line.strip().startswith("!") and "0 hosts" in line
                            for line in out.splitlines()))

    def test_log_denies(self):
        out = "\n".join(ea.render_acl(self._ir_one(["10.0.0.1"], ["10.0.1.1"]),
                                      "ios", "WS", log_denies=True))
        self.assertIn("deny ip any any log", out)


class TestRenderSplit(unittest.TestCase):
    def _ir(self):
        return {"aces": [{
            "action": "permit", "proto": "tcp", "ports": [{"op": "eq", "val": 443}],
            "src": ea.build_addrset(["10.0.0.1"], None, 256),
            "dst": ea.build_addrset(["10.0.1.1"], None, 256),
            "priority": 100,
            "origin": {"policy_id": "p1", "cons_name": "c", "prov_name": "p"},
        }], "fidelity": [], "has_errors": False}

    def test_emits_in_and_out(self):
        out = "\n".join(ea.render_split(self._ir(), "ios", "WS"))
        self.assertIn("CSW_WS_IN", out)
        self.assertIn("CSW_WS_OUT", out)
        self.assertIn("established", out)
        self.assertIn("orientation", out.lower())

    def test_established_return_has_no_port(self):
        # The forward dest-port must NOT be carried onto the stateless return.
        out = "\n".join(ea.render_split(self._ir(), "ios", "WS"))
        self.assertNotIn("eq 443 established", out)
        self.assertIn("host 10.0.1.1 host 10.0.0.1 established", out)


class TestHeaderFidelity(unittest.TestCase):
    def test_header_stamps(self):
        h = "\n".join(ea.render_header("WS", "42", 7, "https://c", "nxos", "single",
                                       "2026-07-07T00:00:00Z", ace_count=3, host_count=9))
        self.assertIn("workspace: WS (id 42)", h)
        self.assertIn("version: 7", h)
        self.assertIn("format: nxos", h)
        self.assertIn("2026-07-07T00:00:00Z", h)

    def test_fidelity_none(self):
        self.assertIn("(none)", "\n".join(ea.render_fidelity([])))

    def test_fidelity_lists(self):
        out = "\n".join(ea.render_fidelity(["a note", "b note"]))
        self.assertIn("FIDELITY NOTES", out)
        self.assertIn("a note", out)


class TestExportAcl(unittest.TestCase):
    def _routes(self):
        return {
            ("GET", "/openapi/v1/applications"):
                {"status": 200, "data": [{"id": "42", "name": "prod",
                 "latest_adm_version": 7, "app_scope_id": "s1"}]},
            ("GET", "/openapi/v1/applications/42/policies?version=7"):
                {"status": 200, "data": [
                    {"id": "p1", "consumer_filter_id": "C", "provider_filter_id": "P",
                     "action": "ALLOW", "priority": 100,
                     "l4_params": [{"proto": 6, "port": [443, 443]}]}]},
            ("GET", "/openapi/v1/inventory_filters/C"):
                {"status": 200, "data": {"id": "C", "name": "cons",
                 "query": {"type": "subnet", "field": "ip", "value": "10.0.0.0/24"}}},
            ("GET", "/openapi/v1/inventory_filters/P"):
                {"status": 200, "data": {"id": "P", "name": "prov",
                 "query": {"type": "eq", "field": "ip", "value": "10.0.1.5"}}},
        }

    def test_happy_path(self):
        text, code = ea.export_acl(fake_fetch(self._routes()), "prod", "ios", "single",
                                   256, False, None, "https://c", "2026-07-07T00:00:00Z")
        self.assertEqual(code, 0)
        self.assertIn("permit tcp 10.0.0.0 0.0.0.255 host 10.0.1.5 eq 443", text)
        self.assertIn("workspace: prod (id 42)", text)

    def test_workspace_not_found(self):
        text, code = ea.export_acl(fake_fetch({("GET", "/openapi/v1/applications"):
                                   {"status": 200, "data": []}}),
                                   "ghost", "ios", "single", 256, False, None, "c", "t")
        self.assertEqual(code, 2)
        self.assertIn("ERROR", text)

    def test_unreadable_filter_nonzero_exit(self):
        routes = self._routes()
        del routes[("GET", "/openapi/v1/inventory_filters/P")]
        text, code = ea.export_acl(fake_fetch(routes), "prod", "ios", "single",
                                   256, False, None, "c", "t")
        self.assertEqual(code, 1)
        self.assertIn("FIDELITY NOTES", text)


class TestCli(unittest.TestCase):
    def test_argparse_missing_workspace_returns_2(self):
        # argparse errors on the missing positional; main() returns its code.
        code = ea.main(["--format", "ios"])
        self.assertEqual(code, 2)


class TestLiveShapes(unittest.TestCase):
    """Covers real Tetration response shapes discovered during post-flight."""

    def test_parse_policies_envelope(self):
        data = {"absolute_policies": [{"id": "a"}],
                "default_policies": [{"id": "d"}], "catch_all_action": "DENY"}
        pols, ca = ea._parse_policies(data)
        self.assertEqual([p["id"] for p in pols], ["a", "d"])
        self.assertEqual(ca, "DENY")

    def test_parse_policies_bare_list(self):
        pols, ca = ea._parse_policies([{"id": "x"}])
        self.assertEqual([p["id"] for p in pols], ["x"])
        self.assertIsNone(ca)

    def test_absolute_outranks_default(self):
        res = {"C": {"id": "C", "name": "c", "error": None,
                     "addrset": ea.build_addrset(["10.0.0.1"], None, 256)},
               "P": {"id": "P", "name": "p", "error": None,
                     "addrset": ea.build_addrset(["10.0.1.1"], None, 256)}}
        policies = [
            {"id": "def-hi", "rank": "DEFAULT", "priority": 10,
             "consumer_filter_id": "C", "provider_filter_id": "P", "action": "ALLOW", "l4_params": []},
            {"id": "abs-lo", "rank": "ABSOLUTE", "priority": 900,
             "consumer_filter_id": "C", "provider_filter_id": "P", "action": "DENY", "l4_params": []},
        ]
        ir = ea.build_ir(policies, res)
        # ABSOLUTE must come first despite its higher priority number.
        self.assertEqual([a["origin"]["policy_id"] for a in ir["aces"]], ["abs-lo", "def-hi"])

    def test_catch_all_allow_terminal(self):
        ir = {"aces": [], "fidelity": [], "has_errors": False}
        out = "\n".join(ea.render_acl(ir, "ios", "WS", catch_all="ALLOW"))
        self.assertIn("permit ip any any", out)
        self.assertNotIn("deny ip any any", out)

    def test_embedded_cluster_filter_resolves(self):
        # Policy embeds a Cluster-type consumer/provider filter WITH a query;
        # no /inventory_filters GET should be needed.
        routes = {
            ("GET", "/openapi/v1/applications"):
                {"status": 200, "data": [{"id": "9", "name": "ws", "latest_adm_version": 2}]},
            ("GET", "/openapi/v1/applications/9/policies?version=2"):
                {"status": 200, "data": {"catch_all_action": "DENY", "absolute_policies": [],
                 "default_policies": [{
                    "id": "pol1", "rank": "DEFAULT", "action": "ALLOW", "priority": 100,
                    "l4_params": [{"proto": 6, "port": [443, 443]}],
                    "consumer_filter_id": "CL1", "provider_filter_id": "CL2",
                    "consumer_filter": {"id": "CL1", "filter_type": "Cluster", "name": "web",
                        "query": {"type": "eq", "field": "os", "value": "linux"}},
                    "provider_filter": {"id": "CL2", "filter_type": "Cluster", "name": "db",
                        "query": {"type": "subnet", "field": "ip", "value": "10.5.0.0/24"}},
                 }]}},
            ("POST", "/openapi/v1/inventory/search"):
                {"status": 200, "data": {"results": [{"ip": "10.9.9.9"}]}},
        }
        f = fake_fetch(routes)
        text, code = ea.export_acl(f, "ws", "ios", "single", 256, False, None, "c", "t")
        self.assertEqual(code, 0)
        self.assertIn("permit tcp host 10.9.9.9 10.5.0.0 0.0.0.255 eq 443", text)
        # No fetch to /inventory_filters/* should have occurred (embedded filters used).
        self.assertFalse(any(p.startswith("/openapi/v1/inventory_filters/") for _, p, _ in f.calls))

    def test_listing_api_error_not_masked_as_not_found(self):
        routes = {("GET", "/openapi/v1/applications"):
                  {"status": 401, "data": {"error": "unknown credentials"}}}
        text, code = ea.export_acl(fake_fetch(routes), "ws", "ios", "single",
                                   256, False, None, "c", "t")
        self.assertEqual(code, 2)
        self.assertIn("could not list workspaces", text)
        self.assertIn("401", text)
        self.assertNotIn("not found", text)


class TestDeterminism(unittest.TestCase):
    def test_byte_identical(self):
        routes = TestExportAcl()._routes()
        a, _ = ea.export_acl(fake_fetch(routes), "prod", "nxos", "single",
                             256, False, None, "c", "t")
        b, _ = ea.export_acl(fake_fetch(routes), "prod", "nxos", "single",
                             256, False, None, "c", "t")
        self.assertEqual(a, b)


if __name__ == "__main__":   # repo convention — every test file carries this
    unittest.main()
