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


if __name__ == "__main__":   # repo convention — every test file carries this
    unittest.main()
