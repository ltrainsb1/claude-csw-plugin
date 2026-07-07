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


if __name__ == "__main__":   # repo convention — every test file carries this
    unittest.main()
