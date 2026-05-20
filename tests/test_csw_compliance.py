import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_compliance as cc


class TestEvaluateVerdict(unittest.TestCase):
    RULE = {"satisfied": ">=0.95", "partial": ">=0.5", "else": "gap"}

    def test_satisfied(self):
        m = cc.measurement(value=0.97, display="x")
        self.assertEqual(cc.evaluate_verdict("enforcing_workspaces_ratio", m, self.RULE), "Satisfied")

    def test_partial(self):
        m = cc.measurement(value=0.6, display="x")
        self.assertEqual(cc.evaluate_verdict("enforcing_workspaces_ratio", m, self.RULE), "Partial")

    def test_gap(self):
        m = cc.measurement(value=0.1, display="x")
        self.assertEqual(cc.evaluate_verdict("enforcing_workspaces_ratio", m, self.RULE), "Gap")

    def test_present_rule(self):
        rule = {"satisfied": "present", "else": "gap"}
        self.assertEqual(cc.evaluate_verdict("flow_visibility_present", cc.measurement(value="present"), rule), "Satisfied")
        self.assertEqual(cc.evaluate_verdict("flow_visibility_present", cc.measurement(value="absent"), rule), "Gap")

    def test_not_evidenceable_short_circuits(self):
        self.assertEqual(cc.evaluate_verdict("not_evidenceable", cc.measurement(value=None), {}), "Not-evidenceable")

    def test_indeterminate(self):
        m = cc.measurement(indeterminate=True, reason="capability missing")
        self.assertEqual(cc.evaluate_verdict("enforcing_workspaces_ratio", m, self.RULE), "Indeterminate")


def fake_fetch(routes):
    """routes: dict[(method, path)] -> envelope. Records calls."""
    calls = []
    def _fetch(method, path, body=None):
        calls.append((method, path, body))
        return routes.get((method, path), {"status": 404, "data": None, "error": "no route"})
    _fetch.calls = calls
    return _fetch


class TestPrimitives(unittest.TestCase):
    def test_enforcing_workspaces_ratio(self):
        f = fake_fetch({("GET", "/openapi/v1/applications"): {"status": 200, "data": [
            {"name": "prod-a", "enforcement_enabled": True},
            {"name": "prod-b", "enforcement_enabled": True},
            {"name": "dev-c", "enforcement_enabled": False},
        ]}})
        m = cc.PRIMITIVES["enforcing_workspaces_ratio"](f)
        self.assertAlmostEqual(m["value"], 2/3)
        self.assertIn("2/3", m["display"])

    def test_scope_filter(self):
        f = fake_fetch({("GET", "/openapi/v1/applications"): {"status": 200, "data": [
            {"name": "prod-a", "enforcement_enabled": True},
            {"name": "dev-c", "enforcement_enabled": False},
        ]}})
        m = cc.PRIMITIVES["enforcing_workspaces_ratio"](f, scope="prod")
        self.assertEqual(m["value"], 1.0)

    def test_403_is_indeterminate(self):
        f = fake_fetch({("GET", "/openapi/v1/applications"): {"status": 403, "data": None, "error": "Forbidden"}})
        m = cc.PRIMITIVES["enforcing_workspaces_ratio"](f)
        self.assertTrue(m["indeterminate"])
        self.assertIn("capability missing", m["reason"])

    def test_flow_visibility_present(self):
        f = fake_fetch({("POST", "/openapi/v1/flow_search/flows"): {"status": 200, "data": {"results": [{"x": 1}]}}})
        m = cc.PRIMITIVES["flow_visibility_present"](f)
        self.assertEqual(m["value"], "present")

    def test_flow_visibility_absent(self):
        f = fake_fetch({("POST", "/openapi/v1/flow_search/flows"): {"status": 200, "data": {"results": []}}})
        m = cc.PRIMITIVES["flow_visibility_present"](f)
        self.assertEqual(m["value"], "absent")

    def test_registry_matches_catalog(self):
        # Registry (callables) must exactly match the loader's catalog (names).
        self.assertEqual(set(cc.PRIMITIVES), set(cc.KNOWN_PRIMITIVES))

    def test_no_mutating_paths(self):
        # Guard: exercising every primitive must never call a mutating endpoint.
        f = fake_fetch({})
        for name, fn in cc.PRIMITIVES.items():
            fn(f)
        banned = ("enable_enforce", "disable_enforce", "submit_run", "commit_query_changes")
        for method, path, _ in f.calls:
            self.assertIn(method, ("GET", "POST"))
            self.assertFalse(any(b in path for b in banned), f"{name} hit mutating path {path}")
            if method == "POST":
                self.assertIn(path, ("/openapi/v1/inventory/search", "/openapi/v1/flow_search/flows"))


class TestLoadMapping(unittest.TestCase):
    FX = os.path.join(os.path.dirname(__file__), "fixtures")

    def test_loads_good_mapping(self):
        m = cc.load_mapping(os.path.join(self.FX, "good_mapping.json"))
        self.assertEqual(m["framework"]["id"], "test-fw-1.0")
        self.assertTrue(len(m["controls"]) >= 1)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            cc.load_mapping(os.path.join(self.FX, "nope.json"))

    def test_unknown_primitive_raises(self):
        with self.assertRaises(ValueError):
            cc.load_mapping(os.path.join(self.FX, "bad_mapping.json"))


class TestRunFramework(unittest.TestCase):
    def _mapping(self):
        return {
            "framework": {"id": "t", "name": "T", "version": "1", "source": "s",
                          "retrieved": "2026-05-20", "disclaimer": "d"},
            "controls": [
                {"id": "A.1", "intent": "seg", "csw_capability": "micro-segmentation",
                 "evidence": "enforcing_workspaces_ratio",
                 "verdict_rule": {"satisfied": ">=0.95", "partial": ">=0.5", "else": "gap"}},
                {"id": "A.2", "intent": "gov", "csw_capability": "none", "evidence": "not_evidenceable"},
            ],
        }

    def test_summary_counts_sum_to_controls(self):
        f = fake_fetch({("GET", "/openapi/v1/applications"): {"status": 200, "data": [
            {"name": "a", "enforcement_enabled": True}]}})
        out = cc.run_framework(self._mapping(), f)
        self.assertEqual(sum(out["summary"].values()), 2)
        self.assertEqual(out["summary"]["Satisfied"], 1)
        self.assertEqual(out["summary"]["Not-evidenceable"], 1)

    def test_pointer_for_gap(self):
        f = fake_fetch({("GET", "/openapi/v1/applications"): {"status": 200, "data": [
            {"name": "a", "enforcement_enabled": False}]}})
        out = cc.run_framework(self._mapping(), f)
        gap_row = [r for r in out["rows"] if r["id"] == "A.1"][0]
        self.assertEqual(gap_row["status"], "Gap")
        self.assertTrue(gap_row["pointer"])  # non-empty pointer for a gap


if __name__ == "__main__":
    unittest.main()
