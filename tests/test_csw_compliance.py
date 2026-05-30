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

    def test_missing_count_key_is_indeterminate_not_false_gap(self):
        # 200 OK but payload lacks the expected key → Indeterminate, never 0%/Gap.
        f = fake_fetch({
            ("GET", "/openapi/v1/inventory/count"): {"status": 200, "data": {"count": 100}},
            ("POST", "/openapi/v1/inventory/search"): {"status": 200, "data": {"wrong_key": 80}},
        })
        m = cc.PRIMITIVES["inventory_enforcement_ratio"](f)
        self.assertTrue(m["indeterminate"])
        self.assertEqual(m["value"], None)

    def test_list_endpoint_returning_dict_is_indeterminate(self):
        # A dict-wrapped list on a 200 must NOT crash and must NOT be read as empty.
        f = fake_fetch({("GET", "/openapi/v1/applications"):
                        {"status": 200, "data": {"results": [], "offset": 0}}})
        m = cc.PRIMITIVES["enforcing_workspaces_ratio"](f)
        self.assertTrue(m["indeterminate"])

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

    def _write_tmp(self, obj):
        import json, tempfile
        fd, p = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh)
        self.addCleanup(os.remove, p)
        return p

    def _base(self, controls):
        return {"framework": {"id": "t", "name": "T", "version": "1", "source": "s",
                              "retrieved": "2026-05-20", "disclaimer": "d"},
                "controls": controls}

    def test_unparseable_verdict_rule_raises_at_load(self):
        p = self._write_tmp(self._base([
            {"id": "X.1", "evidence": "enforcing_workspaces_ratio",
             "verdict_rule": {"satisfied": "~0.9", "else": "gap"}}]))
        with self.assertRaises(ValueError):
            cc.load_mapping(p)

    def test_non_object_control_raises_clean_error(self):
        p = self._write_tmp(self._base(["not-a-dict"]))
        with self.assertRaises(ValueError):
            cc.load_mapping(p)


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

    def test_primitive_exception_degrades_to_indeterminate(self):
        # A primitive that raises must NOT crash the whole report.
        mapping = self._mapping()
        original = cc.PRIMITIVES["enforcing_workspaces_ratio"]
        def boom(fetch, scope=None):
            raise RuntimeError("kaboom")
        cc.PRIMITIVES["enforcing_workspaces_ratio"] = boom
        try:
            out = cc.run_framework(mapping, fake_fetch({}))
        finally:
            cc.PRIMITIVES["enforcing_workspaces_ratio"] = original
        row = [r for r in out["rows"] if r["id"] == "A.1"][0]
        self.assertEqual(row["status"], "Indeterminate")
        self.assertIn("kaboom", row["reason"])
        # the other control still rendered — report survived
        self.assertEqual(sum(out["summary"].values()), 2)


class TestResolveMapping(unittest.TestCase):
    def test_resolves_by_id(self):
        # Depends on Task 7's mapping file.
        p = cc.resolve_mapping_path("pci-dss-4.0")
        self.assertTrue(p.endswith("pci-dss-4.0.json"))

    def test_unknown_id_lists_available(self):
        with self.assertRaises(cc.MappingNotFound):
            cc.resolve_mapping_path("does-not-exist-xyz")


class TestShippedMappings(unittest.TestCase):
    def test_pci_loads_and_is_valid(self):
        p = cc.resolve_mapping_path("pci-dss-4.0")
        m = cc.load_mapping(p)  # raises on any invalid control
        self.assertEqual(m["framework"]["id"], "pci-dss-4.0")
        self.assertGreaterEqual(len(m["controls"]), 10)
        # at least one honest not-evidenceable control
        self.assertTrue(any(c["evidence"] == "not_evidenceable" for c in m["controls"]))

    def test_nist_loads_and_is_valid(self):
        m = cc.load_mapping(cc.resolve_mapping_path("nist-800-53-rev5"))
        self.assertEqual(m["framework"]["id"], "nist-800-53-rev5")
        self.assertGreaterEqual(len(m["controls"]), 10)
        self.assertTrue(any(c["evidence"] == "not_evidenceable" for c in m["controls"]))

    def test_every_shipped_mapping_validates(self):
        # Any JSON dropped into mappings/ must pass strict validation. This guards
        # the "add a framework = add one JSON file" contract for all current and
        # future mappings, with no per-framework test needed.
        ids = cc.available_frameworks()
        self.assertGreaterEqual(len(ids), 2)  # pci + nist at minimum
        for fid in ids:
            with self.subTest(framework=fid):
                cc.load_mapping(cc.resolve_mapping_path(fid))


class TestRender(unittest.TestCase):
    def test_render_contains_disclaimer_and_all_buckets(self):
        fw = {"id": "pci", "name": "PCI DSS", "version": "v4.0",
              "source": "https://example/pci", "retrieved": "2026-05-20",
              "disclaimer": "CSW evidence status, not a compliance attestation."}
        results = {"summary": {"Satisfied": 1, "Partial": 0, "Gap": 1,
                               "Not-evidenceable": 1, "Indeterminate": 0},
                   "rows": [
                       {"id": "1.2.1", "intent": "seg", "csw_capability": "micro-seg",
                        "evidence_display": "1/1 (100%)", "status": "Satisfied", "pointer": "", "reason": ""},
                       {"id": "12.1", "intent": "gov", "csw_capability": "none",
                        "evidence_display": "", "status": "Not-evidenceable", "pointer": "(manual)", "reason": ""},
                   ]}
        md = cc.render_markdown(fw, results, "https://csw.example.com")
        self.assertIn("not a compliance attestation", md)
        self.assertIn("PCI DSS v4.0", md)
        for bucket in cc.ALL_STATUSES:
            self.assertIn(bucket, md)
        self.assertIn("12.1", md)  # not-evidenceable row is shown


class TestRequireListEnvelope(unittest.TestCase):
    """Envelope shape support added in PR #7 — Tetration 4.0.x clusters
    return {"results": [...]} on /sensors etc. instead of a top-level list."""

    def test_top_level_list_still_works(self):
        # Regression: pre-existing shape must still pass through unchanged.
        resp = {"status": 200, "data": [{"id": "a"}, {"id": "b"}]}
        items, bad = cc._require_list(resp, "/openapi/v1/sensors")
        self.assertIsNone(bad)
        self.assertEqual(items, [{"id": "a"}, {"id": "b"}])

    def test_envelope_with_results_key(self):
        resp = {"status": 200, "data": {"results": [{"uuid": "x"}, {"uuid": "y"}]}}
        items, bad = cc._require_list(resp, "/openapi/v1/sensors")
        self.assertIsNone(bad)
        self.assertEqual(items, [{"uuid": "x"}, {"uuid": "y"}])

    def test_empty_envelope_returns_empty_list(self):
        resp = {"status": 200, "data": {"results": []}}
        items, bad = cc._require_list(resp, "/openapi/v1/sensors")
        self.assertIsNone(bad)
        self.assertEqual(items, [])

    def test_dict_without_results_key_is_indeterminate(self):
        resp = {"status": 200, "data": {"foo": "bar"}}
        items, bad = cc._require_list(resp, "/openapi/v1/sensors")
        self.assertIsNone(items)
        self.assertTrue(bad["indeterminate"])
        self.assertIn("expected a list or", bad["reason"])

    def test_results_key_with_non_list_value_is_indeterminate(self):
        resp = {"status": 200, "data": {"results": "not a list"}}
        items, bad = cc._require_list(resp, "/openapi/v1/sensors")
        self.assertIsNone(items)
        self.assertTrue(bad["indeterminate"])


if __name__ == "__main__":
    unittest.main()
