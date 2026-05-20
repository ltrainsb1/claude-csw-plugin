import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_attack as ca
import csw_compliance as cc


def fake_fetch(routes):
    calls = []
    def _fetch(method, path, body=None):
        calls.append((method, path, body))
        return routes.get((method, path), {"status": 404, "data": None, "error": "no route"})
    _fetch.calls = calls
    return _fetch


class TestCoverageStatus(unittest.TestCase):
    RULE = {"satisfied": ">=0.95", "partial": ">=0.5", "else": "gap"}

    def test_covered(self):
        self.assertEqual(ca.coverage_status("enforcing_workspaces_ratio",
                         cc.measurement(value=0.99), self.RULE), "Covered")

    def test_partial(self):
        self.assertEqual(ca.coverage_status("enforcing_workspaces_ratio",
                         cc.measurement(value=0.6), self.RULE), "Partial")

    def test_not_covered(self):
        self.assertEqual(ca.coverage_status("enforcing_workspaces_ratio",
                         cc.measurement(value=0.1), self.RULE), "Not-covered")

    def test_present_rule_covered(self):
        rule = {"satisfied": "present", "else": "gap"}
        self.assertEqual(ca.coverage_status("flow_visibility_present",
                         cc.measurement(value="present"), rule), "Covered")
        self.assertEqual(ca.coverage_status("flow_visibility_present",
                         cc.measurement(value="absent"), rule), "Not-covered")

    def test_out_of_scope_short_circuits(self):
        self.assertEqual(ca.coverage_status(ca.OUT_OF_SCOPE, cc.measurement(value=None), {}),
                         "Out-of-scope")

    def test_indeterminate(self):
        m = cc.measurement(indeterminate=True, reason="capability missing")
        self.assertEqual(ca.coverage_status("enforcing_workspaces_ratio", m, self.RULE),
                         "Indeterminate")


class TestRunMatrix(unittest.TestCase):
    def _mapping(self):
        return {"framework": {"id": "m", "name": "M", "version": "v1", "source": "s",
                              "retrieved": "2026-05-20", "disclaimer": "d"},
                "controls": [
                    {"id": "T1", "intent": "lat", "csw_capability": "micro-segmentation",
                     "evidence": "enforcing_workspaces_ratio",
                     "verdict_rule": {"satisfied": ">=0.95", "partial": ">=0.5", "else": "gap"}},
                    {"id": "T2", "intent": "phish", "csw_capability": "none",
                     "evidence": "out_of_scope"}]}

    def test_summary_and_pointer(self):
        f = fake_fetch({("GET", "/openapi/v1/applications"): {"status": 200, "data": [
            {"name": "a", "enforcement_enabled": False}]}})
        out = ca.run_matrix(self._mapping(), f)
        self.assertEqual(sum(out["summary"].values()), 2)
        self.assertEqual(out["summary"]["Out-of-scope"], 1)
        notcov = [r for r in out["rows"] if r["id"] == "T1"][0]
        self.assertEqual(notcov["status"], "Not-covered")
        self.assertTrue(notcov["pointer"])

    def test_primitive_exception_degrades(self):
        mapping = self._mapping()
        original = ca.PRIMITIVES["enforcing_workspaces_ratio"]
        ca.PRIMITIVES["enforcing_workspaces_ratio"] = lambda f, scope=None: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            out = ca.run_matrix(mapping, fake_fetch({}))
        finally:
            ca.PRIMITIVES["enforcing_workspaces_ratio"] = original
        row = [r for r in out["rows"] if r["id"] == "T1"][0]
        self.assertEqual(row["status"], "Indeterminate")
        self.assertEqual(sum(out["summary"].values()), 2)


class TestRender(unittest.TestCase):
    def test_header_and_buckets(self):
        fw = {"id": "m", "name": "MITRE ATT&CK (Enterprise)", "version": "v15",
              "source": "src", "retrieved": "2026-05-20", "disclaimer": "coverage not compliance."}
        results = {"summary": {"Covered": 2, "Partial": 0, "Not-covered": 1,
                               "Out-of-scope": 1, "Indeterminate": 0},
                   "rows": [{"id": "T1021", "intent": "lat", "csw_capability": "micro-seg",
                             "evidence_display": "9/10 (90%)", "status": "Covered",
                             "pointer": "", "reason": ""}]}
        md = ca.render_markdown(fw, results, "https://csw.example.com")
        self.assertIn("ATT&CK COVERAGE — MITRE ATT&CK (Enterprise) v15", md)
        self.assertNotIn("COMPLIANCE EVIDENCE", md)  # must NOT mislabel as compliance
        for bucket in ca.ALL_STATUSES:
            self.assertIn(bucket, md)


class TestShippedMatrices(unittest.TestCase):
    def test_mitre_loads_and_valid(self):
        m = cc.load_mapping(ca.resolve_mapping_path("mitre-attack-v15"), na_token=ca.OUT_OF_SCOPE)
        self.assertEqual(m["framework"]["id"], "mitre-attack-v15")
        self.assertGreaterEqual(len(m["controls"]), 10)
        self.assertTrue(any(c["evidence"] == ca.OUT_OF_SCOPE for c in m["controls"]))

    def test_every_shipped_matrix_validates(self):
        ids = ca.available_matrices()
        self.assertGreaterEqual(len(ids), 1)
        for mid in ids:
            with self.subTest(matrix=mid):
                cc.load_mapping(ca.resolve_mapping_path(mid), na_token=ca.OUT_OF_SCOPE)


if __name__ == "__main__":
    unittest.main()
