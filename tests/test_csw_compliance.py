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


if __name__ == "__main__":
    unittest.main()
