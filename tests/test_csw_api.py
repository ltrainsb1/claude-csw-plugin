import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_api  # noqa: E402


class TestSmoke(unittest.TestCase):
    def test_module_imports(self):
        self.assertTrue(hasattr(csw_api, "make_request"))


class TestDeploymentEnv(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.pop("CSW_DEPLOYMENT", None)

    def tearDown(self):
        os.environ.pop("CSW_DEPLOYMENT", None)
        if self._saved is not None:
            os.environ["CSW_DEPLOYMENT"] = self._saved

    def test_unset_returns_auto(self):
        self.assertEqual(csw_api._get_deployment_env(), "auto")

    def test_saas(self):
        os.environ["CSW_DEPLOYMENT"] = "saas"
        self.assertEqual(csw_api._get_deployment_env(), "saas")

    def test_selfhosted(self):
        os.environ["CSW_DEPLOYMENT"] = "selfhosted"
        self.assertEqual(csw_api._get_deployment_env(), "selfhosted")

    def test_unknown(self):
        os.environ["CSW_DEPLOYMENT"] = "unknown"
        self.assertEqual(csw_api._get_deployment_env(), "unknown")

    def test_uppercase_normalized(self):
        os.environ["CSW_DEPLOYMENT"] = "SaaS"
        self.assertEqual(csw_api._get_deployment_env(), "saas")

    def test_invalid_falls_back_to_auto(self):
        os.environ["CSW_DEPLOYMENT"] = "garbage"
        self.assertEqual(csw_api._get_deployment_env(), "auto")

    def test_deployment_values_constant(self):
        self.assertEqual(
            csw_api.DEPLOYMENT_VALUES,
            {"saas", "selfhosted", "auto", "unknown"},
        )


if __name__ == "__main__":
    unittest.main()
