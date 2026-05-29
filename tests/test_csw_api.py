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


class TestEndpointMatrix(unittest.TestCase):
    def test_matrix_is_a_list_of_rows(self):
        self.assertIsInstance(csw_api.ENDPOINT_MATRIX, list)
        self.assertTrue(len(csw_api.ENDPOINT_MATRIX) >= 2)
        for row in csw_api.ENDPOINT_MATRIX:
            self.assertEqual(len(row), 3)
            method, path_glob, deploys = row
            self.assertIn(method, {"GET", "POST", "PUT", "DELETE"})
            self.assertIsInstance(path_glob, str)
            self.assertIsInstance(deploys, frozenset)
            self.assertTrue(deploys.issubset({"saas", "selfhosted"}))

    def test_service_health_is_selfhosted_only(self):
        row = csw_api._match_endpoint("GET", "/openapi/v1/service_health")
        self.assertIsNotNone(row)
        _, _, deploys = row
        self.assertEqual(deploys, frozenset({"selfhosted"}))

    def test_rotate_certificates_is_saas_only(self):
        row = csw_api._match_endpoint("POST", "/openapi/v1/connector/rotate_certificates")
        self.assertIsNotNone(row)
        _, _, deploys = row
        self.assertEqual(deploys, frozenset({"saas"}))

    def test_unmatched_path_returns_none(self):
        self.assertIsNone(csw_api._match_endpoint("GET", "/openapi/v1/applications"))

    def test_method_mismatch_does_not_match(self):
        # service_health row is GET only; POST should not match it
        self.assertIsNone(csw_api._match_endpoint("POST", "/openapi/v1/service_health"))

    def test_query_string_is_ignored(self):
        row = csw_api._match_endpoint("GET", "/openapi/v1/service_health?verbose=true")
        self.assertIsNotNone(row)


class TestApplicable(unittest.TestCase):
    def test_saas_refuses_selfhosted_only_endpoint(self):
        ok, reason = csw_api.applicable("GET", "/openapi/v1/service_health", "saas")
        self.assertFalse(ok)
        self.assertIn("saas", reason)
        self.assertIn("service_health", reason)

    def test_selfhosted_refuses_saas_only_endpoint(self):
        ok, reason = csw_api.applicable(
            "POST", "/openapi/v1/connector/rotate_certificates", "selfhosted"
        )
        self.assertFalse(ok)
        self.assertIn("selfhosted", reason)

    def test_saas_allows_saas_endpoint(self):
        ok, reason = csw_api.applicable(
            "POST", "/openapi/v1/connector/rotate_certificates", "saas"
        )
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_selfhosted_allows_selfhosted_endpoint(self):
        ok, reason = csw_api.applicable("GET", "/openapi/v1/service_health", "selfhosted")
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_both_endpoint_allowed_on_either(self):
        ok, _ = csw_api.applicable("GET", "/openapi/v1/applications", "saas")
        self.assertTrue(ok)
        ok, _ = csw_api.applicable("GET", "/openapi/v1/applications", "selfhosted")
        self.assertTrue(ok)

    def test_unknown_deployment_allows_everything(self):
        ok, reason = csw_api.applicable("GET", "/openapi/v1/service_health", "unknown")
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_invalid_deployment_argument_is_permissive(self):
        ok, _ = csw_api.applicable("GET", "/openapi/v1/service_health", "garbage")
        self.assertTrue(ok)


class TestMakeRequestGate(unittest.TestCase):
    def setUp(self):
        os.environ["CSW_API_URL"] = "https://example.invalid"
        os.environ["CSW_API_KEY"] = "deadbeef"
        os.environ["CSW_API_SECRET"] = "cafebabe"
        os.environ["CSW_DEPLOYMENT"] = "saas"

    def tearDown(self):
        for k in ("CSW_API_URL", "CSW_API_KEY", "CSW_API_SECRET", "CSW_DEPLOYMENT"):
            os.environ.pop(k, None)

    def test_saas_refuses_service_health_without_network(self):
        # No network mock — if the gate fails, this would hit
        # https://example.invalid and the test would hang or error.
        result = csw_api.make_request("GET", "/openapi/v1/service_health")
        self.assertEqual(result["status"], 0)
        self.assertIn("not applicable", result["error"])
        self.assertIsNone(result["data"])

    def test_selfhosted_refuses_rotate_certificates_without_network(self):
        os.environ["CSW_DEPLOYMENT"] = "selfhosted"
        result = csw_api.make_request(
            "POST", "/openapi/v1/connector/rotate_certificates", body={}
        )
        self.assertEqual(result["status"], 0)
        self.assertIn("not applicable", result["error"])

    def test_unknown_deployment_does_not_gate(self):
        os.environ["CSW_DEPLOYMENT"] = "unknown"
        # Calling a S-only endpoint on unknown should attempt the network call,
        # not short-circuit. We assert by checking the error is NOT the gate
        # error — it should be a connection failure on the bogus URL instead.
        result = csw_api.make_request("GET", "/openapi/v1/service_health")
        self.assertEqual(result["status"], 0)
        self.assertNotIn("not applicable", result.get("error") or "")


class TestResolveDeployment(unittest.TestCase):
    def setUp(self):
        self._saved_urlopen = csw_api.urllib.request.urlopen

    def tearDown(self):
        csw_api.urllib.request.urlopen = self._saved_urlopen

    def _stub_urlopen(self, status, body_bytes):
        class _Resp:
            def __init__(self):
                self.status = status

            def read(self):
                return body_bytes

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def _fake_open(req, **kwargs):
            return _Resp()

        csw_api.urllib.request.urlopen = _fake_open

    def test_many_vrfs_is_selfhosted(self):
        self._stub_urlopen(200, b'[{"id":"a"},{"id":"b"},{"id":"c"}]')
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True),
            "selfhosted",
        )

    def test_single_vrf_is_saas(self):
        self._stub_urlopen(200, b'[{"id":"Default"}]')
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True), "saas"
        )

    def test_empty_vrf_list_is_saas(self):
        self._stub_urlopen(200, b"[]")
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True), "saas"
        )

    def test_403_is_saas(self):
        import urllib.error

        def _fake_open(req, **kwargs):
            raise urllib.error.HTTPError(
                "https://x/openapi/v1/vrfs", 403, "Forbidden", {}, None
            )

        csw_api.urllib.request.urlopen = _fake_open
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True), "saas"
        )

    def test_5xx_is_unknown(self):
        import urllib.error

        def _fake_open(req, **kwargs):
            raise urllib.error.HTTPError(
                "https://x/openapi/v1/vrfs", 503, "Down", {}, None
            )

        csw_api.urllib.request.urlopen = _fake_open
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True), "unknown"
        )

    def test_connection_failure_is_unknown(self):
        import urllib.error

        def _fake_open(req, **kwargs):
            raise urllib.error.URLError("name resolution failed")

        csw_api.urllib.request.urlopen = _fake_open
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True), "unknown"
        )

    def test_malformed_json_is_unknown(self):
        self._stub_urlopen(200, b"not json")
        self.assertEqual(
            csw_api.resolve_deployment("https://x", "k", "s", True), "unknown"
        )


if __name__ == "__main__":
    unittest.main()
