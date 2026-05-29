import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bin"))
import csw_api  # noqa: E402


class TestSmoke(unittest.TestCase):
    def test_module_imports(self):
        self.assertTrue(hasattr(csw_api, "make_request"))


class TestDocsMentionDeployment(unittest.TestCase):
    def test_module_docstring_mentions_csw_deployment(self):
        self.assertIn("CSW_DEPLOYMENT", csw_api.__doc__ or "")

    def test_module_docstring_mentions_get_deployment_flag(self):
        self.assertIn("--get-deployment", csw_api.__doc__ or "")


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


class TestMatrixCompleteness(unittest.TestCase):
    """Pin the matrix to exactly the two non-Both rows from the design doc.
    Any future change to ENDPOINT_MATRIX must update this test AND
    skills/csw/api-reference.md's Deploy column in the same commit."""

    def test_matrix_has_exactly_two_rows(self):
        self.assertEqual(len(csw_api.ENDPOINT_MATRIX), 2)

    def test_matrix_rows_are_the_documented_two(self):
        rows_as_tuples = sorted(
            (m, p, tuple(sorted(d))) for m, p, d in csw_api.ENDPOINT_MATRIX
        )
        expected = sorted([
            ("GET", "/openapi/v1/service_health", ("selfhosted",)),
            ("POST", "/openapi/v1/connector/rotate_certificates", ("saas",)),
        ])
        self.assertEqual(rows_as_tuples, expected)


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


class TestDeploymentCache(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.mkdtemp(prefix="csw_cache_test_")
        os.environ["CLAUDE_PLUGIN_ROOT"] = self._tmp

    def tearDown(self):
        import shutil
        os.environ.pop("CLAUDE_PLUGIN_ROOT", None)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_read_returns_none_when_no_cache(self):
        self.assertIsNone(csw_api._read_cache("https://x.example.com"))

    def test_roundtrip_saas(self):
        ok = csw_api._write_cache("https://x.example.com", "saas")
        self.assertTrue(ok)
        self.assertEqual(csw_api._read_cache("https://x.example.com"), "saas")

    def test_roundtrip_selfhosted(self):
        csw_api._write_cache("https://x.example.com", "selfhosted")
        self.assertEqual(csw_api._read_cache("https://x.example.com"), "selfhosted")

    def test_different_urls_different_cache(self):
        csw_api._write_cache("https://a.example.com", "saas")
        csw_api._write_cache("https://b.example.com", "selfhosted")
        self.assertEqual(csw_api._read_cache("https://a.example.com"), "saas")
        self.assertEqual(csw_api._read_cache("https://b.example.com"), "selfhosted")

    def test_refuses_to_cache_auto(self):
        # auto should never end up cached; it's the unresolved state.
        ok = csw_api._write_cache("https://x.example.com", "auto")
        self.assertFalse(ok)
        self.assertIsNone(csw_api._read_cache("https://x.example.com"))

    def test_refuses_to_cache_unknown(self):
        # unknown is a probe failure — letting it re-trigger on every call
        # keeps the gate honest if the cluster comes back online.
        ok = csw_api._write_cache("https://x.example.com", "unknown")
        self.assertFalse(ok)
        self.assertIsNone(csw_api._read_cache("https://x.example.com"))

    def test_unwritable_dir_returns_false_not_raises(self):
        os.environ["CLAUDE_PLUGIN_ROOT"] = "/nonexistent/definitely/not/writable"
        ok = csw_api._write_cache("https://x.example.com", "saas")
        self.assertFalse(ok)

    def test_corrupt_cache_treated_as_none(self):
        import hashlib
        key = hashlib.sha256(b"https://x.example.com").hexdigest()[:12]
        cache_path = os.path.join(self._tmp, f".csw_deployment_cache_{key}")
        with open(cache_path, "w") as f:
            f.write("garbage")
        self.assertIsNone(csw_api._read_cache("https://x.example.com"))


class TestAutoResolution(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.mkdtemp(prefix="csw_auto_test_")
        os.environ["CLAUDE_PLUGIN_ROOT"] = self._tmp
        os.environ["CSW_API_URL"] = "https://probe.example.invalid"
        os.environ["CSW_API_KEY"] = "k"
        os.environ["CSW_API_SECRET"] = "s"
        os.environ["CSW_DEPLOYMENT"] = "auto"
        self._saved_urlopen = csw_api.urllib.request.urlopen

    def tearDown(self):
        import shutil
        os.environ.pop("CLAUDE_PLUGIN_ROOT", None)
        for k in ("CSW_API_URL", "CSW_API_KEY", "CSW_API_SECRET", "CSW_DEPLOYMENT"):
            os.environ.pop(k, None)
        shutil.rmtree(self._tmp, ignore_errors=True)
        csw_api.urllib.request.urlopen = self._saved_urlopen

    def test_auto_resolves_via_probe_then_caches(self):
        # Stub the probe to return a saas-shaped /vrfs (one entry).
        probe_calls = {"n": 0}

        class _Resp:
            status = 200
            def read(self): return b'[{"id":"Default"}]'
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def _fake_open(req, **kwargs):
            probe_calls["n"] += 1
            return _Resp()

        csw_api.urllib.request.urlopen = _fake_open

        # First call to a refused (selfhosted-only) endpoint:
        # auto -> probe -> saas -> gate REFUSES (since service_health is H-only).
        r = csw_api.make_request("GET", "/openapi/v1/service_health")
        self.assertEqual(r["status"], 0)
        self.assertIn("not applicable", r["error"])
        # Cache should now be populated.
        self.assertEqual(csw_api._read_cache(os.environ["CSW_API_URL"]), "saas")
        # Second call: cache hit, NO new probe.
        before = probe_calls["n"]
        r2 = csw_api.make_request("GET", "/openapi/v1/service_health")
        self.assertEqual(r2["status"], 0)
        self.assertEqual(probe_calls["n"], before, "probe should not re-run")

    def test_explicit_env_var_skips_probe(self):
        os.environ["CSW_DEPLOYMENT"] = "saas"
        sentinel = {"called": False}

        def _fake_open(req, **kwargs):
            sentinel["called"] = True
            raise AssertionError("should not have been called")

        csw_api.urllib.request.urlopen = _fake_open
        r = csw_api.make_request("GET", "/openapi/v1/service_health")
        self.assertEqual(r["status"], 0)
        self.assertIn("not applicable", r["error"])
        self.assertFalse(sentinel["called"])


class TestGetDeploymentCLI(unittest.TestCase):
    def test_get_deployment_flag_prints_resolved_value(self):
        # We can't easily invoke main() in-process because it sys.exits,
        # so use subprocess.
        import subprocess
        env = os.environ.copy()
        env["CSW_API_URL"] = "https://probe.example.invalid"
        env["CSW_API_KEY"] = "k"
        env["CSW_API_SECRET"] = "s"
        env["CSW_DEPLOYMENT"] = "saas"  # explicit so no probe
        result = subprocess.run(
            ["python3", os.path.join(
                os.path.dirname(__file__), "..", "bin", "csw_api.py"),
             "--get-deployment"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "saas")


class TestVerbChangeBodyDrop(unittest.TestCase):
    def setUp(self):
        os.environ["CSW_API_URL"] = "https://example.invalid"
        os.environ["CSW_API_KEY"] = "deadbeef"
        os.environ["CSW_API_SECRET"] = "cafebabe"
        os.environ["CSW_DEPLOYMENT"] = "selfhosted"

    def tearDown(self):
        for k in ("CSW_API_URL", "CSW_API_KEY", "CSW_API_SECRET", "CSW_DEPLOYMENT"):
            os.environ.pop(k, None)

    def _capture_stderr(self):
        import io, contextlib
        buf = io.StringIO()
        return buf, contextlib.redirect_stderr(buf)

    def test_post_to_get_with_body_emits_drop_note(self):
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request(
                "POST", "/openapi/v1/inventory/dimensions", body={"foo": "bar"}
            )
        err = buf.getvalue()
        self.assertIn("dropping POST body", err)
        self.assertIn("/openapi/v1/inventory/dimensions", err)

    def test_post_to_get_with_no_body_no_drop_note(self):
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request("POST", "/openapi/v1/inventory/dimensions")
        err = buf.getvalue()
        # Rewrite note should still fire, but no body-drop note
        self.assertIn("rewriting", err)
        self.assertNotIn("dropping POST body", err)

    def test_same_verb_rewrite_does_not_drop_body(self):
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request(
                "POST", "/openapi/v1/flow_search/flows", body={"x": 1}
            )
        err = buf.getvalue()
        # Path rewrites, but POST stays POST — no body drop
        self.assertIn("rewriting", err)
        self.assertNotIn("dropping POST body", err)

    def test_no_rewrite_no_body_drop(self):
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request(
                "POST", "/openapi/v1/inventory/search", body={"filter": {}}
            )
        err = buf.getvalue()
        self.assertNotIn("dropping POST body", err)


class TestMakeRequestAlias(unittest.TestCase):
    def setUp(self):
        os.environ["CSW_API_URL"] = "https://example.invalid"
        os.environ["CSW_API_KEY"] = "deadbeef"
        os.environ["CSW_API_SECRET"] = "cafebabe"
        os.environ["CSW_DEPLOYMENT"] = "selfhosted"

    def tearDown(self):
        for k in ("CSW_API_URL", "CSW_API_KEY", "CSW_API_SECRET", "CSW_DEPLOYMENT"):
            os.environ.pop(k, None)

    def _capture_stderr(self):
        import io
        import contextlib
        buf = io.StringIO()
        return buf, contextlib.redirect_stderr(buf)

    def test_selfhosted_flow_search_emits_rewrite_note(self):
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request("POST", "/openapi/v1/flow_search/flows", body={"x": 1})
        err = buf.getvalue()
        self.assertIn("rewriting", err)
        self.assertIn("/openapi/v1/flow_search/flows", err)
        self.assertIn("/openapi/v1/flowsearch", err)
        self.assertIn("on-prem 4.0.x", err)

    def test_saas_does_not_rewrite(self):
        os.environ["CSW_DEPLOYMENT"] = "saas"
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request("POST", "/openapi/v1/flow_search/flows", body={"x": 1})
        err = buf.getvalue()
        self.assertNotIn("rewriting", err)

    def test_unknown_does_not_rewrite(self):
        os.environ["CSW_DEPLOYMENT"] = "unknown"
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request("POST", "/openapi/v1/flow_search/flows", body={"x": 1})
        err = buf.getvalue()
        self.assertNotIn("rewriting", err)

    def test_non_aliased_path_emits_no_note(self):
        # GET /applications is B with no rewrite rule
        buf, redirect = self._capture_stderr()
        with redirect:
            csw_api.make_request("GET", "/openapi/v1/applications")
        err = buf.getvalue()
        self.assertNotIn("rewriting", err)


class TestAliasEndpoint(unittest.TestCase):
    def test_saas_returns_unchanged(self):
        result = csw_api._alias_endpoint("POST", "/openapi/v1/flow_search/flows", "saas")
        self.assertEqual(result, ("POST", "/openapi/v1/flow_search/flows"))

    def test_unknown_returns_unchanged(self):
        result = csw_api._alias_endpoint("POST", "/openapi/v1/flow_search/flows", "unknown")
        self.assertEqual(result, ("POST", "/openapi/v1/flow_search/flows"))

    def test_auto_returns_unchanged(self):
        # auto should never reach here in practice, but be defensive
        result = csw_api._alias_endpoint("POST", "/openapi/v1/flow_search/flows", "auto")
        self.assertEqual(result, ("POST", "/openapi/v1/flow_search/flows"))

    def test_selfhosted_path_rename(self):
        result = csw_api._alias_endpoint(
            "POST", "/openapi/v1/flow_search/flows", "selfhosted"
        )
        self.assertEqual(result, ("POST", "/openapi/v1/flowsearch"))

    def test_selfhosted_verb_change(self):
        result = csw_api._alias_endpoint(
            "POST", "/openapi/v1/inventory/dimensions", "selfhosted"
        )
        self.assertEqual(result, ("GET", "/openapi/v1/inventory/dimensions"))

    def test_path_not_in_table_returns_unchanged(self):
        result = csw_api._alias_endpoint(
            "GET", "/openapi/v1/applications", "selfhosted"
        )
        self.assertEqual(result, ("GET", "/openapi/v1/applications"))

    def test_method_mismatch_no_alias(self):
        # Table only aliases POST /flow_search/flows; GET should be untouched
        result = csw_api._alias_endpoint(
            "GET", "/openapi/v1/flow_search/flows", "selfhosted"
        )
        self.assertEqual(result, ("GET", "/openapi/v1/flow_search/flows"))

    def test_query_string_preserved_through_path_rename(self):
        result = csw_api._alias_endpoint(
            "POST", "/openapi/v1/flow_search/flows?limit=50", "selfhosted"
        )
        self.assertEqual(result, ("POST", "/openapi/v1/flowsearch?limit=50"))

    def test_query_string_preserved_through_verb_change(self):
        result = csw_api._alias_endpoint(
            "POST", "/openapi/v1/inventory/dimensions?foo=bar", "selfhosted"
        )
        self.assertEqual(result, ("GET", "/openapi/v1/inventory/dimensions?foo=bar"))


class TestPathAliasesStructure(unittest.TestCase):
    def test_constant_exists_and_is_list(self):
        self.assertIsInstance(csw_api.PATH_ALIASES, list)

    def test_has_exactly_5_rows(self):
        self.assertEqual(len(csw_api.PATH_ALIASES), 5)

    def test_every_row_is_4_tuple_of_strings(self):
        for row in csw_api.PATH_ALIASES:
            self.assertEqual(len(row), 4)
            for field in row:
                self.assertIsInstance(field, str)

    def test_methods_are_valid_http_verbs(self):
        valid = {"GET", "POST", "PUT", "DELETE"}
        for canonical_method, _, alt_method, _ in csw_api.PATH_ALIASES:
            self.assertIn(canonical_method, valid)
            self.assertIn(alt_method, valid)

    def test_contains_the_five_documented_rows(self):
        # Each row from the design doc / PR #5 catalog (with PR #5
        # catalog amendment in T6 adding the metrics row).
        expected = {
            ("POST", "/openapi/v1/flow_search/flows",      "POST", "/openapi/v1/flowsearch"),
            ("POST", "/openapi/v1/flow_search/topn",       "POST", "/openapi/v1/flowsearch/topn"),
            ("POST", "/openapi/v1/flow_search/metrics",    "GET",  "/openapi/v1/flowsearch/metrics"),
            ("POST", "/openapi/v1/flow_search/dimensions", "GET",  "/openapi/v1/flowsearch/dimensions"),
            ("POST", "/openapi/v1/inventory/dimensions",   "GET",  "/openapi/v1/inventory/dimensions"),
        }
        actual = {tuple(row) for row in csw_api.PATH_ALIASES}
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
