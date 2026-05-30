#!/usr/bin/env python3
"""
Cisco Secure Workload (CSW) API client with HMAC digest authentication.

Usage:
    python3 csw_api.py GET /openapi/v1/scopes
    python3 csw_api.py POST /openapi/v1/inventory/search '{"filter": {...}}'
    python3 csw_api.py GET /openapi/v1/sensors --limit 100 --offset 0
    python3 csw_api.py --get-deployment

Environment variables required:
    CSW_API_URL    - Base URL (e.g., https://csw.example.com)
    CSW_API_KEY    - API key (hex string)
    CSW_API_SECRET - API secret (hex string)

Optional:
    CSW_VERIFY_SSL - Set to "false" to disable SSL verification (default: true)
    CSW_DEPLOYMENT - One of: saas, selfhosted, auto, unknown (default: auto).
                     Controls the deployment-applicability gate. 'auto' probes
                     /openapi/v1/vrfs on first call and caches the result under
                     $CLAUDE_PLUGIN_ROOT/.csw_deployment_cache_<hash>.

Module constants:
    PATH_ALIASES   - Hand-maintained list of (canonical_method, canonical_path,
                     alt_method, alt_path) tuples. When the resolved deployment
                     is 'selfhosted', make_request() transparently rewrites
                     canonical SaaS-spec paths to their on-prem 4.0.x
                     equivalents and emits a one-line stderr note per rewrite.
                     Mirrors skills/csw/SKILL.md "API surface variants"
                     catalog; tests/test_alias_sync.py enforces the mirror.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone


DEPLOYMENT_VALUES = {"saas", "selfhosted", "auto", "unknown"}


def _get_deployment_env():
    """Read CSW_DEPLOYMENT, normalize to a member of DEPLOYMENT_VALUES.
    Invalid values silently fall back to 'auto'. Never raises."""
    raw = os.environ.get("CSW_DEPLOYMENT", "").strip().lower()
    if not raw:
        return "auto"
    if raw not in DEPLOYMENT_VALUES:
        print(f"[csw_api] invalid CSW_DEPLOYMENT={raw!r}; falling back to 'auto'",
              file=sys.stderr)
        return "auto"
    return raw


# Per-endpoint deployment applicability. Mirrors the Deploy column in
# skills/csw/api-reference.md; both must be hand-synced in a single commit.
# Only endpoints that are NOT available on both deployments need a row here —
# the default (no row) means "available on both."
#
# Current non-Both endpoints:
#   /openapi/v1/service_health                 H-only — cluster internals
#   /openapi/v1/connector/rotate_certificates  S-only — Secure Connector tunnel lifecycle
#
# Cross-deployment-but-content-differs endpoints (NOT gated; consumers
# handle interpretation):
#   /openapi/v1/vrfs                  single Default on SaaS vs. many on selfhosted
#   /openapi/v1/software/versions     Cisco-curated on SaaS vs. customer-uploaded
#   /openapi/v1/connector/status      "not configured" on most selfhosted clusters
ENDPOINT_MATRIX = [
    ("GET",  "/openapi/v1/service_health",                  frozenset({"selfhosted"})),
    ("POST", "/openapi/v1/connector/rotate_certificates",   frozenset({"saas"})),
]


# Per-endpoint deployment alias table. Mirrors the path/verb rows in
# skills/csw/SKILL.md "API surface variants" catalog one-to-one
# (tests/test_alias_sync.py enforces the mirror).
#
# Only used when the resolved deployment is 'selfhosted'. Body-shape and
# metric-field drifts from the catalog are NOT here — those stay
# caller-side per the PR #5 decision.
PATH_ALIASES = [
    # (canonical_method, canonical_path, alt_method, alt_path)
    ("POST", "/openapi/v1/flow_search/flows",      "POST", "/openapi/v1/flowsearch"),
    ("POST", "/openapi/v1/flow_search/topn",       "POST", "/openapi/v1/flowsearch/topn"),
    # metrics row: alt verb (GET) was inferred during PR #5 from sibling
    # endpoints; live-verified against tet-pov-rtp1.cpoc.co during PR #6
    # post-flight 2c (HTTP 200 + 59-item metrics list).
    ("POST", "/openapi/v1/flow_search/metrics",    "GET",  "/openapi/v1/flowsearch/metrics"),
    ("POST", "/openapi/v1/flow_search/dimensions", "GET",  "/openapi/v1/flowsearch/dimensions"),
    ("POST", "/openapi/v1/inventory/dimensions",   "GET",  "/openapi/v1/inventory/dimensions"),
    # /scopes path rename — on-prem 4.0.x; verified during PR #7 build.
    ("GET",  "/openapi/v1/scopes",                 "GET",  "/openapi/v1/app_scopes"),
]


def _match_endpoint(method, path):
    """Find the matrix row for (method, path) or None.
    Strips query strings; exact path match against the rows."""
    if "?" in path:
        path = path.split("?", 1)[0]
    for row in ENDPOINT_MATRIX:
        m, p, _ = row
        if m == method.upper() and p == path:
            return row
    return None


def applicable(method, path, deployment):
    """Decide whether a request should be sent given the resolved deployment.

    Returns (True, None) to send, (False, reason) to refuse.
    'unknown' deployment always allows; 'auto' should never reach here
    (make_request resolves first). Invalid deployment values are permissive."""
    if deployment not in {"saas", "selfhosted"}:
        return True, None
    row = _match_endpoint(method, path)
    if row is None:
        return True, None
    _, p, deploys = row
    if deployment in deploys:
        return True, None
    return False, f"endpoint {p} not applicable on {deployment} deployment"


def _alias_endpoint(method, path, deployment):
    """Return (alt_method, alt_path) if a PATH_ALIASES row matches and
    deployment is 'selfhosted'; otherwise return (method, path) unchanged.
    Pure function: no stderr, no side effects.

    Query strings are stripped for matching and reattached to the alt path."""
    if deployment != "selfhosted":
        return method, path
    if "?" in path:
        bare_path, query = path.split("?", 1)
        query = "?" + query
    else:
        bare_path, query = path, ""
    upper_method = method.upper()
    for canonical_method, canonical_path, alt_method, alt_path in PATH_ALIASES:
        if canonical_method == upper_method and canonical_path == bare_path:
            return alt_method, alt_path + query
    return method, path


def resolve_deployment(base_url, api_key, api_secret, verify_ssl):
    """Classify the cluster by probing GET /openapi/v1/vrfs.

    Returns 'saas', 'selfhosted', or 'unknown'. Never raises.
    Does its own HMAC signing inline to avoid recursing into make_request().
    """
    path = "/openapi/v1/vrfs"
    content_type = "application/json"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")
    signature = compute_signature(api_secret, "GET", path, "", content_type, timestamp)
    headers = {
        "Content-Type": content_type,
        "Id": api_key,
        "Authorization": signature,
        "Timestamp": timestamp,
        "User-Agent": "claude-csw-skill/1.0 (deployment-probe)",
    }
    url = f"{base_url.rstrip('/')}{path}"
    req = urllib.request.Request(url, headers=headers, method="GET")

    ctx = None
    if not verify_ssl:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        kwargs = {"context": ctx} if ctx else {}
        with urllib.request.urlopen(req, **kwargs) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            if not isinstance(data, list):
                return "unknown"
            # Heuristic: multiple VRFs => self-hosted; one or none => SaaS tenant.
            return "selfhosted" if len(data) > 1 else "saas"
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return "saas"
        print(f"[csw_api] deployment probe got HTTP {e.code}; treating as unknown",
              file=sys.stderr)
        return "unknown"
    except (urllib.error.URLError, json.JSONDecodeError, ValueError) as e:
        print(f"[csw_api] deployment probe failed: {e}; treating as unknown",
              file=sys.stderr)
        return "unknown"


def _cache_path(url):
    """Resolve the cache file path for a given CSW_API_URL.
    Prefers $CLAUDE_PLUGIN_ROOT; falls back to ~/.cache/csw_api/."""
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if not root:
        root = os.path.join(os.path.expanduser("~"), ".cache", "csw_api")
    return os.path.join(root, f".csw_deployment_cache_{key}")


def _read_cache(url):
    """Return the cached deployment for `url`, or None.
    Treats corrupt/foreign content (including legacy 'unknown' or 'auto')
    as a cache miss."""
    try:
        with open(_cache_path(url), "r") as f:
            value = f.read().strip()
    except OSError:
        return None
    if value in {"saas", "selfhosted"}:
        return value
    return None


def _write_cache(url, value):
    """Persist `value` for `url`. Returns True on success, False on failure.
    Only 'saas' and 'selfhosted' are cacheable — 'auto' is the unresolved
    state, and 'unknown' is a probe failure we want to re-trigger on every
    call (pre-flight WARN #1). Never raises."""
    if value not in {"saas", "selfhosted"}:
        return False
    path = _cache_path(url)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(value)
        return True
    except OSError as e:
        print(f"[csw_api] could not write deployment cache to {path}: {e}",
              file=sys.stderr)
        return False


def get_config():
    url = os.environ.get("CSW_API_URL", "").rstrip("/")
    key = os.environ.get("CSW_API_KEY", "")
    secret = os.environ.get("CSW_API_SECRET", "")

    missing = []
    if not url:
        missing.append("CSW_API_URL")
    if not key:
        missing.append("CSW_API_KEY")
    if not secret:
        missing.append("CSW_API_SECRET")

    if missing:
        print(json.dumps({
            "error": f"Missing environment variables: {', '.join(missing)}",
            "hint": "Set CSW_API_URL, CSW_API_KEY, and CSW_API_SECRET"
        }), file=sys.stderr)
        sys.exit(1)

    verify_ssl = os.environ.get("CSW_VERIFY_SSL", "true").lower() != "false"
    return url, key, secret, verify_ssl


def compute_signature(secret, method, path, checksum, content_type, timestamp):
    """Compute HMAC-SHA256 signature per CSW API specification."""
    msg = method + "\n" + path + "\n" + checksum + "\n" + content_type + "\n" + timestamp + "\n"
    sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256)
    return base64.b64encode(sig.digest()).decode("utf-8")


def make_request(method, path, body=None, params=None):
    base_url, api_key, api_secret, verify_ssl = get_config()

    # Deployment applicability gate. Refusals never sign, never touch the
    # network. Gate decision is based on path without query string —
    # _match_endpoint strips '?...' so insertion before or after the params
    # block is equivalent.
    deployment = _get_deployment_env()
    if deployment == "auto":
        cached = _read_cache(base_url)
        if cached is not None:
            deployment = cached
        else:
            deployment = resolve_deployment(base_url, api_key, api_secret, verify_ssl)
            _write_cache(base_url, deployment)
    ok, reason = applicable(method, path, deployment)
    if not ok:
        return {
            "status": 0,
            "error": reason,
            "data": None,
        }

    # Path/verb alias resolution. Transparently rewrites canonical
    # (SaaS-spec) paths to their on-prem 4.0.x equivalents when the
    # resolved deployment is 'selfhosted'. Mirrors PATH_ALIASES /
    # skills/csw/SKILL.md API-surface-variants catalog.
    alt_method, alt_path = _alias_endpoint(method, path, deployment)
    if (alt_method, alt_path) != (method, path):
        print(
            f"[csw_api] rewriting {method} {path} -> {alt_method} {alt_path} "
            f"(on-prem 4.0.x alias; see skills/csw/SKILL.md API surface variants)",
            file=sys.stderr,
        )
        # On POST->GET verb changes, drop the body — a GET with a body
        # is invalid HTTP semantics on the alt endpoints.
        if method.upper() == "POST" and alt_method == "GET" and body is not None:
            print(
                f"[csw_api] dropping POST body for GET {alt_path} alias "
                f"(operator: confirm dimensions endpoint doesn't need params)",
                file=sys.stderr,
            )
            body = None
        method = alt_method
        path = alt_path

    if params:
        query = urllib.parse.urlencode(params)
        path = f"{path}?{query}"

    url = f"{base_url}{path}"
    content_type = "application/json"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")

    body_bytes = b""
    if body:
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif isinstance(body, (dict, list)):
            body_bytes = json.dumps(body).encode("utf-8")

    # Checksum is empty string for GET/DELETE, SHA-256 hex of body for POST/PUT
    if method.upper() in ("POST", "PUT") and body_bytes:
        checksum = hashlib.sha256(body_bytes).hexdigest()
    else:
        checksum = ""

    signature = compute_signature(api_secret, method.upper(), path, checksum, content_type, timestamp)

    headers = {
        "Content-Type": content_type,
        "Id": api_key,
        "Authorization": signature,
        "Timestamp": timestamp,
        "User-Agent": "claude-csw-skill/1.0",
    }

    if checksum:
        headers["X-Tetration-Cksum"] = checksum

    req = urllib.request.Request(url, data=body_bytes if body_bytes else None,
                                 headers=headers, method=method.upper())

    if not verify_ssl:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = None

    try:
        kwargs = {"context": ctx} if ctx else {}
        with urllib.request.urlopen(req, **kwargs) as resp:
            response_body = resp.read().decode("utf-8")
            try:
                data = json.loads(response_body)
            except json.JSONDecodeError:
                data = response_body
            return {
                "status": resp.status,
                "data": data,
            }
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            error_data = json.loads(error_body)
        except json.JSONDecodeError:
            error_data = error_body
        return {
            "status": e.code,
            "error": str(e.reason),
            "data": error_data,
        }
    except urllib.error.URLError as e:
        return {
            "status": 0,
            "error": f"Connection failed: {e.reason}",
            "data": None,
        }


def main():
    # Handle --get-deployment as a standalone command.
    if "--get-deployment" in sys.argv:
        url, key, secret, verify_ssl = get_config()
        env_value = _get_deployment_env()
        if env_value == "auto":
            cached = _read_cache(url)
            if cached is not None:
                print(cached)
                return
            resolved = resolve_deployment(url, key, secret, verify_ssl)
            _write_cache(url, resolved)
            print(resolved)
            return
        print(env_value)
        return

    if len(sys.argv) < 3:
        print("Usage: csw_api.py METHOD PATH [BODY_JSON] [--limit N] [--offset N] [--deployment saas|selfhosted|unknown]")
        print("       csw_api.py --get-deployment")
        print()
        print("Examples:")
        print('  csw_api.py GET /openapi/v1/scopes')
        print('  csw_api.py POST /openapi/v1/inventory/search \'{"filter": {"type": "eq", "field": "os", "value": "linux"}}\'')
        print('  csw_api.py GET /openapi/v1/sensors --limit 50')
        sys.exit(1)

    method = sys.argv[1].upper()
    path = sys.argv[2]

    body = None
    params = {}
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--limit" and i + 1 < len(sys.argv):
            params["limit"] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--offset" and i + 1 < len(sys.argv):
            params["offset"] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--deployment" and i + 1 < len(sys.argv):
            os.environ["CSW_DEPLOYMENT"] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i].startswith("--"):
            key = sys.argv[i].lstrip("-")
            if i + 1 < len(sys.argv):
                params[key] = sys.argv[i + 1]
                i += 2
            else:
                i += 1
        elif body is None:
            try:
                body = json.loads(sys.argv[i])
            except json.JSONDecodeError:
                print(json.dumps({"error": f"Invalid JSON body: {sys.argv[i]}"}))
                sys.exit(1)
            i += 1
        else:
            i += 1

    result = make_request(method, path, body=body, params=params if params else None)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
