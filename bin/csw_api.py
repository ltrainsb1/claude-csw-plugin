#!/usr/bin/env python3
"""
Cisco Secure Workload (CSW) API client with HMAC digest authentication.

Usage:
    python3 csw_api.py GET /openapi/v1/scopes
    python3 csw_api.py POST /openapi/v1/inventory/search '{"filter": {...}}'
    python3 csw_api.py GET /openapi/v1/sensors --limit 100 --offset 0

Environment variables required:
    CSW_API_URL    - Base URL (e.g., https://csw.example.com)
    CSW_API_KEY    - API key (hex string)
    CSW_API_SECRET - API secret (hex string)

Optional:
    CSW_VERIFY_SSL - Set to "false" to disable SSL verification (default: true)
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
    if len(sys.argv) < 3:
        print("Usage: csw_api.py METHOD PATH [BODY_JSON] [--limit N] [--offset N]")
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
