"""
tests/test_passive_scanner.py
────────────────────────────────────────────────────────────────────
Tests for proxy/modules/passive_scanner.py

All detection functions are pure (no I/O) so tests are synchronous
where possible, async only for the IModule interface methods.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from proxy.core.interfaces import ProxyRequest, ProxyResponse
from proxy.modules.passive_scanner import (
    PassiveScanner,
    _check_secret_in_url,
    _check_security_headers,
    _check_unauthed_sensitive_path,
    _check_version_disclosure,
    _is_checkable_content_type,
)


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

def _req(
    url: str = "https://api.example.com/api/users",
    method: str = "GET",
    headers: dict | None = None,
) -> ProxyRequest:
    return ProxyRequest(
        id="test-req-id",
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        headers=headers or {},
    )


def _resp(
    status_code: int = 200,
    headers: dict | None = None,
) -> ProxyResponse:
    return ProxyResponse(
        request_id="test-req-id",
        timestamp=datetime.now(timezone.utc),
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
    )


_ALL_SECURITY_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "permissions-policy": "geolocation=()",
}


# ─────────────────────────────────────────────────────────────────
#  _check_secret_in_url
# ─────────────────────────────────────────────────────────────────

def test_secret_in_url_detects_token():
    req = _req(url="https://api.example.com/callback?token=eyJhbGciOiJSUzI1NiJ9abc")
    findings = _check_secret_in_url(req)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "token" in findings[0].evidence["parameter"]


def test_secret_in_url_detects_api_key():
    req = _req(url="https://api.example.com/data?api_key=sk-abc123XYZ789")
    findings = _check_secret_in_url(req)
    assert len(findings) == 1
    assert findings[0].title == "Sensitive data in URL"


def test_secret_in_url_detects_password():
    req = _req(url="https://api.example.com/login?password=S3cr3tP@ss")
    findings = _check_secret_in_url(req)
    assert len(findings) == 1


def test_secret_in_url_ignores_empty_value():
    req = _req(url="https://api.example.com/data?token=")
    findings = _check_secret_in_url(req)
    assert findings == []


def test_secret_in_url_ignores_short_value():
    # Values under 8 chars are likely placeholders/demo values
    req = _req(url="https://api.example.com/data?token=abc")
    findings = _check_secret_in_url(req)
    assert findings == []


def test_secret_in_url_ignores_non_secret_params():
    req = _req(url="https://api.example.com/search?q=hello&page=2")
    findings = _check_secret_in_url(req)
    assert findings == []


def test_secret_in_url_no_query_string():
    req = _req(url="https://api.example.com/users")
    findings = _check_secret_in_url(req)
    assert findings == []


def test_secret_in_url_multiple_secrets():
    req = _req(url="https://api.example.com/cb?token=abc123XYZ&api_key=sk-xyz789ABC")
    findings = _check_secret_in_url(req)
    assert len(findings) == 2


def test_secret_in_url_value_preview_truncated():
    req = _req(url="https://api.example.com/cb?token=verylongsecrettoken123456")
    findings = _check_secret_in_url(req)
    assert findings[0].evidence["value_preview"].endswith("…")


# ─────────────────────────────────────────────────────────────────
#  _check_unauthed_sensitive_path
# ─────────────────────────────────────────────────────────────────

def test_unauthed_sensitive_path_flagged():
    # POST without auth on sensitive path should be flagged
    req = _req(url="https://api.example.com/api/users", method="POST", headers={})
    findings = _check_unauthed_sensitive_path(req)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_unauthed_sensitive_path_get_not_flagged():
    # GET without auth is no longer flagged — public APIs commonly allow this
    req = _req(url="https://api.example.com/api/users", method="GET", headers={})
    findings = _check_unauthed_sensitive_path(req)
    assert findings == []


def test_unauthed_sensitive_path_with_auth_header_ignored():
    req = _req(
        url="https://api.example.com/api/users",
        method="POST",
        headers={"Authorization": "Bearer token123"},
    )
    findings = _check_unauthed_sensitive_path(req)
    assert findings == []


def test_unauthed_sensitive_path_with_cookie_ignored():
    req = _req(
        url="https://api.example.com/api/users",
        method="POST",
        headers={"Cookie": "session=abc123"},
    )
    findings = _check_unauthed_sensitive_path(req)
    assert findings == []


def test_unauthed_sensitive_path_with_api_key_ignored():
    req = _req(
        url="https://api.example.com/api/data",
        method="POST",
        headers={"X-Api-Key": "key123"},
    )
    findings = _check_unauthed_sensitive_path(req)
    assert findings == []


def test_non_sensitive_path_not_flagged():
    req = _req(url="https://example.com/about", method="GET", headers={})
    findings = _check_unauthed_sensitive_path(req)
    assert findings == []


def test_unauthed_admin_path_flagged():
    req = _req(url="https://example.com/admin/dashboard", method="POST", headers={})
    findings = _check_unauthed_sensitive_path(req)
    assert len(findings) == 1


def test_unauthed_delete_flagged():
    req = _req(url="https://api.example.com/api/users/42", method="DELETE", headers={})
    findings = _check_unauthed_sensitive_path(req)
    assert len(findings) == 1


# ─────────────────────────────────────────────────────────────────
#  _check_security_headers
# ─────────────────────────────────────────────────────────────────

def test_all_security_headers_present_no_findings():
    req = _req()
    resp = _resp(headers={**_ALL_SECURITY_HEADERS, "content-type": "text/html"})
    findings = _check_security_headers(req, resp)
    assert findings == []


def test_missing_hsts_flagged_as_medium():
    headers = {k: v for k, v in _ALL_SECURITY_HEADERS.items()
               if k != "strict-transport-security"}
    headers["content-type"] = "text/html"
    req = _req()
    resp = _resp(headers=headers)
    findings = _check_security_headers(req, resp)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "strict-transport-security" in findings[0].title


def test_missing_csp_flagged_as_medium():
    headers = {k: v for k, v in _ALL_SECURITY_HEADERS.items()
               if k != "content-security-policy"}
    headers["content-type"] = "text/html"
    req = _req()
    resp = _resp(headers=headers)
    findings = _check_security_headers(req, resp)
    assert any("content-security-policy" in f.title for f in findings)
    assert all(f.severity in ("low", "medium") for f in findings)


def test_missing_x_frame_options_flagged_as_low():
    headers = {k: v for k, v in _ALL_SECURITY_HEADERS.items()
               if k != "x-frame-options"}
    headers["content-type"] = "text/html"
    req = _req()
    resp = _resp(headers=headers)
    findings = _check_security_headers(req, resp)
    frame_findings = [f for f in findings if "x-frame-options" in f.title]
    assert len(frame_findings) == 1
    assert frame_findings[0].severity == "low"


def test_all_security_headers_missing():
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})
    findings = _check_security_headers(req, resp)
    assert len(findings) == 5   # one per missing header


# ─────────────────────────────────────────────────────────────────
#  _check_version_disclosure
# ─────────────────────────────────────────────────────────────────

def test_server_header_disclosure():
    req = _req()
    resp = _resp(headers={"content-type": "text/html", "Server": "Apache/2.4.51"})
    findings = _check_version_disclosure(req, resp)
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "Apache/2.4.51" in findings[0].description


def test_x_powered_by_disclosure():
    req = _req()
    resp = _resp(headers={"content-type": "text/html", "X-Powered-By": "PHP/8.1.0"})
    findings = _check_version_disclosure(req, resp)
    assert len(findings) == 1
    assert "PHP/8.1.0" in findings[0].description


def test_no_disclosure_headers_no_findings():
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})
    findings = _check_version_disclosure(req, resp)
    assert findings == []


# ─────────────────────────────────────────────────────────────────
#  _is_checkable_content_type
# ─────────────────────────────────────────────────────────────────

def test_checkable_types():
    assert _is_checkable_content_type("text/html; charset=utf-8")
    assert _is_checkable_content_type("application/json")
    assert _is_checkable_content_type("application/xml")
    assert _is_checkable_content_type("")   # missing content-type is suspicious


def test_non_checkable_types():
    assert not _is_checkable_content_type("image/png")
    assert not _is_checkable_content_type("font/woff2")
    assert not _is_checkable_content_type("video/mp4")


# ─────────────────────────────────────────────────────────────────
#  PassiveScanner IModule interface (async)
# ─────────────────────────────────────────────────────────────────

class FakeStore:
    async def write(self, table, record): pass
    async def read(self, table, id): return None
    async def query(self, table, filters=None): return []
    async def subscribe(self, topic, handler): pass
    async def publish(self, topic, payload): pass


async def test_on_request_returns_findings():
    scanner = PassiveScanner(FakeStore())
    req = _req(url="https://api.example.com/api/data?token=secrettoken123", headers={})
    findings = await scanner.on_request(req)
    assert len(findings) >= 1


async def test_on_response_skips_images():
    scanner = PassiveScanner(FakeStore())
    req = _req()
    resp = _resp(headers={"content-type": "image/png"})
    findings = await scanner.on_response(req, resp)
    assert findings == []


async def test_on_response_checks_html():
    scanner = PassiveScanner(FakeStore())
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})
    findings = await scanner.on_response(req, resp)
    # Should find missing security headers
    assert len(findings) > 0


async def test_healthcheck_returns_ok():
    scanner = PassiveScanner(FakeStore())
    health = await scanner.healthcheck()
    assert health.status == "ok"
    assert health.module_name == "passive_scanner"


# ─────────────────────────────────────────────────────────────────
#  Deduplication
# ─────────────────────────────────────────────────────────────────

def test_dedup_suppresses_duplicate_within_window():
    scanner = PassiveScanner(FakeStore(), dedup_window_seconds=3600)
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})

    findings1 = _check_security_headers(req, resp)
    findings2 = _check_security_headers(req, resp)

    # First pass — all findings through
    out1 = scanner._dedup(findings1)
    assert len(out1) == 5

    # Second pass same host+title — all suppressed
    out2 = scanner._dedup(findings2)
    assert out2 == []


def test_dedup_allows_different_hosts():
    scanner = PassiveScanner(FakeStore(), dedup_window_seconds=3600)

    req_a = _req(url="https://site-a.example.com/page")
    req_b = _req(url="https://site-b.example.com/page")
    resp = _resp(headers={"content-type": "text/html"})

    out_a = scanner._dedup(_check_security_headers(req_a, resp))
    out_b = scanner._dedup(_check_security_headers(req_b, resp))

    # Different hosts — both sets should pass through
    assert len(out_a) == 5
    assert len(out_b) == 5


def test_dedup_resets_after_window_expires():
    from datetime import timedelta

    scanner = PassiveScanner(FakeStore(), dedup_window_seconds=1)
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})

    findings = _check_security_headers(req, resp)

    out1 = scanner._dedup(findings)
    assert len(out1) == 5

    # Manually expire the cache by backdating all entries
    expired = datetime.now(timezone.utc) - timedelta(seconds=2)
    for key in scanner._seen:
        scanner._seen[key] = expired

    out2 = scanner._dedup(findings)
    assert len(out2) == 5   # window expired — all pass through again


def test_dedup_flush_clears_cache():
    scanner = PassiveScanner(FakeStore(), dedup_window_seconds=3600)
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})

    findings = _check_security_headers(req, resp)
    scanner._dedup(findings)
    assert len(scanner._seen) > 0

    scanner.flush_dedup_cache()
    assert scanner._seen == {}


def test_dedup_window_zero_never_suppresses():
    scanner = PassiveScanner(FakeStore(), dedup_window_seconds=0)
    req = _req()
    resp = _resp(headers={"content-type": "text/html"})
    findings = _check_security_headers(req, resp)

    out1 = scanner._dedup(findings)
    out2 = scanner._dedup(findings)
    # window=0 means every finding is always "expired"
    assert len(out1) == 5
    assert len(out2) == 5