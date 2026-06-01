"""
tests/test_passive_scanner_blocklist.py
────────────────────────────────────────────────────────────────────
Tests for PassiveScanner v0.3.0 host blocklist feature.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from proxy.core.interfaces import ProxyRequest, ProxyResponse
from proxy.modules.passive_scanner import PassiveScanner, _BLOCKED_HOST_SUFFIXES


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

class FakeStore:
    async def write(self, t, r): pass
    async def read(self, t, i): return None
    async def query(self, t, f=None): return []
    async def subscribe(self, t, h): pass
    async def publish(self, t, p): pass


def _req(url: str, method: str = "GET", headers: dict | None = None) -> ProxyRequest:
    return ProxyRequest(
        id="test-id",
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        headers=headers or {},
    )


def _resp(status: int = 200, headers: dict | None = None) -> ProxyResponse:
    return ProxyResponse(
        request_id="test-id",
        timestamp=datetime.now(timezone.utc),
        status_code=status,
        headers=headers or {"content-type": "text/html"},
    )


# ─────────────────────────────────────────────────────────────────
#  _is_blocked
# ─────────────────────────────────────────────────────────────────

def test_is_blocked_google_subdomain():
    scanner = PassiveScanner(FakeStore())
    assert scanner._is_blocked("fonts.googleapis.com") is True
    assert scanner._is_blocked("www.googleapis.com") is True


def test_is_blocked_exact_match():
    scanner = PassiveScanner(FakeStore())
    assert scanner._is_blocked("detectportal.firefox.com") is True


def test_is_blocked_cloudfront():
    scanner = PassiveScanner(FakeStore())
    assert scanner._is_blocked("d1abc.cloudfront.net") is True


def test_is_blocked_gstatic():
    scanner = PassiveScanner(FakeStore())
    assert scanner._is_blocked("www.gstatic.com") is True


def test_is_not_blocked_target_api():
    scanner = PassiveScanner(FakeStore())
    assert scanner._is_blocked("api.example.com") is False
    assert scanner._is_blocked("api.motorola.com") is False
    assert scanner._is_blocked("www.bbc.com") is False


def test_is_blocked_case_insensitive():
    scanner = PassiveScanner(FakeStore())
    assert scanner._is_blocked("FONTS.GOOGLEAPIS.COM") is True


def test_use_blocklist_false_skips_all_blocking():
    scanner = PassiveScanner(FakeStore(), use_blocklist=False)
    assert scanner._is_blocked("fonts.googleapis.com") is False
    assert scanner._is_blocked("detectportal.firefox.com") is False


def test_extra_blocked_hosts():
    scanner = PassiveScanner(
        FakeStore(),
        extra_blocked_hosts={".mycdn.example.com"}
    )
    assert scanner._is_blocked("assets.mycdn.example.com") is True
    assert scanner._is_blocked("api.example.com") is False


# ─────────────────────────────────────────────────────────────────
#  on_request — blocked hosts produce no findings
# ─────────────────────────────────────────────────────────────────

async def test_on_request_blocked_host_no_findings():
    scanner = PassiveScanner(FakeStore())
    req = _req("https://fonts.googleapis.com/css?api_key=supersecret123")
    findings = await scanner.on_request(req)
    # even though there's a secret in the URL, the host is blocked
    assert findings == []
    assert scanner._blocked_count == 1


async def test_on_request_unblocked_host_finds_secret():
    scanner = PassiveScanner(FakeStore())
    req = _req("https://api.example.com/login?api_key=supersecret123")
    findings = await scanner.on_request(req)
    assert len(findings) == 1
    assert findings[0].severity == "high"


async def test_on_request_blocked_count_increments():
    scanner = PassiveScanner(FakeStore())
    for _ in range(5):
        await scanner.on_request(_req("https://www.google.com/search"))
    assert scanner._blocked_count == 5


# ─────────────────────────────────────────────────────────────────
#  on_response — blocked hosts produce no findings
# ─────────────────────────────────────────────────────────────────

async def test_on_response_blocked_host_no_findings():
    scanner = PassiveScanner(FakeStore())
    req = _req("https://d1abc.cloudfront.net/bundle.js")
    resp = _resp(headers={"content-type": "application/javascript"})
    findings = await scanner.on_response(req, resp)
    assert findings == []


async def test_on_response_unblocked_host_finds_missing_headers():
    scanner = PassiveScanner(FakeStore())
    req = _req("https://api.example.com/v1/users")
    resp = _resp(headers={"content-type": "application/json"})
    findings = await scanner.on_response(req, resp)
    assert len(findings) > 0   # missing security headers


# ─────────────────────────────────────────────────────────────────
#  healthcheck reports blocked count
# ─────────────────────────────────────────────────────────────────

async def test_healthcheck_reports_blocked_count():
    scanner = PassiveScanner(FakeStore())
    await scanner.on_request(_req("https://fonts.googleapis.com/css"))
    await scanner.on_request(_req("https://www.gstatic.com/js/nav.js"))
    health = await scanner.healthcheck()
    assert "2 blocked host request(s)" in health.detail
    assert health.module_name == "passive_scanner"
    assert health.status == "ok"


# ─────────────────────────────────────────────────────────────────
#  Blocklist coverage — spot check known noisy hosts from live traffic
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", [
    "cdn.privacy-mgmt.com",
    "content-autofill.googleapis.com",
    "encrypted-tbn0.gstatic.com",
    "static.files.bbci.co.uk",   # NOT blocked — BBC is a target
    "www.motorola.com",           # NOT blocked — target
])
def test_known_hosts_blocklist_coverage(host):
    scanner = PassiveScanner(FakeStore())
    blocked = scanner._is_blocked(host)
    # BBC and Motorola should NOT be blocked
    if host in ("static.files.bbci.co.uk", "www.motorola.com"):
        assert blocked is False, f"{host} should not be blocked"
    else:
        assert blocked is True, f"{host} should be blocked" 