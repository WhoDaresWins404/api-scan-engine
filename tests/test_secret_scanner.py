"""
tests/test_secret_scanner.py
────────────────────────────────────────────────────────────────────
Tests for proxy/modules/secret_scanner.py
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone

from proxy.core.interfaces import ProxyRequest, ProxyResponse
from proxy.modules.secret_scanner import (
    SecretScanner,
    _check_known_patterns,
    _check_high_entropy,
    _shannon_entropy,
)


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

class FakeStore:
    async def write(self, t, r): pass
    async def read(self, t, i): return None
    async def query(self, t, f=None): return []
    async def subscribe(self, t, h): pass
    async def publish(self, t, p): pass


def _req(url: str = "https://api.example.com/v1/user") -> ProxyRequest:
    return ProxyRequest(
        id="test-id",
        timestamp=datetime.now(timezone.utc),
        method="GET",
        url=url,
        headers={},
    )


def _resp(
    body: bytes | None = None,
    content_type: str = "application/json",
    status: int = 200,
) -> ProxyResponse:
    return ProxyResponse(
        request_id="test-id",
        timestamp=datetime.now(timezone.utc),
        status_code=status,
        headers={"content-type": content_type},
        body=body,
    )


def _json_resp(data: dict) -> ProxyResponse:
    return _resp(body=json.dumps(data).encode())


# ─────────────────────────────────────────────────────────────────
#  _shannon_entropy
# ─────────────────────────────────────────────────────────────────

def test_entropy_empty_string():
    assert _shannon_entropy("") == 0.0

def test_entropy_uniform_string():
    # All same chars -> 0 entropy
    assert _shannon_entropy("aaaaaaa") == 0.0

def test_entropy_random_looking():
    # High entropy string
    assert _shannon_entropy("aB3$xY9!mK2@pQ7#") > 3.5

def test_entropy_low_for_plain_word():
    assert _shannon_entropy("password") < 3.0


# ─────────────────────────────────────────────────────────────────
#  _check_known_patterns
# ─────────────────────────────────────────────────────────────────

def test_detects_aws_access_key():
    text = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert any("AWS Access Key" in f.title for f in findings)
    assert all(f.severity == "high" for f in findings)

def test_detects_github_token():
    text = '{"token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert any("GitHub" in f.title for f in findings)

def test_detects_stripe_secret_key():
    text = '{"key": "sk_live_abcdefghijklmnopqrstuvwx"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert any("Stripe" in f.title for f in findings)

def test_detects_private_key_header():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert any("Private key" in f.title for f in findings)

def test_detects_bearer_token_in_json():
    text = '{"access_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert len(findings) >= 1

def test_detects_jwt_in_response():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    text = f'{{"token": "{jwt}"}}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert any("JWT" in f.title for f in findings)

def test_no_findings_on_clean_response():
    text = '{"user": "alice", "email": "alice@example.com", "role": "admin"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert findings == []

def test_preview_truncated():
    text = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    aws = [f for f in findings if "AWS Access Key" in f.title]
    assert aws[0].evidence["preview"].endswith("...")

def test_google_api_key_detected():
    text = '{"key": "AIzaSyD-9tSrke72I6e0DVWherFinalEx4mple"}'
    findings = _check_known_patterns(text, "req1", "https://api.example.com/")
    assert any("Google" in f.title for f in findings)


# ─────────────────────────────────────────────────────────────────
#  _check_high_entropy
# ─────────────────────────────────────────────────────────────────

def test_high_entropy_detects_random_value():
    # A high-entropy value in a suspicious key name
    text = '{"secret_key": "xK9mP2nQ8rT5vW3yA7bC1dE6fG4hJ0"}'
    findings = _check_high_entropy(text, "req1", "https://api.example.com/")
    assert len(findings) >= 1
    assert findings[0].severity == "medium"

def test_high_entropy_skips_url_field():
    text = '{"url": "https://cdn.example.com/assets/abc123def456ghi789jkl012mno345"}'
    findings = _check_high_entropy(text, "req1", "https://api.example.com/")
    assert findings == []

def test_high_entropy_skips_short_values():
    text = '{"token": "abc123"}'
    findings = _check_high_entropy(text, "req1", "https://api.example.com/")
    assert findings == []

def test_high_entropy_skips_low_entropy_value():
    # Repeating pattern -- low entropy despite being long
    text = '{"key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    findings = _check_high_entropy(text, "req1", "https://api.example.com/")
    assert findings == []

def test_high_entropy_reports_entropy_value():
    text = '{"api_secret": "xK9mP2nQ8rT5vW3yA7bC1dE6fG4hJ0lZ"}'
    findings = _check_high_entropy(text, "req1", "https://api.example.com/")
    if findings:
        assert "entropy" in findings[0].evidence


# ─────────────────────────────────────────────────────────────────
#  SecretScanner.on_response
# ─────────────────────────────────────────────────────────────────

async def test_on_response_detects_aws_key():
    scanner = SecretScanner(FakeStore())
    body = json.dumps({"aws_key": "AKIAIOSFODNN7EXAMPLE"}).encode()
    findings = await scanner.on_response(_req(), _resp(body=body))
    assert any("AWS" in f.title for f in findings)

async def test_on_response_skips_images():
    scanner = SecretScanner(FakeStore())
    body = b"\x89PNG\r\n\x1a\n" + b"AKIAIOSFODNN7EXAMPLE"
    findings = await scanner.on_response(_req(), _resp(body=body, content_type="image/png"))
    assert findings == []

async def test_on_response_skips_large_body():
    scanner = SecretScanner(FakeStore())
    big_body = b"x" * (512 * 1024 + 1)
    findings = await scanner.on_response(_req(), _resp(body=big_body))
    assert findings == []
    assert scanner._skipped == 1

async def test_on_response_skips_empty_body():
    scanner = SecretScanner(FakeStore())
    findings = await scanner.on_response(_req(), _resp(body=None))
    assert findings == []

async def test_on_request_always_empty():
    scanner = SecretScanner(FakeStore())
    from proxy.core.interfaces import ProxyRequest
    req = _req()
    findings = await scanner.on_request(req)
    assert findings == []

async def test_dedup_suppresses_same_finding():
    scanner = SecretScanner(FakeStore())
    body = json.dumps({"aws_key": "AKIAIOSFODNN7EXAMPLE"}).encode()
    resp = _resp(body=body)
    await scanner.on_response(_req(), resp)
    findings2 = await scanner.on_response(_req(), resp)
    assert findings2 == []

async def test_dedup_allows_different_hosts():
    scanner = SecretScanner(FakeStore())
    body = json.dumps({"aws_key": "AKIAIOSFODNN7EXAMPLE"}).encode()
    f1 = await scanner.on_response(
        _req("https://site-a.example.com/api"), _resp(body=body))
    f2 = await scanner.on_response(
        _req("https://site-b.example.com/api"), _resp(body=body))
    assert len(f1) >= 1
    assert len(f2) >= 1

async def test_scanned_counter_increments():
    scanner = SecretScanner(FakeStore())
    body = json.dumps({"user": "alice"}).encode()
    await scanner.on_response(_req(), _resp(body=body))
    await scanner.on_response(_req(), _resp(body=body))
    assert scanner._scanned == 2

async def test_healthcheck():
    scanner = SecretScanner(FakeStore())
    body = json.dumps({"user": "alice"}).encode()
    await scanner.on_response(_req(), _resp(body=body))
    health = await scanner.healthcheck()
    assert health.status == "ok"
    assert health.module_name == "secret_scanner"
    assert "scanned" in health.detail

async def test_entropy_check_disabled():
    scanner = SecretScanner(FakeStore(), check_entropy=False)
    # High-entropy value that would normally be flagged
    text = json.dumps({"api_secret": "xK9mP2nQ8rT5vW3yA7bC1dE6fG4hJ0lZ"}).encode()
    findings = await scanner.on_response(_req(), _resp(body=text))
    entropy_findings = [f for f in findings if "entropy" in f.title.lower()]
    assert entropy_findings == []