"""
proxy/modules/secret_scanner.py
────────────────────────────────────────────────────────────────────
SecretScanner v0.1.0 -- detects secrets in HTTP response bodies.

Scans JSON and plain-text responses for:
  [high]   Known secret patterns -- AWS keys, GitHub tokens, private keys,
           Bearer tokens, Stripe keys, Slack webhooks, etc.
  [medium] High-entropy strings -- generic secrets not matching a known
           pattern but with enough randomness to be a credential

Only scans response bodies, never requests (we don't want to log
inbound credentials). Skips binary, image, and large responses.

Deduplication
─────────────
  (title, host) suppressed for 24h -- same as PassiveScanner.
  Value previews are truncated and never stored in full.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from proxy.core.interfaces import (
    Finding,
    IStore,
    ModuleHealth,
    ProxyRequest,
    ProxyResponse,
)

# ── tunables ──────────────────────────────────────────────────────
DEDUP_WINDOW_SECONDS: int = 86_400      # 24 hours
MAX_BODY_BYTES:       int = 512 * 1024  # skip responses > 512KB
MIN_ENTROPY_LENGTH:   int = 20          # min length for entropy check
HIGH_ENTROPY_THRESHOLD: float = 4.5    # Shannon entropy bits/char

# ── known secret patterns ─────────────────────────────────────────
# Each entry: (title, regex, severity)
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # AWS
    ("AWS Access Key ID",
     re.compile(r"AKIA[0-9A-Z]{16}", re.ASCII),
     "high"),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
     "high"),
    # GitHub
    ("GitHub Personal Access Token",
     re.compile(r"ghp_[0-9a-zA-Z]{36}"),
     "high"),
    ("GitHub OAuth Token",
     re.compile(r"gho_[0-9a-zA-Z]{36}"),
     "high"),
    ("GitHub App Token",
     re.compile(r"(ghu|ghs|ghr)_[0-9a-zA-Z]{36}"),
     "high"),
    # Stripe
    ("Stripe Secret Key",
     re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
     "high"),
    ("Stripe Publishable Key",
     re.compile(r"pk_(live|test)_[0-9a-zA-Z]{24,}"),
     "medium"),
    # Slack
    ("Slack Bot Token",
     re.compile(r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}"),
     "high"),
    ("Slack Webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+"),
     "high"),
    # Generic Bearer / API tokens in JSON values
    ("Bearer token in response",
     re.compile(r'"(?:access_token|token|bearer|api_key|apikey|secret)"\s*:\s*"([A-Za-z0-9+/=_\-\.]{20,})"',
                re.IGNORECASE),
     "high"),
    # Private keys
    ("Private key material",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "high"),
    # Google API key
    ("Google API Key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "high"),
    # SendGrid
    ("SendGrid API Key",
     re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
     "high"),
    # Twilio
    ("Twilio Auth Token",
     re.compile(r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]"),
     "high"),
    # JWT (any JWT in a response body)
    ("JWT token in response",
     re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
     "medium"),
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


# Regex to find candidate high-entropy strings in JSON values
_JSON_VALUE_RE = re.compile(
    r'"(?:[a-z_]{2,30})"\s*:\s*"([A-Za-z0-9+/=_\-\.]{' + str(MIN_ENTROPY_LENGTH) + r',})"',
    re.IGNORECASE,
)

# Key names that are commonly high-entropy but not secrets
_ENTROPY_SKIP_KEYS: frozenset[str] = frozenset({
    "url", "href", "src", "link", "path", "hash", "etag",
    "content", "body", "html", "text", "message", "description",
    "name", "title", "label", "slug", "id", "uuid",
})


def _check_known_patterns(text: str, req_id: str, url: str) -> list[Finding]:
    findings = []
    for title, pattern, severity in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            # Grab the full match or first group for preview
            raw = match.group(1) if match.lastindex else match.group(0)
            preview = raw[:8] + "..." if len(raw) > 8 else raw
            findings.append(Finding(
                module_name="secret_scanner",
                severity=severity,
                title=f"Secret in response: {title}",
                description=(
                    f"A {title} was found in the response body from {url}. "
                    f"Secrets should never appear in API responses."
                ),
                request_id=req_id,
                evidence={"url": url, "pattern": title, "preview": preview},
            ))
    return findings


def _check_high_entropy(text: str, req_id: str, url: str) -> list[Finding]:
    findings = []
    seen_previews: set[str] = set()

    for match in _JSON_VALUE_RE.finditer(text):
        # Extract the key name to skip non-secret fields
        full_match = match.group(0)
        key_match = re.match(r'"([^"]+)"', full_match)
        if key_match and key_match.group(1).lower() in _ENTROPY_SKIP_KEYS:
            continue

        value = match.group(1)
        entropy = _shannon_entropy(value)

        if entropy >= HIGH_ENTROPY_THRESHOLD:
            preview = value[:8] + "..."
            if preview in seen_previews:
                continue
            seen_previews.add(preview)
            findings.append(Finding(
                module_name="secret_scanner",
                severity="medium",
                title="High-entropy string in response",
                description=(
                    f"A high-entropy string (entropy={entropy:.2f}) was found "
                    f"in the response body from {url}. This may be a secret, "
                    f"token, or credential exposed in the API response."
                ),
                request_id=req_id,
                evidence={
                    "url": url,
                    "entropy": round(entropy, 2),
                    "preview": preview,
                },
            ))

    return findings


class SecretScanner:
    name = "secret_scanner"
    version = "0.1.0"

    def __init__(
        self,
        store: IStore,
        dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
        check_entropy: bool = True,
    ) -> None:
        self._store = store
        self._dedup_window = timedelta(seconds=dedup_window_seconds)
        self._seen: dict[tuple[str, str], datetime] = {}
        self._check_entropy = check_entropy
        self._scanned = 0
        self._skipped = 0

    # ── IModule ───────────────────────────────────────────────────

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        return []   # secrets are in responses, not requests

    async def on_response(
        self, req: ProxyRequest, resp: ProxyResponse
    ) -> list[Finding]:
        if not self._should_scan(resp):
            self._skipped += 1
            return []

        self._scanned += 1
        body = _decode_body(resp.body)
        if not body:
            return []

        url  = req.url
        host = urlparse(url).netloc
        findings: list[Finding] = []

        findings.extend(_check_known_patterns(body, req.id, url))
        if self._check_entropy:
            findings.extend(_check_high_entropy(body, req.id, url))

        return self._dedup(findings, host)

    async def healthcheck(self) -> ModuleHealth:
        count = len(await self._store.query(
            "findings", {"module_name": self.name}
        ))
        return ModuleHealth(
            module_name=self.name,
            version=self.version,
            status="ok",
            last_seen=datetime.now(timezone.utc),
            detail=(
                f"{self._scanned} response(s) scanned, "
                f"{self._skipped} skipped, "
                f"{count} finding(s) logged"
            ),
        )

    # ── deduplication ─────────────────────────────────────────────

    def _dedup(self, findings: list[Finding], host: str) -> list[Finding]:
        now = datetime.now(timezone.utc)
        out: list[Finding] = []
        for f in findings:
            key = (f.title, host)
            last = self._seen.get(key)
            if last is None or (now - last) >= self._dedup_window:
                self._seen[key] = now
                out.append(f)
        return out

    # ── filtering ─────────────────────────────────────────────────

    def _should_scan(self, resp: ProxyResponse) -> bool:
        if not resp.body:
            return False
        if len(resp.body) > MAX_BODY_BYTES:
            return False
        ct = resp.headers.get("content-type", "").lower()
        # Only scan text-based responses
        return any(t in ct for t in (
            "application/json", "text/plain", "text/html",
            "application/javascript", "text/javascript",
            "application/graphql",
        )) or ct == ""


def _decode_body(body: bytes | None) -> str:
    if not body:
        return ""
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return ""

