"""
proxy/modules/passive_scanner.py
────────────────────────────────────────────────────────────────────
Passive scanner — never modifies traffic, only observes.

Detections
──────────
  on_request:
    * Sensitive data in URL query string (tokens, passwords, API keys)
    * Sensitive path accessed without an Authorization header

  on_response:
    * Missing security headers (HSTS, CSP, X-Frame-Options,
      X-Content-Type-Options, Permissions-Policy)
    * Server version disclosure via Server / X-Powered-By headers

Deduplication
─────────────
  Findings are deduplicated by (title, host) within a rolling time
  window (default DEDUP_WINDOW_SECONDS = 86400, i.e. 24 hours).
  The first occurrence is written to the store; subsequent identical
  findings are dropped until the window expires, at which point the
  finding is re-recorded to capture any changes.

  The dedup cache is in-process only (a plain dict) so it resets on
  proxy restart — intentional, since a restart is a natural boundary
  for re-checking known issues.

Host blocklist
──────────────
  CDN, analytics, ad-network, and telemetry hosts are blocked by
  default — they generate hundreds of low-value findings (missing
  CSP on a Google CDN is not actionable).  Add custom hosts via
  PassiveScanner(store, extra_blocked_hosts={"mycdn.example.com"}).
  Disable entirely with PassiveScanner(store, use_blocklist=False).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from proxy.core.interfaces import (
    Finding,
    IStore,
    ModuleHealth,
    ProxyRequest,
    ProxyResponse,
)


# ── tunables ──────────────────────────────────────────────────────

# Suppress duplicate (title, host) findings within this window
DEDUP_WINDOW_SECONDS: int = 86_400      # 24 hours

# Query-string parameter names that should never appear in a URL
_SECRET_PARAMS: set[str] = {
    "token", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "api_secret",
    "password", "passwd", "pwd", "secret",
    "auth", "authorization",
    "private_key", "client_secret",
    "session", "sessionid", "session_token",
    "jwt",
}

# Regex that matches values looking like real secrets (length >= 8)
_SECRET_VALUE_RE = re.compile(r"[A-Za-z0-9+/=_\-\.@!#$%^&*]{8,}")

# Path prefixes considered sensitive for auth checks
_SENSITIVE_PATHS: tuple[str, ...] = (
    "/api/", "/admin/", "/internal/", "/private/",
    "/v1/", "/v2/", "/v3/",
    "/graphql", "/rpc",
    "/user", "/account", "/profile",
    "/payment", "/checkout", "/billing",
    "/auth/", "/oauth/",
)

# Methods checked for missing auth headers
_AUTH_CHECK_METHODS: set[str] = {"POST", "PUT", "PATCH", "DELETE", "GET"}

# Security response headers: name -> (severity, description)
_SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "medium",
        "Missing Strict-Transport-Security (HSTS) — allows HTTP downgrade attacks",
    ),
    "content-security-policy": (
        "medium",
        "Missing Content-Security-Policy — increases XSS impact",
    ),
    "x-frame-options": (
        "low",
        "Missing X-Frame-Options — page may be embeddable in iframes (clickjacking)",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options — browser may MIME-sniff responses",
    ),
    "permissions-policy": (
        "low",
        "Missing Permissions-Policy — browser features not explicitly restricted",
    ),
}

# Headers that disclose server/framework versions
_DISCLOSURE_HEADERS: tuple[str, ...] = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
)

# ── host blocklist ────────────────────────────────────────────────
# Hosts where security findings are not actionable — CDNs, analytics,
# ad networks, telemetry, browser infrastructure.
# Matched by exact hostname OR suffix (e.g. ".googleapis.com" blocks
# all subdomains of googleapis.com).
_BLOCKED_HOST_SUFFIXES: frozenset[str] = frozenset({
    # Google infrastructure
    ".googleapis.com",
    ".gstatic.com",
    ".google.com",
    ".google.de",
    ".google.co.uk",
    ".googletagmanager.com",
    ".googleanalytics.com",
    ".doubleclick.net",
    ".googlesyndication.com",
    # Microsoft / Bing
    ".microsoft.com",
    ".bing.com",
    ".msecnd.net",
    ".azure.com",
    ".azureedge.net",
    # CDN providers
    ".cloudflare.com",
    ".cloudfront.net",
    ".fastly.net",
    ".akamai.net",
    ".akamaized.net",
    ".akamaitechnologies.com",
    ".edgesuite.net",
    # Analytics & tracking
    ".analytics.google.com",
    ".segment.com",
    ".mixpanel.com",
    ".amplitude.com",
    ".hotjar.com",
    ".clarity.ms",
    # Ad networks
    ".doubleclick.net",
    ".adnxs.com",
    ".advertising.com",
    ".moatads.com",
    # Social / auth SDKs
    ".facebook.com",
    ".facebook.net",
    ".twitter.com",
    ".twimg.com",
    # Browser telemetry
    "detectportal.firefox.com",
    "content-autofill.googleapis.com",
    # Privacy management (consent popups)
    ".privacy-mgmt.com",
    ".cookielaw.org",
    ".onetrust.com",
})


class PassiveScanner:
    name = "passive_scanner"
    version = "0.3.0"

    def __init__(
        self,
        store: IStore,
        dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
        use_blocklist: bool = True,
        extra_blocked_hosts: set[str] | None = None,
    ) -> None:
        self._store = store
        self._dedup_window = timedelta(seconds=dedup_window_seconds)
        self._seen: dict[tuple[str, str], datetime] = {}
        self._use_blocklist = use_blocklist
        self._blocked_suffixes = (
            _BLOCKED_HOST_SUFFIXES | (extra_blocked_hosts or set())
        )
        self._blocked_count = 0   # for healthcheck reporting

    def _is_blocked(self, host: str) -> bool:
        """Return True if this host should be skipped."""
        if not self._use_blocklist:
            return False
        host_lower = host.lower()
        for suffix in self._blocked_suffixes:
            if host_lower == suffix.lstrip(".") or host_lower.endswith(suffix):
                return True
        return False

    # ── IModule ───────────────────────────────────────────────────

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        host = urlparse(req.url).netloc
        if self._is_blocked(host):
            self._blocked_count += 1
            return []
        findings: list[Finding] = []
        findings.extend(_check_secret_in_url(req))
        findings.extend(_check_unauthed_sensitive_path(req))
        return self._dedup(findings)

    async def on_response(
        self, req: ProxyRequest, resp: ProxyResponse
    ) -> list[Finding]:
        host = urlparse(req.url).netloc
        if self._is_blocked(host):
            return []
        findings: list[Finding] = []
        ct = resp.headers.get("content-type", "").lower()
        if _is_checkable_content_type(ct):
            findings.extend(_check_security_headers(req, resp))
            findings.extend(_check_version_disclosure(req, resp))
        return self._dedup(findings)

    async def healthcheck(self) -> ModuleHealth:
        count = len(await self._store.query("findings", {"module_name": self.name}))
        return ModuleHealth(
            module_name=self.name,
            version=self.version,
            status="ok",
            last_seen=datetime.now(timezone.utc),
            detail=(
                f"{count} finding(s) in store, "
                f"{len(self._seen)} active dedup key(s), "
                f"{self._blocked_count} blocked host request(s)"
            ),
        )

    # ── deduplication ─────────────────────────────────────────────

    def _dedup(self, findings: list[Finding]) -> list[Finding]:
        """
        Filter findings to suppress duplicates within the rolling window.

        Key: (finding.title, host extracted from finding.evidence['url'])
        A finding passes through if:
          - its key has never been seen, OR
          - the window for its key has expired
        On pass-through the key's timestamp is reset to now.
        """
        now = datetime.now(timezone.utc)
        out: list[Finding] = []
        for f in findings:
            host = _host_from_evidence(f)
            key = (f.title, host)
            last_seen = self._seen.get(key)
            if last_seen is None or (now - last_seen) >= self._dedup_window:
                self._seen[key] = now
                out.append(f)
        return out

    def flush_dedup_cache(self) -> None:
        """Clear the dedup cache — useful for testing or manual resets."""
        self._seen.clear()


# ── detection functions (pure — no I/O, easy to unit-test) ───────

def _check_secret_in_url(req: ProxyRequest) -> list[Finding]:
    parsed = urlparse(req.url)
    if not parsed.query:
        return []

    findings = []
    params = parse_qs(parsed.query, keep_blank_values=True)
    for name, values in params.items():
        if name.lower() in _SECRET_PARAMS:
            value = values[0] if values else ""
            if _SECRET_VALUE_RE.match(value):
                findings.append(Finding(
                    module_name="passive_scanner",
                    severity="high",
                    title="Sensitive data in URL",
                    description=(
                        f"Query parameter '{name}' looks like a secret and is "
                        f"exposed in the URL. URLs are logged by proxies, servers, "
                        f"and browsers."
                    ),
                    request_id=req.id,
                    evidence={
                        "parameter": name,
                        "value_preview": value[:6] + "…" if len(value) > 6 else value,
                        "url": req.url,
                    },
                ))
    return findings


def _check_unauthed_sensitive_path(req: ProxyRequest) -> list[Finding]:
    if req.method not in _AUTH_CHECK_METHODS:
        return []

    parsed = urlparse(req.url)
    path = parsed.path.lower()

    if not any(path.startswith(p) for p in _SENSITIVE_PATHS):
        return []

    headers_lower = {k.lower(): v for k, v in req.headers.items()}
    has_auth = (
        "authorization" in headers_lower
        or "x-api-key" in headers_lower
        or "cookie" in headers_lower
    )
    if has_auth:
        return []

    return [Finding(
        module_name="passive_scanner",
        severity="medium",
        title="Sensitive path accessed without authentication",
        description=(
            f"{req.method} {parsed.path} was requested with no Authorization, "
            f"X-Api-Key, or Cookie header."
        ),
        request_id=req.id,
        evidence={"method": req.method, "path": parsed.path, "url": req.url},
    )]


def _check_security_headers(req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
    findings = []
    headers_lower = {k.lower() for k in resp.headers}
    for header, (severity, description) in _SECURITY_HEADERS.items():
        if header not in headers_lower:
            findings.append(Finding(
                module_name="passive_scanner",
                severity=severity,
                title=f"Missing security header: {header}",
                description=description,
                request_id=req.id,
                evidence={"header": header, "url": req.url},
            ))
    return findings


def _check_version_disclosure(req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
    findings = []
    for header in _DISCLOSURE_HEADERS:
        value = ""
        for k, v in resp.headers.items():
            if k.lower() == header:
                value = v
                break
        if value:
            findings.append(Finding(
                module_name="passive_scanner",
                severity="low",
                title=f"Server version disclosure via {header}",
                description=(
                    f"Response includes '{header}: {value}' which reveals "
                    f"server/framework version information."
                ),
                request_id=req.id,
                evidence={"header": header, "value": value, "url": req.url},
            ))
    return findings


def _is_checkable_content_type(ct: str) -> bool:
    return any(t in ct for t in (
        "text/html", "application/json", "application/xml",
        "text/xml", "text/plain", "application/javascript",
    )) or ct == ""


def _host_from_evidence(finding: Finding) -> str:
    """Extract hostname from finding evidence URL, fall back to empty string."""
    url = finding.evidence.get("url", "")
    if url:
        return urlparse(url).netloc
    return ""