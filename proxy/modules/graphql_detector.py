"""
proxy/modules/graphql_detector.py
────────────────────────────────────────────────────────────────────
GraphQL Detector — Phase 2 first module.

Identifies GraphQL traffic and flags security issues:

  on_request:
    [info]   GraphQL endpoint discovered (first time seen per host)
    [high]   Introspection query -- full schema exposure
    [medium] Mutation without Authorization / X-Api-Key / Cookie
    [medium] Batched query array -- potential DoS amplification

  on_response:
    [low]    GraphQL errors in response body -- leaks internals

Detection strategy
──────────────────
GraphQL can travel over:
  - POST  /graphql          (most common)
  - POST  /api/graphql
  - POST  /v1/graphql
  - GET   /graphql?query=…  (less common, read-only)
  - Any path with Content-Type: application/graphql

We detect by:
  1. Path contains "graphql" (case-insensitive)
  2. Content-Type: application/graphql  OR  application/json with
     a body containing a "query" key at the top level

Deduplication
─────────────
  Endpoint-discovered findings dedup by host (one per host).
  All other findings dedup by (title, host) with a 24h window.
"""
from __future__ import annotations

import json
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
DEDUP_WINDOW_SECONDS: int = 86_400   # 24 hours

_GRAPHQL_PATH_RE   = re.compile(r"/graphql", re.IGNORECASE)
_INTROSPECTION_RE  = re.compile(r"__schema|__type", re.IGNORECASE)
_MUTATION_RE       = re.compile(r"\bmutation\b", re.IGNORECASE)


class GraphQLDetector:
    name = "graphql_detector"
    version = "0.1.0"

    def __init__(
        self,
        store: IStore,
        dedup_window_seconds: int = DEDUP_WINDOW_SECONDS,
    ) -> None:
        self._store = store
        self._dedup_window = timedelta(seconds=dedup_window_seconds)
        self._seen: dict[tuple[str, str], datetime] = {}
        self._endpoints_seen: set[str] = set()

    # ── IModule ───────────────────────────────────────────────────

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        if not _is_graphql_request(req):
            return []

        findings: list[Finding] = []
        host = urlparse(req.url).netloc
        body_str = _body_str(req.body)
        gql_body = _parse_graphql_body(req, body_str)

        # endpoint discovery (once per host)
        if host not in self._endpoints_seen:
            self._endpoints_seen.add(host)
            findings.append(Finding(
                module_name=self.name,
                severity="info",
                title="GraphQL endpoint discovered",
                description=f"GraphQL API detected at {req.url}",
                request_id=req.id,
                evidence={"url": req.url, "method": req.method},
            ))

        if gql_body is None:
            return self._dedup(findings, host)

        # batched query array
        if isinstance(gql_body, list) and len(gql_body) > 1:
            findings.append(Finding(
                module_name=self.name,
                severity="medium",
                title="GraphQL batched query detected",
                description=(
                    f"Request contains {len(gql_body)} batched GraphQL operations. "
                    "Batching can amplify server load and may be used for "
                    "DoS or brute-force attacks if not rate-limited."
                ),
                request_id=req.id,
                evidence={"url": req.url, "batch_size": len(gql_body)},
            ))
            return self._dedup(findings, host)

        query = gql_body.get("query", "") or "" if isinstance(gql_body, dict) else ""

        # introspection
        if _INTROSPECTION_RE.search(query):
            findings.append(Finding(
                module_name=self.name,
                severity="high",
                title="GraphQL introspection query detected",
                description=(
                    "An introspection query (__schema or __type) was sent. "
                    "If introspection is enabled in production it exposes the "
                    "full API schema to attackers, including all types, fields, "
                    "and mutations."
                ),
                request_id=req.id,
                evidence={"url": req.url, "query_preview": query[:200]},
            ))

        # mutation without auth
        if _MUTATION_RE.search(query):
            headers_lower = {k.lower() for k in req.headers}
            has_auth = (
                "authorization" in headers_lower
                or "x-api-key" in headers_lower
                or "cookie" in headers_lower
            )
            if not has_auth:
                findings.append(Finding(
                    module_name=self.name,
                    severity="medium",
                    title="GraphQL mutation without authentication",
                    description=(
                        "A GraphQL mutation was sent with no Authorization, "
                        "X-Api-Key, or Cookie header."
                    ),
                    request_id=req.id,
                    evidence={"url": req.url, "query_preview": query[:200]},
                ))

        return self._dedup(findings, host)

    async def on_response(
        self, req: ProxyRequest, resp: ProxyResponse
    ) -> list[Finding]:
        if not _is_graphql_response(resp):
            return []

        host = urlparse(req.url).netloc
        body_str = _body_str(resp.body)

        try:
            data = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            return []

        errors = data.get("errors") if isinstance(data, dict) else None
        if not errors or not isinstance(errors, list):
            return []

        first_msg = ""
        if isinstance(errors[0], dict):
            first_msg = str(errors[0].get("message", ""))

        return self._dedup([Finding(
            module_name=self.name,
            severity="low",
            title="GraphQL errors exposed in response",
            description=(
                f"Response contains {len(errors)} GraphQL error(s). "
                "Error messages may leak internal implementation details, "
                "stack traces, or schema information."
            ),
            request_id=req.id,
            evidence={
                "url": req.url,
                "error_count": len(errors),
                "first_message": first_msg[:200],
            },
        )], host)

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
                f"{len(self._endpoints_seen)} GraphQL endpoint(s) discovered, "
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


# ── helpers ───────────────────────────────────────────────────────

def _is_graphql_request(req: ProxyRequest) -> bool:
    parsed = urlparse(req.url)
    if _GRAPHQL_PATH_RE.search(parsed.path):
        return True
    ct = req.headers.get("content-type", "").lower()
    if "application/graphql" in ct:
        return True
    if req.method == "POST" and "application/json" in ct and req.body:
        try:
            body = json.loads(req.body)
            if isinstance(body, dict) and "query" in body:
                return True
            if isinstance(body, list) and body and isinstance(body[0], dict) and "query" in body[0]:
                return True
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            pass
    return False


def _is_graphql_response(resp: ProxyResponse) -> bool:
    ct = resp.headers.get("content-type", "").lower()
    if "application/json" not in ct and "application/graphql" not in ct:
        return False
    if not resp.body:
        return False
    try:
        sniff = resp.body[:64].decode("utf-8", errors="ignore")
        return "data" in sniff or "errors" in sniff
    except Exception:
        return False


def _body_str(body: bytes | None) -> str:
    if not body:
        return ""
    try:
        return body.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_graphql_body(req: ProxyRequest, body_str: str) -> dict | list | None:
    if not body_str:
        return None
    ct = req.headers.get("content-type", "").lower()
    if "application/graphql" in ct:
        return {"query": body_str}
    try:
        parsed = json.loads(body_str)
        if isinstance(parsed, (dict, list)):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass
    return None