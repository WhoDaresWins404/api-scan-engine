"""
proxy/core/proxy.py
────────────────────────────────────────────────────────────────────
ScanAddon — mitmproxy addon that feeds live HTTP(S) traffic through
every registered IModule and persists results via IStore.

Design decisions
────────────────
* mitmproxy runs its own asyncio loop; we integrate by using
  mitmproxy's native async hooks (request / response / error).
* Each flow gets a stable ProxyRequest built once on `request` and
  stored in flow.metadata so the `response` hook can retrieve it
  without re-parsing.
* Module calls are fire-and-forget tasks so a slow module never
  blocks the proxy.  Findings are gathered via asyncio.gather with
  a per-module timeout (default 5 s).
* All findings are written to the store via IStore.write().
* Health of each module is checked on startup and every
  HEALTH_INTERVAL seconds thereafter.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any

from mitmproxy import http
from mitmproxy.options import Options

from proxy.core.interfaces import (
    Finding,
    IModule,
    IStore,
    ProxyRequest,
    ProxyResponse,
)

log = logging.getLogger("scan.proxy")

# ── tunables ──────────────────────────────────────────────────────
MODULE_TIMEOUT = 5.0          # seconds before a module call is abandoned
HEALTH_INTERVAL = 60.0        # seconds between health sweeps
META_KEY = "scan_request"     # key in flow.metadata


# ─────────────────────────────────────────────────────────────────
class ScanAddon:
    """
    mitmproxy addon.  Instantiate with a list of IModule objects and
    an IStore implementation, then pass to mitmproxy's master.

    Example
    ───────
        from proxy.core.proxy import ScanAddon
        from proxy.modules.endpoint_mapper import EndpointMapper
        from proxy.core.store import SQLiteStore

        store   = SQLiteStore("scan.db")
        addon   = ScanAddon(modules=[EndpointMapper(store)], store=store)
    """

    def __init__(self, modules: list[IModule], store: IStore) -> None:
        self.modules: list[IModule] = modules
        self.store: IStore = store
        self._health_task: asyncio.Task | None = None

    # ── mitmproxy lifecycle ───────────────────────────────────────

    def running(self) -> None:
        """Called by mitmproxy when the proxy is ready to accept connections."""
        log.info("ScanAddon running — %d module(s) loaded", len(self.modules))
        for mod in self.modules:
            log.info("  • %s v%s", mod.name, mod.version)
        # kick off background health polling
        loop = asyncio.get_event_loop()
        self._health_task = loop.create_task(self._health_loop())

    def done(self) -> None:
        """Called by mitmproxy on shutdown."""
        if self._health_task:
            self._health_task.cancel()
        log.info("ScanAddon stopped")

    # ── traffic hooks ─────────────────────────────────────────────

    async def request(self, flow: http.HTTPFlow) -> None:
        """Intercept outbound request."""
        req = _flow_to_request(flow)
        flow.metadata[META_KEY] = req

        findings = await self._run_modules_request(req)
        await self._persist_findings(findings)

    async def response(self, flow: http.HTTPFlow) -> None:
        """Intercept inbound response."""
        req: ProxyRequest | None = flow.metadata.get(META_KEY)
        if req is None:
            # edge case: flow was created before addon was attached
            req = _flow_to_request(flow)

        resp = _flow_to_response(req.id, flow)

        findings = await self._run_modules_response(req, resp)
        await self._persist_findings(findings)

    async def error(self, flow: http.HTTPFlow) -> None:
        """Log proxy-level errors (TLS failures, connection resets, …)."""
        req: ProxyRequest | None = flow.metadata.get(META_KEY)
        rid = req.id if req else "unknown"
        log.warning("flow error [request_id=%s]: %s", rid, flow.error)

    # ── internal helpers ──────────────────────────────────────────

    async def _run_modules_request(self, req: ProxyRequest) -> list[Finding]:
        tasks = [
            _timed(mod.on_request(req), MODULE_TIMEOUT, mod.name)
            for mod in self.modules
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return _flatten(results)

    async def _run_modules_response(
        self, req: ProxyRequest, resp: ProxyResponse
    ) -> list[Finding]:
        tasks = [
            _timed(mod.on_response(req, resp), MODULE_TIMEOUT, mod.name)
            for mod in self.modules
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return _flatten(results)

    async def _persist_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            try:
                await self.store.write(
                    "findings",
                    {
                        "module_name": f.module_name,
                        "severity": f.severity,
                        "title": f.title,
                        "description": f.description,
                        "request_id": f.request_id,
                        "evidence": f.evidence,
                        "timestamp": f.timestamp.isoformat(),
                    },
                )
                await self.store.publish("findings", f)
            except Exception as exc:
                log.error("Failed to persist finding: %s", exc)

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(HEALTH_INTERVAL)
            for mod in self.modules:
                try:
                    health = await asyncio.wait_for(
                        mod.healthcheck(), timeout=MODULE_TIMEOUT
                    )
                    await self.store.write(
                        "health",
                        {
                            "module_name": health.module_name,
                            "version": health.version,
                            "status": health.status,
                            "last_seen": health.last_seen.isoformat(),
                            "detail": health.detail,
                        },
                    )
                    log.debug(
                        "health [%s] %s — %s",
                        health.module_name,
                        health.status,
                        health.detail,
                    )
                except Exception as exc:
                    log.error("Healthcheck failed for %s: %s", mod.name, exc)


# ── flow conversion helpers ───────────────────────────────────────

def _flow_to_request(flow: http.HTTPFlow) -> ProxyRequest:
    mf = flow.request
    return ProxyRequest(
        id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        method=mf.method,
        url=mf.pretty_url,
        headers=dict(mf.headers),
        body=mf.content or None,
    )


def _flow_to_response(request_id: str, flow: http.HTTPFlow) -> ProxyResponse:
    mresp = flow.response
    return ProxyResponse(
        request_id=request_id,
        timestamp=datetime.utcnow(),
        status_code=mresp.status_code,
        headers=dict(mresp.headers),
        body=mresp.content or None,
    )


# ── concurrency utilities ─────────────────────────────────────────

async def _timed(coro, timeout: float, name: str):
    """Wrap a coroutine with a timeout; log and return [] on failure."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("Module %s timed out", name)
        return []
    except Exception as exc:
        log.error("Module %s raised: %s", name, exc)
        return []


def _flatten(results: list) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
    return out
