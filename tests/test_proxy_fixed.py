"""
tests/test_proxy.py
────────────────────────────────────────────────────────────────────
Tests for proxy/core/proxy.py — the ScanAddon mitmproxy bridge.

Strategy
────────
We never spin up a real mitmproxy instance.  Instead we:

  1. Build minimal stubs for mitmproxy's http.HTTPFlow / HTTPRequest /
     HTTPResponse objects (only the attributes ScanAddon reads).
  2. Call ScanAddon.request() / .response() directly, as mitmproxy
     would.
  3. Assert the right calls land on our FakeStore / FakeModule.

This makes the suite fast, dependency-free at test time (mitmproxy is
still imported since ScanAddon imports it, but no network is used),
and fully deterministic.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

import pytest

from proxy.core.interfaces import (
    Finding,
    IModule,
    IStore,
    ModuleHealth,
    ProxyRequest,
    ProxyResponse,
)
from proxy.core.proxy import ScanAddon, _flatten, _timed


# ─────────────────────────────────────────────────────────────────
#  Fakes
# ─────────────────────────────────────────────────────────────────

class FakeStore:
    """Minimal in-memory IStore."""

    def __init__(self):
        self._tables: dict[str, list[dict]] = {}
        self._published: list[tuple[str, Any]] = []
        self._subscribers: dict[str, list] = {}

    async def write(self, table: str, record: dict) -> None:
        self._tables.setdefault(table, []).append(record)

    async def read(self, table: str, id: str) -> dict | None:
        for r in self._tables.get(table, []):
            if r.get("id") == id:
                return r
        return None

    async def query(self, table: str, filters: dict | None = None) -> list[dict]:
        rows = self._tables.get(table, [])
        if not filters:
            return list(rows)
        return [r for r in rows if all(r.get(k) == v for k, v in filters.items())]

    async def subscribe(self, topic: str, handler) -> None:
        self._subscribers.setdefault(topic, []).append(handler)

    async def publish(self, topic: str, payload: Any) -> None:
        self._published.append((topic, payload))
        for h in self._subscribers.get(topic, []):
            await h(payload)


class NullModule:
    """Module that always returns no findings."""
    name = "null_module"
    version = "0.0.1"

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        return []

    async def on_response(self, req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
        return []

    async def healthcheck(self) -> ModuleHealth:
        return ModuleHealth(
            module_name=self.name, version=self.version,
            status="ok", last_seen=datetime.utcnow()
        )


class RecordingModule:
    """Module that records calls and returns a canned Finding on response."""
    name = "recording_module"
    version = "0.0.1"

    def __init__(self):
        self.requests: list[ProxyRequest] = []
        self.responses: list[tuple[ProxyRequest, ProxyResponse]] = []

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        self.requests.append(req)
        return []

    async def on_response(self, req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
        self.responses.append((req, resp))
        return [
            Finding(
                module_name=self.name,
                severity="info",
                title="Test finding",
                description="response observed",
                request_id=req.id,
            )
        ]

    async def healthcheck(self) -> ModuleHealth:
        return ModuleHealth(
            module_name=self.name, version=self.version,
            status="ok", last_seen=datetime.utcnow()
        )


class SlowModule:
    """Module that always times out."""
    name = "slow_module"
    version = "0.0.1"

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        await asyncio.sleep(999)
        return []

    async def on_response(self, req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
        await asyncio.sleep(999)
        return []

    async def healthcheck(self) -> ModuleHealth:
        await asyncio.sleep(999)


class BrokenModule:
    """Module that always raises."""
    name = "broken_module"
    version = "0.0.1"

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        raise RuntimeError("boom")

    async def on_response(self, req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
        raise RuntimeError("boom")

    async def healthcheck(self) -> ModuleHealth:
        raise RuntimeError("boom")


# ─────────────────────────────────────────────────────────────────
#  mitmproxy flow stubs
# ─────────────────────────────────────────────────────────────────

def _make_flow(
    method: str = "GET",
    url: str = "https://api.example.com/users",
    req_body: bytes = b"",
    status_code: int = 200,
    resp_body: bytes = b'{"ok":true}',
) -> MagicMock:
    """Build a minimal mitmproxy HTTPFlow stub."""
    flow = MagicMock()
    flow.metadata = {}
    flow.error = None

    # request side
    flow.request.method = method
    flow.request.pretty_url = url
    flow.request.headers = {"user-agent": "test"}
    flow.request.content = req_body

    # response side
    flow.response.status_code = status_code
    flow.response.headers = {"content-type": "application/json"}
    flow.response.content = resp_body

    return flow


# ─────────────────────────────────────────────────────────────────
#  Utility tests
# ─────────────────────────────────────────────────────────────────

async def test_timed_normal():
    async def fast():
        return [1, 2, 3]
    result = await _timed(fast(), timeout=1.0, name="fast")
    assert result == [1, 2, 3]


async def test_timed_timeout():
    async def slow():
        await asyncio.sleep(999)
        return ["never"]
    result = await _timed(slow(), timeout=0.05, name="slow")
    assert result == []


async def test_timed_exception():
    async def boom():
        raise ValueError("oops")
    result = await _timed(boom(), timeout=1.0, name="boom")
    assert result == []


def test_flatten_mixed():
    findings = [Finding("m", "info", "t", "d", "r")]
    result = _flatten([findings, [], Exception("x")])
    assert len(result) == 1
    assert result[0].module_name == "m"


# ─────────────────────────────────────────────────────────────────
#  ScanAddon — request hook
# ─────────────────────────────────────────────────────────────────

async def test_request_hook_populates_metadata():
    store = FakeStore()
    mod = RecordingModule()
    addon = ScanAddon(modules=[mod], store=store)

    flow = _make_flow()
    await addon.request(flow)

    assert "scan_request" in flow.metadata
    req = flow.metadata["scan_request"]
    assert req.method == "GET"
    assert req.url == "https://api.example.com/users"


async def test_request_hook_calls_module():
    store = FakeStore()
    mod = RecordingModule()
    addon = ScanAddon(modules=[mod], store=store)

    flow = _make_flow(method="POST", url="https://api.example.com/login")
    await addon.request(flow)

    assert len(mod.requests) == 1
    assert mod.requests[0].method == "POST"


async def test_request_hook_tolerates_slow_module():
    store = FakeStore()
    addon = ScanAddon(modules=[SlowModule()], store=store)
    addon.__class__  # ensure MODULE_TIMEOUT patch works
    import proxy.core.proxy as proxy_mod
    orig = proxy_mod.MODULE_TIMEOUT
    proxy_mod.MODULE_TIMEOUT = 0.05
    try:
        flow = _make_flow()
        # should complete quickly despite slow module
        await asyncio.wait_for(addon.request(flow), timeout=2.0)
    finally:
        proxy_mod.MODULE_TIMEOUT = orig


async def test_request_hook_tolerates_broken_module():
    store = FakeStore()
    addon = ScanAddon(modules=[BrokenModule()], store=store)
    flow = _make_flow()
    # must not raise
    await addon.request(flow)


# ─────────────────────────────────────────────────────────────────
#  ScanAddon — response hook
# ─────────────────────────────────────────────────────────────────

async def test_response_hook_calls_module():
    store = FakeStore()
    mod = RecordingModule()
    addon = ScanAddon(modules=[mod], store=store)

    flow = _make_flow(status_code=201)
    await addon.request(flow)   # populates metadata
    await addon.response(flow)

    assert len(mod.responses) == 1
    req, resp = mod.responses[0]
    assert resp.status_code == 201


async def test_response_hook_persists_findings():
    store = FakeStore()
    mod = RecordingModule()
    addon = ScanAddon(modules=[mod], store=store)

    flow = _make_flow()
    await addon.request(flow)
    await addon.response(flow)

    findings_rows = store._tables.get("findings", [])
    assert len(findings_rows) == 1
    assert findings_rows[0]["title"] == "Test finding"


async def test_response_hook_without_prior_request():
    """response() must work even if request() was never called on this flow."""
    store = FakeStore()
    mod = RecordingModule()
    addon = ScanAddon(modules=[mod], store=store)

    flow = _make_flow()
    # skip addon.request() — simulate an edge case
    await addon.response(flow)

    assert len(mod.responses) == 1


# ─────────────────────────────────────────────────────────────────
#  ScanAddon — findings published to store
# ─────────────────────────────────────────────────────────────────

async def test_findings_published():
    store = FakeStore()
    received = []

    async def _capture(f):
        received.append(f)

    await store.subscribe("findings", _capture)

    mod = RecordingModule()
    addon = ScanAddon(modules=[mod], store=store)

    flow = _make_flow()
    await addon.request(flow)
    await addon.response(flow)

    pubs = [p for topic, p in store._published if topic == "findings"]
    assert len(pubs) == 1


# ─────────────────────────────────────────────────────────────────
#  ScanAddon + EndpointMapper integration
# ─────────────────────────────────────────────────────────────────

async def test_endpoint_mapper_wired_to_proxy():
    from proxy.modules.endpoint_mapper import EndpointMapper

    store = FakeStore()
    mapper = EndpointMapper(store)
    addon = ScanAddon(modules=[mapper], store=store)

    # First request — should be stored as new endpoint
    flow1 = _make_flow(method="GET", url="https://api.example.com/items", status_code=200)
    await addon.request(flow1)
    await addon.response(flow1)

    endpoints = store._tables.get("endpoints", [])
    assert len(endpoints) >= 1
    assert any(ep["path"] == "/items" for ep in endpoints)

    # Findings table should have the "new endpoint" info finding
    findings = store._tables.get("findings", [])
    assert any(f["title"] == "New endpoint discovered" for f in findings)


async def test_endpoint_mapper_deduplication():
    from proxy.modules.endpoint_mapper import EndpointMapper

    store = FakeStore()
    mapper = EndpointMapper(store)
    addon = ScanAddon(modules=[mapper], store=store)

    url = "https://api.example.com/products"
    for _ in range(5):
        flow = _make_flow(method="GET", url=url)
        await addon.request(flow)
        await addon.response(flow)

    # Only 1 "New endpoint discovered" finding despite 5 requests
    findings = store._tables.get("findings", [])
    new_ep_findings = [f for f in findings if f["title"] == "New endpoint discovered"]
    assert len(new_ep_findings) == 1


async def test_endpoint_mapper_different_methods_counted_separately():
    from proxy.modules.endpoint_mapper import EndpointMapper

    store = FakeStore()
    mapper = EndpointMapper(store)
    addon = ScanAddon(modules=[mapper], store=store)

    for method in ("GET", "POST", "DELETE"):
        flow = _make_flow(method=method, url="https://api.example.com/resource")
        await addon.request(flow)
        await addon.response(flow)

    findings = store._tables.get("findings", [])
    new_ep_findings = [f for f in findings if f["title"] == "New endpoint discovered"]
    assert len(new_ep_findings) == 3


async def test_multiple_modules_all_called():
    mod_a = RecordingModule()
    mod_a.name = "mod_a"
    mod_b = RecordingModule()
    mod_b.name = "mod_b"

    store = FakeStore()
    addon = ScanAddon(modules=[mod_a, mod_b], store=store)

    flow = _make_flow()
    await addon.request(flow)
    await addon.response(flow)

    assert len(mod_a.requests) == 1
    assert len(mod_b.requests) == 1
    assert len(mod_a.responses) == 1
    assert len(mod_b.responses) == 1
