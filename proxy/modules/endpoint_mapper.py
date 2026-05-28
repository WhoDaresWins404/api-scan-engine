"""
proxy/modules/endpoint_mapper.py
────────────────────────────────────────────────────────────────────
Discovers unique host + path + method combinations and stores them
as "endpoints" records in IStore.

A Finding (severity=info) is emitted the first time each unique
endpoint is seen, so subscribers can react in real time.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

from proxy.core.interfaces import (
    Finding,
    IStore,
    ModuleHealth,
    ProxyRequest,
    ProxyResponse,
)


class EndpointMapper:
    name = "endpoint_mapper"
    version = "0.2.0"

    def __init__(self, store: IStore) -> None:
        self._store = store
        self._seen: set[str] = set()   # in-memory dedup cache

    # ── IModule ───────────────────────────────────────────────────

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        parsed = urlparse(req.url)
        key = f"{req.method}|{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if key in self._seen:
            return []

        self._seen.add(key)

        record = {
            "method": req.method,
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "first_seen": req.timestamp.isoformat(),
            "last_status": None,
        }
        await self._store.write("endpoints", record)

        finding = Finding(
            module_name=self.name,
            severity="info",
            title="New endpoint discovered",
            description=f"{req.method} {parsed.scheme}://{parsed.netloc}{parsed.path}",
            request_id=req.id,
            evidence=record,
        )
        await self._store.publish("endpoints", record)
        return [finding]

    async def on_response(
        self, req: ProxyRequest, resp: ProxyResponse
    ) -> list[Finding]:
        # Update last_status for the endpoint (best-effort, no Finding emitted)
        parsed = urlparse(req.url)
        endpoints = await self._store.query(
            "endpoints",
            {
                "method": req.method,
                "host": parsed.netloc,
                "path": parsed.path,
            },
        )
        for ep in endpoints:
            ep["last_status"] = resp.status_code
            await self._store.write("endpoints", ep)
        return []

    async def healthcheck(self) -> ModuleHealth:
        count = len(await self._store.query("endpoints"))
        return ModuleHealth(
            module_name=self.name,
            version=self.version,
            status="ok",
            last_seen=datetime.utcnow(),
            detail=f"{count} endpoint(s) discovered so far",
        )
