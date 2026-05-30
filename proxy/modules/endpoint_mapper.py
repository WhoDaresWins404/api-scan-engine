"""
proxy/modules/endpoint_mapper.py
────────────────────────────────────────────────────────────────────
Discovers unique host + path + method combinations and stores them
as "endpoints" records in IStore.

A Finding (severity=info) is emitted the first time each unique
endpoint is seen, so subscribers can react in real time.

v0.3.0 — static asset filtering
  Static assets (.js, .css, images, fonts, etc.) are skipped by
  default.  They inflate the endpoint count with noise that has no
  security relevance.  Pass filter_assets=False to disable.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from proxy.core.interfaces import (
    Finding,
    IStore,
    ModuleHealth,
    ProxyRequest,
    ProxyResponse,
)

# Extensions considered static noise — never interesting for security scanning
_STATIC_EXTENSIONS: frozenset[str] = frozenset({
    # scripts / styles
    ".js", ".mjs", ".cjs", ".css", ".map",
    # images
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".avif", ".bmp", ".tiff",
    # fonts
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    # media
    ".mp4", ".webm", ".m3u8", ".ts", ".mp3", ".ogg",
    # documents / data (static)
    ".pdf", ".txt", ".xml",
    # archives
    ".gz", ".br", ".zip",
})


def _is_static(path: str) -> bool:
    """Return True if the path looks like a static asset."""
    lower = path.lower().split("?")[0]   # strip query string
    dot = lower.rfind(".")
    if dot == -1:
        return False
    return lower[dot:] in _STATIC_EXTENSIONS


class EndpointMapper:
    name = "endpoint_mapper"
    version = "0.3.0"

    def __init__(self, store: IStore, filter_assets: bool = True) -> None:
        self._store = store
        self._filter_assets = filter_assets
        self._seen: set[str] = set()   # in-memory dedup cache
        self._skipped: int = 0         # static assets skipped (for healthcheck)

    # ── IModule ───────────────────────────────────────────────────

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        parsed = urlparse(req.url)

        if self._filter_assets and _is_static(parsed.path):
            self._skipped += 1
            return []

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
        parsed = urlparse(req.url)

        if self._filter_assets and _is_static(parsed.path):
            return []

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
            last_seen=datetime.now(timezone.utc),
            detail=(
                f"{count} endpoint(s) discovered, "
                f"{self._skipped} static asset(s) skipped"
            ),
        )