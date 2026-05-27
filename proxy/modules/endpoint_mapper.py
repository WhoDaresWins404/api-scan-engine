# proxy/modules/endpoint_mapper.py
# Discovers and records every unique API endpoint seen in traffic.
# Writes to the 'endpoints' collection in IStore.
# Publishes 'new_endpoint' events when a previously unseen endpoint appears.
# No active probing — purely observational.

from datetime import datetime, timezone
from urllib.parse import urlparse

from proxy.core.interfaces import IModule, IStore, ModuleHealth, ProxyRequest, ProxyResponse


class EndpointMapper(IModule):

    MODULE_NAME = "endpoint_mapper"
    MODULE_VERSION = "0.1.0"

    def __init__(self, store: IStore):
        self._store = store
        self._seen: set[str] = set()   # in-memory dedup cache
        self._request_count = 0
        self._new_count = 0
        self._last_error: str = ""
        self._started_at = datetime.utcnow()

    # ------------------------------------------------------------------
    # IModule properties
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return self.MODULE_NAME

    @property
    def version(self) -> str:
        return self.MODULE_VERSION

    # ------------------------------------------------------------------
    # IModule hooks
    # ------------------------------------------------------------------

    async def on_request(self, request: ProxyRequest) -> None:
        self._request_count += 1
        try:
            await self._record_endpoint(request)
        except Exception as e:
            self._last_error = str(e)

    async def on_response(
        self, request: ProxyRequest, response: ProxyResponse
    ) -> None:
        # Update the stored endpoint record with the last observed status code.
        key = self._make_key(request)
        try:
            results = await self._store.query(
                "endpoints", {"_key": key}
            )
            if results:
                record = results[0]
                record["last_status"] = response.status_code
                record["last_seen"] = datetime.utcnow().isoformat()
                await self._store.write("endpoints", record)
        except Exception as e:
            self._last_error = str(e)

    def healthcheck(self) -> ModuleHealth:
        status = "ok" if not self._last_error else "degraded"
        detail = (
            f"requests={self._request_count} new_endpoints={self._new_count}"
            + (f" last_error={self._last_error}" if self._last_error else "")
        )
        return ModuleHealth(
            module_name=self.MODULE_NAME,
            version=self.MODULE_VERSION,
            status=status,
            last_seen=datetime.utcnow(),
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(request: ProxyRequest) -> str:
        parsed = urlparse(request.url)
        host = parsed.netloc or parsed.hostname or ""
        path = parsed.path or "/"
        return f"{request.method.upper()}:{host}:{path}"

    async def _record_endpoint(self, request: ProxyRequest) -> None:
        key = self._make_key(request)

        # Fast path — already seen in this session
        if key in self._seen:
            return

        # Check the persistent store in case this is a resumed session
        existing = await self._store.query("endpoints", {"_key": key})
        if existing:
            self._seen.add(key)
            return

        # New endpoint — record it and publish an event
        parsed = urlparse(request.url)
        record = {
            "_key": key,
            "method": request.method.upper(),
            "host": parsed.netloc or parsed.hostname or "",
            "path": parsed.path or "/",
            "query": parsed.query or "",
            "scheme": parsed.scheme or "https",
            "first_seen": request.timestamp.isoformat(),
            "last_seen": request.timestamp.isoformat(),
            "last_status": None,
        }

        await self._store.write("endpoints", record)
        self._seen.add(key)
        self._new_count += 1

        await self._store.publish("new_endpoint", {
            "key": key,
            "method": record["method"],
            "host": record["host"],
            "path": record["path"],
        })