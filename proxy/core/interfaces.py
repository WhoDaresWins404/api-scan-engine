# proxy/core/interfaces.py
# Core contracts for the API scan engine.
# No module may import anything other than these abstractions.
# Concrete implementations are injected at startup.

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Data transfer objects — shared across all modules
# ---------------------------------------------------------------------------

@dataclass
class ProxyRequest:
    id: str
    timestamp: datetime
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None = None


@dataclass
class ProxyResponse:
    request_id: str
    timestamp: datetime
    status_code: int
    headers: dict[str, str]
    body: bytes | None = None


@dataclass
class ModuleHealth:
    module_name: str
    version: str
    status: str          # "ok" | "degraded" | "error"
    last_seen: datetime
    detail: str = ""


@dataclass
class Finding:
    module_name: str
    severity: str        # "critical" | "high" | "medium" | "low" | "info"
    title: str
    description: str
    request_id: str
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# IModule — every module implements this
# ---------------------------------------------------------------------------

class IModule(ABC):
    """
    All modules are isolated units that communicate only through
    this interface and IStore. No direct module-to-module calls.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique module identifier, e.g. 'passive_scanner'"""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string, e.g. '0.1.0'"""
        ...

    @abstractmethod
    async def on_request(self, request: ProxyRequest) -> None:
        """Called before a request is forwarded to the target."""
        ...

    @abstractmethod
    async def on_response(
        self, request: ProxyRequest, response: ProxyResponse
    ) -> None:
        """Called after a response is received from the target."""
        ...

    @abstractmethod
    def healthcheck(self) -> ModuleHealth:
        """Returns current module status. Must never raise."""
        ...


# ---------------------------------------------------------------------------
# IStore — every data operation goes through this
# ---------------------------------------------------------------------------

class IStore(ABC):
    """
    Shared data store abstraction. Modules never import SQLite,
    PostgreSQL, or any other DB directly — only this interface.
    Swap the backend without touching module code.
    """

    @abstractmethod
    async def write(self, collection: str, record: dict) -> str:
        """Write a record. Returns the generated record ID."""
        ...

    @abstractmethod
    async def read(self, collection: str, record_id: str) -> dict | None:
        """Read a single record by ID. Returns None if not found."""
        ...

    @abstractmethod
    async def query(
        self, collection: str, filters: dict | None = None
    ) -> list[dict]:
        """Query a collection with optional key=value filters."""
        ...

    @abstractmethod
    async def subscribe(self, event_type: str, callback) -> None:
        """Register a callback for a named event type."""
        ...

    @abstractmethod
    async def publish(self, event_type: str, payload: dict) -> None:
        """Publish an event to all subscribers of event_type."""
        ...