# proxy/core/store.py
# Concrete SQLite implementation of IStore.
# Modules never import this directly — it is injected at startup.
# To migrate to PostgreSQL later: implement IStore with asyncpg,
# pass the new instance at startup. Zero module changes required.

import asyncio
import json
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from proxy.core.interfaces import IStore


DB_PATH = Path(__file__).parent.parent.parent / "scan_engine.db"

# How often the vacuum background task runs (seconds)
VACUUM_INTERVAL = 7 * 24 * 3600   # once a week


class SQLiteStore(IStore):
    """
    IStore backed by SQLite.
    All collections are stored in a single 'records' table.
    Events are dispatched in-process via asyncio callbacks.
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Call once at startup before any reads or writes."""
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
        self._create_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _create_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id          TEXT PRIMARY KEY,
                collection  TEXT NOT NULL,
                data        TEXT NOT NULL,
                created_at  TEXT NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_collection
            ON records (collection)
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # IStore implementation
    # ------------------------------------------------------------------

    async def write(self, collection: str, record: dict) -> str:
        record_id = record.get("id") or str(uuid.uuid4())
        record["id"] = record_id
        record.setdefault("created_at", datetime.now(timezone.utc).isoformat())

        self._conn.execute(
            "INSERT OR REPLACE INTO records (id, collection, data, created_at) "
            "VALUES (?, ?, ?, ?)",
            (record_id, collection, json.dumps(record), record["created_at"]),
        )
        self._conn.commit()
        return record_id

    async def read(self, collection: str, record_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT data FROM records WHERE collection = ? AND id = ?",
            (collection, record_id),
        ).fetchone()
        return json.loads(row["data"]) if row else None

    async def query(
        self, collection: str, filters: dict | None = None
    ) -> list[dict]:
        rows = self._conn.execute(
            "SELECT data FROM records WHERE collection = ?",
            (collection,),
        ).fetchall()

        results = [json.loads(row["data"]) for row in rows]

        if filters:
            for key, value in filters.items():
                results = [r for r in results if r.get(key) == value]

        return results

    async def subscribe(self, event_type: str, callback: Callable) -> None:
        self._subscribers[event_type].append(callback)

    async def publish(self, event_type: str, payload: dict) -> None:
        for callback in self._subscribers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(payload)
                else:
                    callback(payload)
            except Exception:
                pass  # subscribers must never crash the publisher

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def vacuum(self, max_age_days: int = 30) -> int:
        """
        Delete records older than max_age_days from all collections
        EXCEPT 'endpoints' (we want to keep the full discovered map).

        Returns the number of rows deleted.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=max_age_days)
        ).isoformat()

        cursor = self._conn.execute(
            "DELETE FROM records "
            "WHERE collection != 'endpoints' AND created_at < ?",
            (cutoff,),
        )
        deleted = cursor.rowcount
        self._conn.commit()
        # VACUUM must run outside any transaction — use isolation_level=None
        self._conn.isolation_level = None
        self._conn.execute("VACUUM")
        self._conn.isolation_level = ""   # restore default (deferred)
        return deleted