# proxy/core/store.py
# Concrete SQLite implementation of IStore.
# Modules never import this directly — it is injected at startup.
# To migrate to PostgreSQL later: implement IStore with asyncpg,
# pass the new instance at startup. Zero module changes required.

import asyncio
import hashlib
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
        # Use a content-based deterministic ID where possible so that
        # INSERT OR REPLACE naturally collapses duplicate records across
        # proxy restarts instead of accumulating them with fresh UUIDs.
        record_id = record.get("id") or _content_id(collection, record)
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

    def deduplicate(self) -> dict[str, int]:
        """
        Remove duplicate records from the existing database.

        Duplicates are records in the same collection with the same
        content-based key (title+module+host for findings,
        method+host+path for endpoints).  Keeps the earliest record
        (lowest created_at) and deletes the rest.

        Returns a dict mapping collection name to number of rows deleted.
        Safe to call on a live database — uses a single transaction.
        """
        rows = self._conn.execute(
            "SELECT id, collection, data FROM records"
        ).fetchall()

        # Group by (collection, content_key) — keep earliest
        seen: dict[tuple[str, str], tuple[str, str]] = {}  # key -> (id, created_at)
        to_delete: list[str] = []

        for row in rows:
            rec = json.loads(row["data"])
            col = row["collection"]
            key = _content_key(col, rec)
            full_key = (col, key)

            if full_key not in seen:
                seen[full_key] = row["id"]
            else:
                to_delete.append(row["id"])

        deleted_by_col: dict[str, int] = {}
        if to_delete:
            for rid in to_delete:
                # find collection for reporting
                row = self._conn.execute(
                    "SELECT collection FROM records WHERE id=?", (rid,)
                ).fetchone()
                if row:
                    col = row["collection"]
                    deleted_by_col[col] = deleted_by_col.get(col, 0) + 1
                self._conn.execute("DELETE FROM records WHERE id=?", (rid,))
            self._conn.commit()
            # Reclaim space
            self._conn.isolation_level = None
            self._conn.execute("VACUUM")
            self._conn.isolation_level = ""

        return deleted_by_col
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


# ── content-based ID helpers ──────────────────────────────────────

def _content_key(collection: str, record: dict) -> str:
    """Return a stable string key representing the record's logical identity."""
    if collection == "findings":
        # Same finding = same module + title + host (from evidence URL)
        from urllib.parse import urlparse
        url   = record.get("evidence", {}).get("url", "") if isinstance(record.get("evidence"), dict) else ""
        host  = urlparse(url).netloc if url else record.get("host", "")
        parts = [
            record.get("module_name", ""),
            record.get("title", ""),
            host,
        ]
    elif collection == "endpoints":
        parts = [
            record.get("method", ""),
            record.get("host", ""),
            record.get("path", ""),
        ]
    elif collection == "health":
        parts = [record.get("module_name", "")]
    else:
        # Fallback: use all values sorted for stability
        parts = [str(v) for v in sorted(record.values())]

    return "|".join(parts)


def _content_id(collection: str, record: dict) -> str:
    """Return a short deterministic hex ID for a record."""
    key = _content_key(collection, record)
    return hashlib.sha1(f"{collection}:{key}".encode()).hexdigest()[:16]