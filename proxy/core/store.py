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
        self._conn.execute("PRAGMA journal_mode=WAL")
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
        # Use a content-based deterministic ID so INSERT OR REPLACE
        # naturally collapses duplicate records across proxy restarts.
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
        # VACUUM must run outside any transaction
        self._conn.isolation_level = None
        self._conn.execute("VACUUM")
        self._conn.isolation_level = ""
        return deleted

    def deduplicate(self) -> dict[str, int]:
        """
        Remove duplicate records from the existing database.

        Duplicates are records in the same collection sharing the same
        content-based key:
          findings  -> module_name + title + host
          endpoints -> method + host + path
          health    -> module_name

        Keeps the earliest record (lowest created_at) and deletes the rest.
        Returns a dict mapping collection name to number of rows deleted.
        Safe to call on a live database.
        """
        rows = self._conn.execute(
            "SELECT id, collection, data, created_at FROM records "
            "ORDER BY created_at ASC"   # process oldest first so we keep them
        ).fetchall()

        seen: dict[tuple[str, str], str] = {}   # (collection, key) -> id to keep
        to_delete: list[tuple[str, str]] = []   # (id, collection) to delete

        for row in rows:
            rec = json.loads(row["data"])
            col = row["collection"]
            key = _content_key(col, rec)
            full_key = (col, key)

            if full_key not in seen:
                seen[full_key] = row["id"]
            else:
                to_delete.append((row["id"], col))

        deleted_by_col: dict[str, int] = {}
        if to_delete:
            for rid, col in to_delete:
                self._conn.execute("DELETE FROM records WHERE id=?", (rid,))
                deleted_by_col[col] = deleted_by_col.get(col, 0) + 1
            self._conn.commit()
            # Reclaim disk space
            self._conn.isolation_level = None
            self._conn.execute("VACUUM")
            self._conn.isolation_level = ""

        return deleted_by_col

    def stats(self) -> dict[str, int]:
        """Return record count per collection."""
        rows = self._conn.execute(
            "SELECT collection, COUNT(*) as cnt FROM records GROUP BY collection"
        ).fetchall()
        return {row["collection"]: row["cnt"] for row in rows}


# ── content-based ID helpers ──────────────────────────────────────

def _content_key(collection: str, record: dict) -> str:
    """Return a stable string key representing the record's logical identity."""
    if collection == "findings":
        from urllib.parse import urlparse
        evidence = record.get("evidence", {})
        url  = evidence.get("url", "") if isinstance(evidence, dict) else ""
        host = urlparse(url).netloc if url else record.get("host", "")
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
        parts = [str(v) for v in sorted(str(v) for v in record.values())]

    return "|".join(parts)


def _content_id(collection: str, record: dict) -> str:
    """Return a short deterministic hex ID for a record."""
    key = _content_key(collection, record)
    return hashlib.sha1(f"{collection}:{key}".encode()).hexdigest()[:16]


# ── CLI entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, logging

    logging.basicConfig(level="INFO", format="%(message)s")
    log = logging.getLogger(__name__)

    p = argparse.ArgumentParser(description="SQLiteStore maintenance CLI")
    p.add_argument("--db", default="scan.db", help="Path to SQLite database")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("stats",       help="Show record counts per collection")
    sub.add_parser("dedup",       help="Remove duplicate records and VACUUM")
    vac = sub.add_parser("vacuum", help="Delete old records and VACUUM")
    vac.add_argument("--days", type=int, default=30, help="Max age in days")

    args = p.parse_args()
    store = SQLiteStore(args.db)
    store.open()

    if args.cmd == "stats":
        s = store.stats()
        total = sum(s.values())
        for col, cnt in sorted(s.items()):
            log.info("  %-20s %d", col, cnt)
        log.info("  %-20s %d", "TOTAL", total)

    elif args.cmd == "dedup":
        before = sum(store.stats().values())
        deleted = store.deduplicate()
        after = sum(store.stats().values())
        if deleted:
            for col, cnt in sorted(deleted.items()):
                log.info("  deleted %d duplicate(s) from '%s'", cnt, col)
        else:
            log.info("  no duplicates found")
        log.info("  %d -> %d records (-%d)", before, after, before - after)

    elif args.cmd == "vacuum":
        before = sum(store.stats().values())
        deleted = store.vacuum(max_age_days=args.days)
        after = sum(store.stats().values())
        log.info("  deleted %d record(s) older than %d days", deleted, args.days)
        log.info("  %d -> %d records", before, after)

    store.close()