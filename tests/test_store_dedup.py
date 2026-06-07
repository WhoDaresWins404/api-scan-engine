"""
tests/test_store_dedup.py
────────────────────────────────────────────────────────────────────
Tests for SQLiteStore content-based IDs and deduplicate() method.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from proxy.core.store import SQLiteStore, _content_id, _content_key


def _open_store(path: str) -> SQLiteStore:
    store = SQLiteStore(path)
    store.open()
    return store


# ─────────────────────────────────────────────────────────────────
#  _content_key
# ─────────────────────────────────────────────────────────────────

def test_content_key_findings_stable():
    rec = {
        "module_name": "passive_scanner",
        "title": "Missing CSP",
        "evidence": {"url": "https://bbc.com/news"},
    }
    k1 = _content_key("findings", rec)
    k2 = _content_key("findings", rec)
    assert k1 == k2


def test_content_key_findings_differs_by_host():
    rec_a = {"module_name": "m", "title": "T", "evidence": {"url": "https://a.com/x"}}
    rec_b = {"module_name": "m", "title": "T", "evidence": {"url": "https://b.com/x"}}
    assert _content_key("findings", rec_a) != _content_key("findings", rec_b)


def test_content_key_findings_differs_by_title():
    rec_a = {"module_name": "m", "title": "T1", "evidence": {"url": "https://a.com/"}}
    rec_b = {"module_name": "m", "title": "T2", "evidence": {"url": "https://a.com/"}}
    assert _content_key("findings", rec_a) != _content_key("findings", rec_b)


def test_content_key_endpoints_stable():
    rec = {"method": "GET", "host": "api.example.com", "path": "/v1/users"}
    assert _content_key("endpoints", rec) == _content_key("endpoints", rec)


def test_content_key_endpoints_differs_by_path():
    rec_a = {"method": "GET", "host": "api.example.com", "path": "/v1/users"}
    rec_b = {"method": "GET", "host": "api.example.com", "path": "/v1/products"}
    assert _content_key("endpoints", rec_a) != _content_key("endpoints", rec_b)


def test_content_id_is_16_chars():
    assert len(_content_id("findings", {"module_name": "m", "title": "t"})) == 16


def test_content_id_stable():
    rec = {"module_name": "m", "title": "T", "evidence": {"url": "https://x.com/"}}
    assert _content_id("findings", rec) == _content_id("findings", rec)


# ─────────────────────────────────────────────────────────────────
#  Write-time deduplication via content-based IDs
# ─────────────────────────────────────────────────────────────────

async def test_same_finding_written_twice_stored_once():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = _open_store(db_path)
    finding = {
        "module_name": "passive_scanner",
        "severity": "medium",
        "title": "Missing CSP",
        "description": "No CSP header",
        "request_id": "req-1",
        "evidence": {"url": "https://bbc.com/news"},
    }
    await store.write("findings", dict(finding))
    await store.write("findings", dict(finding))   # exact duplicate

    rows = store._conn.execute(
        "SELECT COUNT(*) FROM records WHERE collection='findings'"
    ).fetchone()[0]
    store.close()
    Path(db_path).unlink()

    assert rows == 1


async def test_different_findings_both_stored():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = _open_store(db_path)
    base = {"module_name": "m", "severity": "low", "description": "d",
            "request_id": "r", "evidence": {"url": "https://x.com/"}}

    await store.write("findings", {**base, "title": "Finding A"})
    await store.write("findings", {**base, "title": "Finding B"})

    rows = store._conn.execute(
        "SELECT COUNT(*) FROM records WHERE collection='findings'"
    ).fetchone()[0]
    store.close()
    Path(db_path).unlink()

    assert rows == 2


async def test_same_endpoint_written_twice_stored_once():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = _open_store(db_path)
    ep = {"method": "GET", "scheme": "https", "host": "api.example.com",
          "path": "/v1/users", "first_seen": "2026-01-01T00:00:00+00:00"}

    await store.write("endpoints", dict(ep))
    await store.write("endpoints", dict(ep))

    rows = store._conn.execute(
        "SELECT COUNT(*) FROM records WHERE collection='endpoints'"
    ).fetchone()[0]
    store.close()
    Path(db_path).unlink()

    assert rows == 1


# ─────────────────────────────────────────────────────────────────
#  deduplicate()
# ─────────────────────────────────────────────────────────────────

def test_deduplicate_removes_old_duplicates():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = _open_store(db_path)

    # Insert duplicate findings with old-style UUID IDs directly
    for i in range(5):
        store._conn.execute(
            "INSERT INTO records (id, collection, data, created_at) VALUES (?,?,?,?)",
            (
                f"uuid-{i}",
                "findings",
                json.dumps({"module_name": "m", "title": "Missing CSP",
                            "evidence": {"url": "https://bbc.com/"}}),
                "2026-01-01T00:00:00+00:00",
            ),
        )
    store._conn.commit()

    before = store._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    result = store.deduplicate()
    after = store._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    store.close()
    Path(db_path).unlink()

    assert before == 5
    assert after == 1
    assert result.get("findings", 0) == 4


def test_deduplicate_preserves_unique_records():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = _open_store(db_path)

    for i in range(5):
        store._conn.execute(
            "INSERT INTO records (id, collection, data, created_at) VALUES (?,?,?,?)",
            (
                f"uuid-{i}",
                "findings",
                json.dumps({"module_name": "m", "title": f"Finding {i}",
                            "evidence": {"url": "https://bbc.com/"}}),
                "2026-01-01T00:00:00+00:00",
            ),
        )
    store._conn.commit()

    result = store.deduplicate()
    after = store._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    store.close()
    Path(db_path).unlink()

    assert after == 5
    assert result == {}


def test_deduplicate_empty_db_returns_empty():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = _open_store(db_path)
    result = store.deduplicate()
    store.close()
    Path(db_path).unlink()

    assert result == {}