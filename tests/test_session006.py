"""
tests/test_session006.py
────────────────────────────────────────────────────────────────────
Tests for session-006 changes:
  - SQLiteStore.vacuum()
  - EndpointMapper v0.3.0 static asset filtering
  - FindingReporter wired as IModule
"""
from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from proxy.core.interfaces import Finding, ProxyRequest, ProxyResponse
from proxy.modules.endpoint_mapper import EndpointMapper, _is_static


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

def _req(url: str, method: str = "GET") -> ProxyRequest:
    return ProxyRequest(
        id="test-id",
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        headers={},
    )


def _resp(status: int = 200) -> ProxyResponse:
    return ProxyResponse(
        request_id="test-id",
        timestamp=datetime.now(timezone.utc),
        status_code=status,
        headers={},
    )


class FakeStore:
    def __init__(self):
        self._tables: dict = {}
        self._published = []

    async def write(self, table, record):
        self._tables.setdefault(table, []).append(record)

    async def read(self, table, id): return None

    async def query(self, table, filters=None):
        rows = self._tables.get(table, [])
        if not filters:
            return list(rows)
        return [r for r in rows if all(r.get(k) == v for k, v in filters.items())]

    async def subscribe(self, topic, handler): pass

    async def publish(self, topic, payload):
        self._published.append((topic, payload))


# ─────────────────────────────────────────────────────────────────
#  SQLiteStore.vacuum()
# ─────────────────────────────────────────────────────────────────

def test_vacuum_deletes_old_findings():
    from proxy.core.store import SQLiteStore

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.open()

    import json, sqlite3
    # Insert an old finding directly
    old_date = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    store._conn.execute(
        "INSERT INTO records (id, collection, data, created_at) VALUES (?,?,?,?)",
        ("old-1", "findings", json.dumps({"id": "old-1"}), old_date),
    )
    # Insert a recent finding
    new_date = datetime.now(timezone.utc).isoformat()
    store._conn.execute(
        "INSERT INTO records (id, collection, data, created_at) VALUES (?,?,?,?)",
        ("new-1", "findings", json.dumps({"id": "new-1"}), new_date),
    )
    # Insert an old endpoint (should NOT be deleted)
    store._conn.execute(
        "INSERT INTO records (id, collection, data, created_at) VALUES (?,?,?,?)",
        ("ep-1", "endpoints", json.dumps({"id": "ep-1"}), old_date),
    )
    store._conn.commit()

    deleted = store.vacuum(max_age_days=30)
    store.close()
    Path(db_path).unlink()

    assert deleted == 1   # only the old finding, not the old endpoint


def test_vacuum_preserves_endpoints():
    from proxy.core.store import SQLiteStore
    import json

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.open()

    old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    for i in range(5):
        store._conn.execute(
            "INSERT INTO records (id, collection, data, created_at) VALUES (?,?,?,?)",
            (f"ep-{i}", "endpoints", json.dumps({"id": f"ep-{i}"}), old_date),
        )
    store._conn.commit()

    deleted = store.vacuum(max_age_days=30)
    store.close()
    Path(db_path).unlink()

    assert deleted == 0   # endpoints never deleted


def test_vacuum_returns_zero_when_nothing_old():
    from proxy.core.store import SQLiteStore

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.open()
    deleted = store.vacuum(max_age_days=30)
    store.close()
    Path(db_path).unlink()

    assert deleted == 0


# ─────────────────────────────────────────────────────────────────
#  _is_static helper
# ─────────────────────────────────────────────────────────────────

def test_is_static_javascript():
    assert _is_static("/app/bundle.js") is True
    assert _is_static("/chunk-abc123.mjs") is True


def test_is_static_css():
    assert _is_static("/styles/main.css") is True


def test_is_static_images():
    for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"):
        assert _is_static(f"/img/logo{ext}") is True


def test_is_static_fonts():
    for ext in (".woff", ".woff2", ".ttf", ".otf"):
        assert _is_static(f"/fonts/myfont{ext}") is True


def test_is_static_media():
    assert _is_static("/video/promo.mp4") is True
    assert _is_static("/stream/playlist.m3u8") is True


def test_is_static_api_paths_not_filtered():
    assert _is_static("/api/users") is False
    assert _is_static("/v1/products") is False
    assert _is_static("/graphql") is False
    assert _is_static("/admin/dashboard") is False


def test_is_static_strips_query_string():
    assert _is_static("/bundle.js?v=abc123") is True
    assert _is_static("/api/data?format=json") is False


def test_is_static_no_extension():
    assert _is_static("/about") is False
    assert _is_static("/") is False


# ─────────────────────────────────────────────────────────────────
#  EndpointMapper v0.3.0 — asset filtering
# ─────────────────────────────────────────────────────────────────

async def test_mapper_skips_js_by_default():
    store = FakeStore()
    mapper = EndpointMapper(store)
    req = _req("https://example.com/bundle.min.js")
    findings = await mapper.on_request(req)
    assert findings == []
    assert mapper._skipped == 1
    assert store._tables.get("endpoints", []) == []


async def test_mapper_skips_images_by_default():
    store = FakeStore()
    mapper = EndpointMapper(store)
    for ext in (".png", ".jpg", ".svg", ".woff2"):
        findings = await mapper.on_request(_req(f"https://cdn.example.com/img/logo{ext}"))
        assert findings == []
    assert mapper._skipped == 4


async def test_mapper_records_api_paths():
    store = FakeStore()
    mapper = EndpointMapper(store)
    findings = await mapper.on_request(_req("https://api.example.com/v1/users"))
    assert len(findings) == 1
    assert findings[0].title == "New endpoint discovered"
    assert len(store._tables.get("endpoints", [])) == 1


async def test_mapper_filter_disabled():
    store = FakeStore()
    mapper = EndpointMapper(store, filter_assets=False)
    findings = await mapper.on_request(_req("https://cdn.example.com/bundle.js"))
    assert len(findings) == 1   # recorded when filter off
    assert mapper._skipped == 0


async def test_mapper_healthcheck_reports_skipped():
    store = FakeStore()
    mapper = EndpointMapper(store)
    await mapper.on_request(_req("https://cdn.example.com/app.js"))
    await mapper.on_request(_req("https://api.example.com/users"))
    health = await mapper.healthcheck()
    assert "1 static asset(s) skipped" in health.detail
    assert "1 endpoint(s)" in health.detail


async def test_mapper_on_response_skips_static():
    store = FakeStore()
    mapper = EndpointMapper(store)
    req = _req("https://cdn.example.com/style.css")
    resp = _resp(200)
    findings = await mapper.on_response(req, resp)
    assert findings == []


# ─────────────────────────────────────────────────────────────────
#  FindingReporter wired as IModule
# ─────────────────────────────────────────────────────────────────

async def test_reporter_on_request_returns_empty():
    from proxy.modules.finding_reporter import FindingReporter
    store = FakeStore()
    reporter = FindingReporter(store, console=False, json_path=None, csv_path=None)
    await reporter.start()
    findings = await reporter.on_request(_req("https://example.com/api"))
    assert findings == []


async def test_reporter_on_response_returns_empty():
    from proxy.modules.finding_reporter import FindingReporter
    store = FakeStore()
    reporter = FindingReporter(store, console=False, json_path=None, csv_path=None)
    await reporter.start()
    findings = await reporter.on_response(_req("https://example.com/api"), _resp())
    assert findings == []


async def test_reporter_healthcheck_as_imodule():
    from proxy.modules.finding_reporter import FindingReporter
    store = FakeStore()
    reporter = FindingReporter(store, console=False, json_path=None, csv_path=None)
    await reporter.start()
    health = await reporter.healthcheck()
    assert health.module_name == "finding_reporter"
    assert health.status == "ok"