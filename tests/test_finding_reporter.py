"""
tests/test_finding_reporter.py
────────────────────────────────────────────────────────────────────
Tests for proxy/modules/finding_reporter.py
"""
from __future__ import annotations

import csv
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from proxy.core.interfaces import Finding
from proxy.modules.finding_reporter import (
    CSV_FIELDS,
    SEVERITY_ORDER,
    FindingReporter,
    _dict_to_finding,
)


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

class FakeStore:
    def __init__(self):
        self._subscribers: dict = {}
        self._written: list = []

    async def write(self, table, record): self._written.append((table, record))
    async def read(self, table, id): return None
    async def query(self, table, filters=None): return []
    async def subscribe(self, topic, handler):
        self._subscribers.setdefault(topic, []).append(handler)
    async def publish(self, topic, payload):
        for h in self._subscribers.get(topic, []):
            await h(payload)


def _finding(
    severity="medium",
    title="Test finding",
    description="A test finding description",
    module="test_module",
    request_id="req-123",
) -> Finding:
    return Finding(
        module_name=module,
        severity=severity,
        title=title,
        description=description,
        request_id=request_id,
        evidence={"url": "https://example.com"},
        timestamp=datetime.now(timezone.utc),
    )


# ─────────────────────────────────────────────────────────────────
#  _dict_to_finding
# ─────────────────────────────────────────────────────────────────

def test_dict_to_finding_basic():
    d = {
        "module_name": "pm",
        "severity": "high",
        "title": "T",
        "description": "D",
        "request_id": "r1",
        "evidence": {"k": "v"},
        "timestamp": "2026-01-01T12:00:00+00:00",
    }
    f = _dict_to_finding(d)
    assert f.severity == "high"
    assert f.title == "T"
    assert f.evidence == {"k": "v"}


def test_dict_to_finding_missing_timestamp():
    f = _dict_to_finding({"module_name": "m", "severity": "low", "title": "t",
                           "description": "d", "request_id": "r"})
    assert f.timestamp is not None


def test_dict_to_finding_bad_timestamp():
    f = _dict_to_finding({"module_name": "m", "severity": "low", "title": "t",
                           "description": "d", "request_id": "r",
                           "timestamp": "not-a-date"})
    assert f.timestamp is not None


# ─────────────────────────────────────────────────────────────────
#  Severity filtering
# ─────────────────────────────────────────────────────────────────

async def test_severity_filter_blocks_below_threshold():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="medium", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    await store.publish("findings", _finding(severity="low"))
    await store.publish("findings", _finding(severity="info"))
    assert reporter._reported_count == 0


async def test_severity_filter_passes_at_threshold():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="medium", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    await store.publish("findings", _finding(severity="medium"))
    assert reporter._reported_count == 1


async def test_severity_filter_passes_above_threshold():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="low", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    for sev in ("low", "medium", "high", "critical"):
        await store.publish("findings", _finding(severity=sev, title=f"Finding {sev}"))
    assert reporter._reported_count == 4


async def test_severity_filter_info_passes_all():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    for sev in SEVERITY_ORDER:
        await store.publish("findings", _finding(severity=sev, title=f"Finding {sev}"))
    assert reporter._reported_count == len(SEVERITY_ORDER)


def test_invalid_min_severity_raises():
    store = FakeStore()
    with pytest.raises(ValueError, match="Invalid min_severity"):
        FindingReporter(store, min_severity="urgent")


# ─────────────────────────────────────────────────────────────────
#  JSON output
# ─────────────────────────────────────────────────────────────────

async def test_json_output_written():
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tmp:
        path = Path(tmp.name)

    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=path, csv_path=None)
    await reporter.start()
    await store.publish("findings", _finding(severity="high", title="SQL injection"))
    await reporter.stop()

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["title"] == "SQL injection"
    assert record["severity"] == "high"
    assert "timestamp" in record
    path.unlink()


async def test_json_output_appends():
    with tempfile.NamedTemporaryFile(suffix=".ndjson", delete=False) as tmp:
        path = Path(tmp.name)

    store = FakeStore()
    for _ in range(3):
        reporter = FindingReporter(store, min_severity="info", console=False,
                                    json_path=path, csv_path=None)
        await reporter.start()
        await store.publish("findings", _finding())
        await reporter.stop()

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 3
    path.unlink()


# ─────────────────────────────────────────────────────────────────
#  CSV output
# ─────────────────────────────────────────────────────────────────

async def test_csv_output_written():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = Path(tmp.name)
    path.unlink()  # ensure fresh file so header is written

    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=None, csv_path=path)
    await reporter.start()
    await store.publish("findings", _finding(severity="medium", title="Missing CSP"))
    await reporter.stop()

    rows = list(csv.DictReader(path.open()))
    assert len(rows) == 1
    assert rows[0]["title"] == "Missing CSP"
    assert rows[0]["severity"] == "medium"
    path.unlink()


async def test_csv_header_written_once():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = Path(tmp.name)
    path.unlink()

    store = FakeStore()
    for _ in range(2):
        reporter = FindingReporter(store, min_severity="info", console=False,
                                    json_path=None, csv_path=path)
        await reporter.start()
        await store.publish("findings", _finding())
        await reporter.stop()

    rows = list(csv.DictReader(path.open()))
    assert len(rows) == 2
    # header appears only once — DictReader consumes it
    raw_lines = path.read_text().splitlines()
    header_lines = [l for l in raw_lines if l.startswith("timestamp")]
    assert len(header_lines) == 1
    path.unlink()


async def test_csv_evidence_serialised_as_json():
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        path = Path(tmp.name)
    path.unlink()

    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=None, csv_path=path)
    await reporter.start()
    f = _finding()
    f.evidence["url"] = "https://example.com/api"
    await store.publish("findings", f)
    await reporter.stop()

    rows = list(csv.DictReader(path.open()))
    evidence = json.loads(rows[0]["evidence"])
    assert evidence["url"] == "https://example.com/api"
    path.unlink()


# ─────────────────────────────────────────────────────────────────
#  Dict payload (from store re-publish)
# ─────────────────────────────────────────────────────────────────

async def test_dict_payload_accepted():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    await store.publish("findings", {
        "module_name": "passive_scanner",
        "severity": "medium",
        "title": "Missing HSTS",
        "description": "No HSTS header",
        "request_id": "abc123",
        "evidence": {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    assert reporter._reported_count == 1


# ─────────────────────────────────────────────────────────────────
#  Lifecycle
# ─────────────────────────────────────────────────────────────────

async def test_healthcheck():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    await store.publish("findings", _finding())
    health = await reporter.healthcheck()
    assert health.status == "ok"
    assert health.module_name == "finding_reporter"
    assert "1 finding" in health.detail


async def test_stop_resets_files():
    store = FakeStore()
    reporter = FindingReporter(store, min_severity="info", console=False,
                                json_path=None, csv_path=None)
    await reporter.start()
    await reporter.stop()
    assert reporter._json_file is None
    assert reporter._csv_file is None