"""
proxy/brain/generator.py
────────────────────────────────────────────────────────────────────
Reads the live SQLiteStore and rewrites PROJECT_BRAIN.md.

Triggered three ways:
  1. Automatically every BRAIN_INTERVAL seconds while proxy runs
     (background asyncio task started by runner.py)
  2. On clean proxy shutdown (runner.py finally block)
  3. Manually: python -m proxy.brain.generator --db scan.db
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("scan.brain")

BRAIN_INTERVAL = 600        # regenerate every 10 minutes
BRAIN_PATH = Path(__file__).parent.parent.parent / "PROJECT_BRAIN.md"
STATUS_PATH = Path(__file__).parent.parent.parent / "SCAN_STATUS.md"

BRAIN_TEMPLATE = """# PROJECT_BRAIN — API Scan Engine
_Last updated: {generated_at}_
_Paste this file at the start of every new session._

## Architecture (immutable decisions)
- Proxy core: mitmproxy (Phase 1) → asyncio+httpx (Phase 3)
- Module model: in-process, IModule interface enforced
- Store: SQLite (Phase 1) → PostgreSQL (Phase 2), IStore abstraction
- Protocols: HTTP/HTTPS (Phase 1) → GraphQL/WS (Phase 2) → gRPC (Phase 3)
- Delta patch workflow: git apply / python apply.py for all code changes
- Lab environment: VirtualBox Ubuntu VM (192.168.50.221), VS Code Remote-SSH

## Core interfaces (proxy/core/interfaces.py)
- ProxyRequest: id, timestamp, method, url, headers, body
- ProxyResponse: request_id, timestamp, status_code, headers, body
- ModuleHealth: module_name, version, status, last_seen, detail
- Finding: module_name, severity, title, description, request_id, evidence, timestamp
- IModule: name, version, on_request(), on_response(), healthcheck()
- IStore: write(), read(), query(), subscribe(), publish()

## File structure
proxy/
  core/
    interfaces.py       # IModule, IStore, shared dataclasses
    store.py            # SQLiteStore — concrete IStore implementation
    proxy.py            # ScanAddon (mitmproxy addon)
    runner.py           # CLI launcher — wires store, journal, generator, brain_loop
  modules/
    endpoint_mapper.py  # discovers unique host+path+method combinations (v0.2.0)
    passive_scanner.py  # passive security checks (v0.2.0)
  brain/
    generator.py        # writes PROJECT_BRAIN.md (session doc) + SCAN_STATUS.md (traffic data)
    journal.py          # append-only JSONL event log (scan.journal.jsonl)
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
patches/                # numbered .patch files from each session
tests/
  test_proxy.py         # 16 tests — ScanAddon pipeline
  test_passive_scanner.py  # 35 tests — PassiveScanner + dedup

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, BrainGenerator, Journal
- [x] mitmproxy integration — ScanAddon + runner.py
- [x] PassiveScanner v0.2.0 — 5 detection categories, 24h dedup
- [x] Clean proxy shutdown — CancelledError handled, no traceback
- [x] 51 tests passing, 0 warnings
- [x] VirtualBox VM — 192.168.50.221, DHCP reserved, VS Code Remote-SSH
- [x] CA cert deployed — TLS interception working subnet-wide
- [ ] FindingReporter module — not started
- [ ] SQLiteStore vacuum — not started

## Traffic summary (see SCAN_STATUS.md for full details)
- Endpoints discovered: {endpoint_count}
- Findings logged:      {finding_count}

## Hard-won operational notes
- fix-perms after any manual file copy:
  sudo chown -R lab:lab ~/api-scan-engine && find ~/api-scan-engine -name "*.py" -exec chmod 644 {{}} \\\\;
- Prefer git checkout HEAD -- <file> over SCP to restore files
- After any patch touching dataclass constructors verify all required fields:
  grep "ProxyRequest|ProxyResponse" proxy/core/proxy.py
- Proxy start: python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db
- Manual regen: python -m proxy.brain.generator --db scan.db
- PROJECT_BRAIN.md = lean session handoff (~6KB). SCAN_STATUS.md = live traffic data.

## Last journal entries
{journal_section}

## Next session goal
- FindingReporter module (proxy/modules/finding_reporter.py)
  Output: console (coloured), JSON file, CSV file; configurable severity threshold
- SQLiteStore vacuum(max_age_days) — weekly background task to bound scan.db size
- Wire FindingReporter into runner.py; add tests/test_finding_reporter.py
"""

STATUS_TEMPLATE = """# SCAN_STATUS — API Scan Engine
_Auto-generated: {generated_at} — do NOT paste into chat sessions_
_For session handoff use PROJECT_BRAIN.md instead_

## Summary
- Endpoints discovered: {endpoint_count}
- Findings logged:      {finding_count}

## Discovered endpoints ({endpoint_count} total)
{endpoints_section}

## Findings ({finding_count} total)
{findings_section}
"""


async def generate(db_path: str) -> None:
    """Read store + journal, write PROJECT_BRAIN.md."""
    from proxy.core.store import SQLiteStore
    from proxy.brain.journal import Journal

    store = SQLiteStore(db_path)
    store.open()
    try:
        endpoints = await store.query("endpoints")
        findings  = await store.query("findings")
    finally:
        store.close()

    journal = Journal(db_path)
    entries = journal.tail(20)

    # ── endpoints section ─────────────────────────────────────────
    if endpoints:
        lines = []
        for ep in sorted(endpoints, key=lambda e: (e.get("host", ""), e.get("path", ""))):
            status = ep.get("last_status") or "—"
            lines.append(
                f"- {ep.get('method', '?')} "
                f"{ep.get('scheme', 'https')}://{ep.get('host', '?')}{ep.get('path', '/')} "
                f"  [last status: {status}]"
            )
        endpoints_section = "\n".join(lines)
    else:
        endpoints_section = "_None yet._"

    # ── findings section ──────────────────────────────────────────
    if findings:
        by_sev: dict[str, list] = {}
        for f in findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)
        lines = []
        for sev in ("critical", "high", "medium", "low", "info"):
            for f in by_sev.get(sev, []):
                lines.append(
                    f"- [{sev.upper()}] {f.get('title', '')} "
                    f"— {f.get('module_name', '')} "
                    f"(request {f.get('request_id', '?')[:8]}…)"
                )
        findings_section = "\n".join(lines)
    else:
        findings_section = "_None yet._"

    # ── journal section ───────────────────────────────────────────
    if entries:
        journal_section = "\n".join(
            f"- {e['timestamp']}  [{e['type']}]  {e['detail']}"
            for e in entries
        )
    else:
        journal_section = "_No entries yet._"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # PROJECT_BRAIN.md — lean session handoff doc (counts only, no raw lists)
    brain_content = BRAIN_TEMPLATE.format(
        generated_at   = now_str,
        endpoint_count = len(endpoints),
        finding_count  = len(findings),
        journal_section = journal_section,
    )
    BRAIN_PATH.write_text(brain_content)

    # SCAN_STATUS.md — full traffic data (never paste into chat)
    status_content = STATUS_TEMPLATE.format(
        generated_at      = now_str,
        endpoint_count    = len(endpoints),
        finding_count     = len(findings),
        endpoints_section = endpoints_section,
        findings_section  = findings_section,
    )
    STATUS_PATH.write_text(status_content)

    log.info(
        "PROJECT_BRAIN.md + SCAN_STATUS.md updated  (%d endpoints, %d findings)",
        len(endpoints), len(findings),
    )


async def brain_loop(db_path: str) -> None:
    """Background task: regenerate PROJECT_BRAIN.md every BRAIN_INTERVAL seconds."""
    while True:
        await asyncio.sleep(BRAIN_INTERVAL)
        try:
            await generate(db_path)
        except Exception as exc:
            log.error("BrainGenerator failed: %s", exc)


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level="INFO", format="%(message)s")
    p = argparse.ArgumentParser(description="Regenerate PROJECT_BRAIN.md from live store")
    p.add_argument("--db", default="scan.db", help="Path to SQLite database")
    args = p.parse_args()
    asyncio.run(generate(args.db))
