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

TEMPLATE = """\
# PROJECT_BRAIN — API Scan Engine
_Auto-generated: {generated_at}_
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
    runner.py           # CLI launcher — wires store, journal, generator
  modules/
    endpoint_mapper.py  # discovers unique host+path+method combinations (v0.2.0)
  brain/
    generator.py        # regenerates this file — every 10 min + on shutdown
    journal.py          # append-only session event log (scan.journal.jsonl)
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
patches/                # numbered .patch files from each session
tests/
  test_proxy.py         # 16 tests, all passing

## Current state
- [x] Project skeleton — interfaces, store, journal, apply helper
- [x] SQLiteStore — write, read, query, pub/sub verified
- [x] EndpointMapper module — verified (v0.2.0, emits Finding on discovery)
- [x] BrainGenerator — every 10 min + on shutdown, wired to runner.py
- [x] Journal — wired to runner.py start/stop events
- [x] mitmproxy integration — proxy/core/proxy.py + runner.py complete
- [x] 16 tests passing (pytest tests/ -v), 0 warnings
- [x] VirtualBox VM deployment — 192.168.50.221, DHCP reserved lease
- [x] CA cert distributed — TLS interception working subnet-wide
- [ ] PassiveScanner module — not started
- [ ] FindingReporter module — not started

## Discovered endpoints ({endpoint_count} total)
{endpoints_section}

## Findings ({finding_count} total)
{findings_section}

## Last session journal
{journal_section}

## Next session goal
- Implement PassiveScanner module (proxy/modules/passive_scanner.py)
  Detections: missing security headers (CSP, HSTS, X-Frame-Options),
  sensitive data in URLs (tokens/passwords in query strings),
  unauthenticated endpoints on sensitive paths
- Wire PassiveScanner into runner.py alongside EndpointMapper
- Add tests/test_passive_scanner.py
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

    content = TEMPLATE.format(
        generated_at      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        endpoint_count    = len(endpoints),
        finding_count     = len(findings),
        endpoints_section = endpoints_section,
        findings_section  = findings_section,
        journal_section   = journal_section,
    )

    BRAIN_PATH.write_text(content)
    log.info(
        "PROJECT_BRAIN.md updated  (%d endpoints, %d findings)",
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
