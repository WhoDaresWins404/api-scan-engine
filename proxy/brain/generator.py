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
- Workflow: PC1 (Windows/VS Code) -> GitHub -> PC2 (Ubuntu VM git pull)
- Lab environment: VirtualBox Ubuntu VM (192.168.50.221), DHCP reserved

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
    store.py            # SQLiteStore + vacuum(max_age_days)
    proxy.py            # ScanAddon (mitmproxy addon)
    runner.py           # CLI launcher -- all modules + vacuum + brain_loop
  modules/
    endpoint_mapper.py  # host+path+method discovery, asset filtering (v0.3.0)
    passive_scanner.py  # passive security checks, 24h dedup (v0.2.0)
    finding_reporter.py # real-time console/JSON/CSV output (v0.1.0)
  brain/
    generator.py        # PROJECT_BRAIN.md (lean) + SCAN_STATUS.md (traffic data)
    journal.py          # append-only JSONL event log
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
.gitignore              # PROJECT_BRAIN.md, SCAN_STATUS.md, scan.db, findings.* excluded
tests/
  test_proxy.py              # 16 tests
  test_passive_scanner.py    # 35 tests
  test_finding_reporter.py   # 16 tests
  test_session006.py         # 20 tests

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, Journal, BrainGenerator
- [x] mitmproxy integration -- ScanAddon + runner.py
- [x] PassiveScanner v0.2.0 -- 5 detection categories, 24h dedup
- [x] FindingReporter v0.1.0 -- console (ANSI colour), JSON, CSV, severity filter
- [x] FindingReporter wired as IModule in runner.py modules list
- [x] SQLiteStore.vacuum(max_age_days=30) -- weekly background task
- [x] EndpointMapper v0.3.0 -- static asset filtering (JS/CSS/images/fonts/media)
- [x] Clean proxy shutdown -- CancelledError handled, no traceback
- [x] 87 tests passing, 0 warnings
- [x] GitHub workflow -- credentials stored, no password prompts
- [x] PROJECT_BRAIN.md in .gitignore -- no merge conflicts on git pull
- [x] CA cert deployed -- TLS interception working subnet-wide

## Module summary
| Module          | Version | Role                                       |
|-----------------|---------|--------------------------------------------|
| EndpointMapper  | 0.3.0   | Discover API endpoints, skip static assets |
| PassiveScanner  | 0.2.0   | Detect security issues, 24h dedup          |
| FindingReporter | 0.1.0   | Real-time output -- console / JSON / CSV   |

## Traffic summary (see SCAN_STATUS.md for full details)
- Endpoints discovered: {endpoint_count}
- Findings logged:      {finding_count}

## Proxy start commands
  python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db
  python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db --min-severity medium
  python -m proxy.core.runner --help

## Hard-won operational notes
- PROJECT_BRAIN.md is .gitignored -- generated locally, never tracked in git
- SCAN_STATUS.md, findings.ndjson, findings.csv also .gitignored
- After git pull: always run pytest tests/ -v before restarting proxy
- Manual brain regen: python -m proxy.brain.generator --db scan.db
- GitHub credentials: git config --global credential.helper store
- SQLite VACUUM must run outside a transaction -- commit first, then
  set isolation_level=None, VACUUM, restore isolation_level=""

## Last journal entries
{journal_section}

## Next session goal
- PassiveScanner host blocklist -- skip CDN/analytics/ad hosts to cut false positives
- Review findings.csv quality after live browsing session
- Consider GraphQL/WebSocket detection (Phase 2 prep)
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