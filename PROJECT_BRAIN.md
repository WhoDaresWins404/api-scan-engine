# PROJECT_BRAIN — API Scan Engine
_Session 006 start — 2026-05-30 UTC_
_Paste this file at the start of every new session._

## Architecture (immutable decisions)
- Proxy core: mitmproxy (Phase 1) → asyncio+httpx (Phase 3)
- Module model: in-process, IModule interface enforced
- Store: SQLite (Phase 1) → PostgreSQL (Phase 2), IStore abstraction
- Protocols: HTTP/HTTPS (Phase 1) → GraphQL/WS (Phase 2) → gRPC (Phase 3)
- Workflow: PC1 (Windows/VS Code) → GitHub → PC2 (Ubuntu VM git pull)
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
    store.py            # SQLiteStore — concrete IStore implementation
    proxy.py            # ScanAddon (mitmproxy addon)
    runner.py           # CLI launcher — wires store, journal, generator, brain_loop
  modules/
    endpoint_mapper.py  # discovers unique host+path+method (v0.2.0)
    passive_scanner.py  # passive security checks (v0.2.0)
    finding_reporter.py # real-time finding output — console/JSON/CSV (v0.1.0)
  brain/
    generator.py        # PROJECT_BRAIN.md (lean) + SCAN_STATUS.md (traffic data)
    journal.py          # append-only JSONL event log (scan.journal.jsonl)
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
.gitignore              # PROJECT_BRAIN.md, SCAN_STATUS.md, scan.db, findings.* excluded
tests/
  test_proxy.py              # 16 tests — ScanAddon pipeline
  test_passive_scanner.py    # 35 tests — PassiveScanner + dedup
  test_finding_reporter.py   # 16 tests — FindingReporter

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, Journal
- [x] mitmproxy integration — ScanAddon + runner.py
- [x] PassiveScanner v0.2.0 — 5 detection categories, 24h dedup
- [x] BrainGenerator — lean PROJECT_BRAIN.md + SCAN_STATUS.md split
- [x] Clean proxy shutdown — CancelledError handled, no traceback
- [x] FindingReporter v0.1.0 — console (ANSI colour), JSON, CSV, severity filter
- [x] 67 tests passing, 0 warnings
- [x] GitHub workflow — PC1 commits/pushes, PC2 git pull, credentials stored
- [x] PROJECT_BRAIN.md in .gitignore — no more merge conflicts on git pull
- [x] CA cert deployed — TLS interception working subnet-wide
- [x] Proxy live — 625 endpoints, 822 findings captured
- [ ] SQLiteStore vacuum(max_age_days) — not started
- [ ] FindingReporter not yet wired as IModule in runner.py modules list

## FindingReporter usage (v0.1.0)
- Subscribes to store pub/sub — real-time output as traffic flows
- Console: ANSI colour-coded by severity (bold red=high, yellow=medium, blue=low)
- JSON: append-only findings.ndjson (one record per line)
- CSV: append-only findings.csv (opens in Excel)
- CLI flags: --min-severity (info/low/medium/high/critical), --no-console,
             --report-json <path>, --report-csv <path>
- Recommended start: python -m proxy.core.runner --host 0.0.0.0 --port 8080
                       --db scan.db --min-severity medium

## Hard-won operational notes
- PROJECT_BRAIN.md is .gitignored — generated locally, never tracked in git
- SCAN_STATUS.md, findings.ndjson, findings.csv also .gitignored
- Proxy start: python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db
- Manual brain regen: python -m proxy.brain.generator --db scan.db
- After git pull: always run pytest tests/ -v before restarting proxy
- GitHub credentials: stored via git config --global credential.helper store
- fix-perms (legacy, no longer needed with GitHub workflow):
  sudo chown -R lab:lab ~/api-scan-engine && find ~/api-scan-engine -name "*.py" -exec chmod 644 {} \;

## Last journal entries
- 2026-05-29 08:28  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 09:08  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 09:26  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 09:27  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-30 10:37  [proxy]  started on 0.0.0.0:8080
- 2026-05-30 10:37  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-30 ~11:00 [feat]   session-005 FindingReporter v0.1.0 — 67 tests green
- 2026-05-30 ~11:00 [fix]    PROJECT_BRAIN.md added to .gitignore — no more pull conflicts
- 2026-05-30 ~11:00 [fix]    GitHub credentials stored permanently on PC1 and PC2

## Next session goal
1. SQLiteStore vacuum — add vacuum(max_age_days=30) method to store.py,
   call weekly from a background task in runner.py to keep scan.db bounded
2. Wire FindingReporter as a proper IModule in runner.py modules list
   (currently started separately — should be part of the module pipeline)
3. Consider: domain/path filtering in EndpointMapper to exclude noise
   (static assets — .js, .css, .woff, images — inflate endpoint count)
4. Run proxy with --min-severity medium and verify coloured console output