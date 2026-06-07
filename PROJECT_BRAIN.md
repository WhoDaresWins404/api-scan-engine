# PROJECT_BRAIN — API Scan Engine
_Last updated: 2026-06-07 13:18 UTC_
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
- Endpoints discovered: 1956
- Findings logged:      2641

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
- 2026-05-28 21:31  [proxy]  started on 0.0.0.0:8080
- 2026-05-28 21:32  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-28 21:32  [proxy]  started on 0.0.0.0:8080
- 2026-05-28 21:33  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 08:28  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 08:51  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 08:58  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 09:08  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 09:26  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 09:27  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-30 10:37  [proxy]  started on 0.0.0.0:8080
- 2026-05-30 10:37  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-06-01 11:16  [proxy]  started on 0.0.0.0:8080
- 2026-06-01 11:16  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-06-01 11:18  [proxy]  started on 0.0.0.0:8080
- 2026-06-01 11:18  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-06-01 11:26  [proxy]  started on 0.0.0.0:8080
- 2026-06-07 13:06  [proxy]  started on 0.0.0.0:8080
- 2026-06-07 13:18  [proxy]  stopped — regenerating PROJECT_BRAIN.md

## Next session goal
- PassiveScanner host blocklist -- skip CDN/analytics/ad hosts to cut false positives
- Review findings.csv quality after live browsing session
- Consider GraphQL/WebSocket detection (Phase 2 prep)
