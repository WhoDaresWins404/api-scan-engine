# PROJECT_BRAIN — API Scan Engine
_Session 009 start — 2026-06-07 UTC_
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
    passive_scanner.py  # passive security checks, host blocklist (v0.3.0)
    finding_reporter.py # real-time console/JSON/CSV output, dedup (v0.2.0)
  brain/
    generator.py        # PROJECT_BRAIN.md (lean) + SCAN_STATUS.md (filtered)
    journal.py          # append-only JSONL event log
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
.gitignore              # PROJECT_BRAIN.md, SCAN_STATUS.md, scan.db, findings.* excluded
tests/
  test_proxy.py                       # 16 tests
  test_passive_scanner.py             # 36 tests
  test_passive_scanner_blocklist.py   # 18 tests
  test_finding_reporter.py            # 16 tests
  test_session006.py                  # 20 tests (vacuum, asset filter, reporter IModule)
  # total: 107 tests

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, Journal, BrainGenerator
- [x] mitmproxy integration -- ScanAddon + runner.py
- [x] PassiveScanner v0.3.0 -- host blocklist (CDN/analytics/ads), write-methods-only auth check
- [x] FindingReporter v0.2.0 -- output dedup by (title, host) per session
- [x] FindingReporter wired as IModule in runner.py modules list
- [x] SQLiteStore.vacuum(max_age_days=30) -- weekly background task
- [x] EndpointMapper v0.3.0 -- static asset filtering
- [x] generator.py -- SCAN_STATUS.md filters blocked hosts, shows noise count
- [x] Clean proxy shutdown -- CancelledError handled, no traceback
- [x] 107 tests passing, 0 warnings
- [x] GitHub workflow -- credentials stored, no password prompts
- [x] CA cert deployed -- TLS interception working subnet-wide

## Module summary
| Module          | Version | Role                                              |
|-----------------|---------|---------------------------------------------------|
| EndpointMapper  | 0.3.0   | Discover API endpoints, skip static assets        |
| PassiveScanner  | 0.3.0   | Security checks, host blocklist, write-method auth|
| FindingReporter | 0.2.0   | Real-time output, session dedup, console/JSON/CSV |

## Traffic summary (see SCAN_STATUS.md for full details)
- Endpoints discovered: 1956 (CDN/analytics filtered in SCAN_STATUS.md)
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
- Generator template in generator.py needs updating after major state changes
  (auto-generation keeps traffic data current but not the state checklist)

## Last journal entries
- 2026-06-01 11:26  [proxy]  started on 0.0.0.0:8080
- 2026-06-07 13:06  [proxy]  started on 0.0.0.0:8080
- 2026-06-07 13:18  [proxy]  stopped -- regenerating PROJECT_BRAIN.md
- 2026-06-07 ~14:00 [feat]   session-008 three quality improvements
- 2026-06-07 ~14:00 [fix]    session-008b reporter test titles uniquified
- 2026-06-07 ~14:30 [close]  107 passed 0 warnings -- session-008 closed

## Next session goal
1. GraphQL detection module (Phase 2 first step)
   - Detect POST to /graphql endpoints
   - Extract operation type (query/mutation/subscription) from request body
   - Flag introspection queries (high severity -- information disclosure)
   - Flag mutations without auth (medium severity)
2. Review findings.csv quality with the new blocklist/write-method changes
   in place -- are there still obvious false positives to address?
3. Consider: response body scanning for secrets
   (API keys, tokens in JSON response bodies)