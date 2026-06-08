# PROJECT_BRAIN — API Scan Engine
_Session 010 start — 2026-06-08 UTC_
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
    store.py            # SQLiteStore + vacuum() + deduplicate() + stats() + CLI
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
  test_session006.py                  # 20 tests
  # total: 120 tests

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, Journal, BrainGenerator
- [x] mitmproxy integration -- ScanAddon + runner.py
- [x] PassiveScanner v0.3.0 -- host blocklist, write-methods-only auth check
- [x] FindingReporter v0.2.0 -- output dedup by (title, host) per session
- [x] FindingReporter wired as IModule in runner.py modules list
- [x] SQLiteStore.vacuum(max_age_days=30) -- weekly background task
- [x] SQLiteStore.deduplicate() -- content-keyed dedup, run on existing data
- [x] SQLiteStore._content_id() -- deterministic IDs prevent future duplicates
- [x] SQLiteStore.stats() + CLI -- python -m proxy.core.store --db scan.db stats|dedup|vacuum
- [x] EndpointMapper v0.3.0 -- static asset filtering
- [x] generator.py -- SCAN_STATUS.md filters blocked hosts, shows noise count
- [x] Clean proxy shutdown -- CancelledError handled, no traceback
- [x] 120 tests passing, 0 warnings
- [x] GitHub workflow -- credentials stored, no password prompts
- [x] CA cert deployed -- TLS interception working subnet-wide
- [x] scan.db deduped -- 22070 -> 2559 records (88% reduction), now 2.8MB

## Module summary
| Module          | Version | Role                                              |
|-----------------|---------|---------------------------------------------------|
| EndpointMapper  | 0.3.0   | Discover API endpoints, skip static assets        |
| PassiveScanner  | 0.3.0   | Security checks, host blocklist, write-method auth|
| FindingReporter | 0.2.0   | Real-time output, session dedup, console/JSON/CSV |

## DB maintenance commands
  python -m proxy.core.store --db scan.db stats          # show record counts
  python -m proxy.core.store --db scan.db dedup          # remove duplicates + VACUUM
  python -m proxy.core.store --db scan.db vacuum --days 30  # delete old records

## Traffic summary (post-dedup, see SCAN_STATUS.md for full details)
- Endpoints: 1972 (38 duplicates removed)
- Findings:  584 unique (2194 duplicates removed)
- Health:    3 (17279 duplicates removed)

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
- Health records were the biggest source of DB bloat (17k duplicates) --
  now prevented by deterministic _content_id() on all writes
- Generator template in generator.py needs manual update after major state
  changes (auto-generation keeps traffic counts current, not the checklist)

## Last journal entries
- 2026-06-07 13:06  [proxy]  started on 0.0.0.0:8080
- 2026-06-07 13:18  [proxy]  stopped -- regenerating PROJECT_BRAIN.md
- 2026-06-07 ~14:00 [feat]   session-008 three quality improvements
- 2026-06-07 ~14:30 [close]  107 passed 0 warnings -- session-008 closed
- 2026-06-08 ~09:00 [feat]   session-009 store dedup + stats + CLI
- 2026-06-08 ~09:30 [maint]  dedup run: 22070 -> 2559 records (88% reduction)
- 2026-06-08 ~09:30 [close]  120 passed 0 warnings -- session-009 closed

## Next session goal
1. GraphQL detection module (Phase 2 first step)
   - Detect POST to /graphql endpoints
   - Extract operation type (query/mutation/subscription) from body
   - Flag introspection queries (high -- information disclosure)
   - Flag mutations without auth (medium)
   - Wire into runner.py; add tests/test_graphql_detector.py
2. Update generator.py BRAIN_TEMPLATE to reflect session-009 state
3. Consider: response body scanning for secrets in JSON responses