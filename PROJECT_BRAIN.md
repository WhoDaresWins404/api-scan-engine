# PROJECT_BRAIN — API Scan Engine
_Session 012 start — 2026-06-15 UTC_
_Paste this file at the start of every new session._

## Architecture (immutable decisions)
- Proxy core: mitmproxy (Phase 1) -> asyncio+httpx (Phase 3)
- Module model: in-process, IModule interface enforced
- Store: SQLite (Phase 1) -> PostgreSQL (Phase 2), IStore abstraction
- Protocols: HTTP/HTTPS (Phase 1) -> GraphQL/WS (Phase 2) -> gRPC (Phase 3)
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
    runner.py           # CLI launcher -- all 5 modules + vacuum + brain_loop
  modules/
    endpoint_mapper.py  # host+path+method discovery, asset filtering (v0.3.0)
    passive_scanner.py  # passive security checks, host blocklist (v0.3.0)
    graphql_detector.py # GraphQL introspection/mutation/batch/error (v0.1.0)
    secret_scanner.py   # response body secret detection (v0.1.0)
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
  test_graphql_detector.py            # 26 tests
  test_secret_scanner.py              # 28 tests (2 fixed: GitHub/Google regex lengths)
  # total: 174 tests

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, Journal, BrainGenerator
- [x] mitmproxy integration -- ScanAddon + runner.py
- [x] PassiveScanner v0.3.0 -- host blocklist, write-methods-only auth check
- [x] GraphQLDetector v0.1.0 -- introspection/mutation/batch/error detection
- [x] SecretScanner v0.1.0 -- AWS/GitHub/Stripe/Slack/JWT/high-entropy detection
- [x] FindingReporter v0.2.0 -- output dedup, console/JSON/CSV
- [x] SQLiteStore -- vacuum, deduplicate, stats, deterministic IDs, CLI
- [x] EndpointMapper v0.3.0 -- static asset filtering
- [x] generator.py BRAIN_TEMPLATE -- updated to reflect all sessions to date
- [x] Clean proxy shutdown -- CancelledError handled, no traceback
- [x] 174 tests passing, 0 warnings
- [x] GitHub workflow -- credentials stored, no password prompts
- [x] CA cert deployed -- TLS interception working subnet-wide
- [x] scan.db deduped -- 22070 -> 2559 records (88% reduction)

## Module summary
| Module          | Version | Role                                              |
|-----------------|---------|---------------------------------------------------|
| EndpointMapper  | 0.3.0   | Discover API endpoints, skip static assets        |
| PassiveScanner  | 0.3.0   | Security checks, host blocklist, write-method auth|
| GraphQLDetector | 0.1.0   | GraphQL introspection/mutation/batch/error checks |
| SecretScanner   | 0.1.0   | Detect secrets in response bodies                 |
| FindingReporter | 0.2.0   | Real-time output, session dedup, console/JSON/CSV |

## DB maintenance commands
  python -m proxy.core.store --db scan.db stats
  python -m proxy.core.store --db scan.db dedup
  python -m proxy.core.store --db scan.db vacuum --days 30

## Traffic summary (see SCAN_STATUS.md for full details)
- Endpoints: 1726 (302 CDN/analytics hidden)
- Findings:  653 unique

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
- generator.py BRAIN_TEMPLATE needs manual update after major state changes
  (traffic counts + journal update automatically; module list/checklist do not)
- Regex test values must match pattern length exactly -- GitHub ghp_ needs 36
  chars after prefix, Google AIza needs 35 chars after prefix

## Last journal entries
- 2026-06-08 07:25  [proxy]  started on 0.0.0.0:8080
- 2026-06-08 11:33  [proxy]  stopped -- regenerating PROJECT_BRAIN.md
- 2026-06-10 11:47  [proxy]  started on 0.0.0.0:8080
- 2026-06-10 11:48  [proxy]  stopped -- regenerating PROJECT_BRAIN.md
- 2026-06-10 ~12:00 [feat]   session-010 GraphQLDetector v0.1.0 -- 146 tests
- 2026-06-15 09:39  [proxy]  started on 0.0.0.0:8080
- 2026-06-15 09:39  [proxy]  stopped -- regenerating PROJECT_BRAIN.md
- 2026-06-15 ~10:00 [feat]   session-011 SecretScanner v0.1.0 + generator fix
- 2026-06-15 ~10:30 [fix]    session-011b GitHub/Google regex test value lengths
- 2026-06-15 ~10:30 [close]  174 passed 0 warnings -- session-011 closed

## Next session goal
1. WebSocket detection (Phase 2 continuation)
   - Detect WS/WSS upgrades (101 Switching Protocols)
   - Log WebSocket endpoints as discoveries
   - Flag unauthenticated WebSocket connections
2. Review SecretScanner findings quality after live browsing session
   - Check false positive rate on high-entropy detection
   - Tune MIN_ENTROPY_LENGTH or HIGH_ENTROPY_THRESHOLD if needed
3. Consider: PostgreSQL store migration prep (Phase 2)
   - IStore abstraction already in place -- just needs AsyncpgStore implementation
