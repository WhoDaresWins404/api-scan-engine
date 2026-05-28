# PROJECT_BRAIN — API Scan Engine
_Auto-generated: 2026-05-28 — Session 002_
_Paste this file at the start of every new session._

## Architecture (immutable decisions)
- Proxy core: mitmproxy (Phase 1) → asyncio+httpx (Phase 3)
- Module model: in-process, IModule interface enforced
- Store: SQLite (Phase 1) → PostgreSQL (Phase 2), IStore abstraction
- Protocols: HTTP/HTTPS (Phase 1) → GraphQL/WS (Phase 2) → gRPC (Phase 3)
- Delta patch workflow: git apply / python apply.py for all code changes
- Lab environment: WSL2/Ubuntu inside Windows, VS Code WSL extension

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
    proxy.py            # ★ NEW — ScanAddon (mitmproxy addon)
    runner.py           # ★ NEW — CLI launcher (python -m proxy.core.runner)
  modules/
    endpoint_mapper.py  # discovers unique host+path+method combinations (v0.2.0)
  brain/
    generator.py        # generates this file from live store
    journal.py          # append-only session event log
apply.py                # patch helper (git apply wrapper)
patches/                # numbered .patch files from each session
  0001-session-002-mitmproxy-integration-tests.patch
tests/
  test_proxy.py         # ★ NEW — 15 tests for ScanAddon pipeline

## Key design decisions made this session
- ScanAddon stores ProxyRequest in `flow.metadata["scan_request"]` so the
  response hook can retrieve the exact same object without re-parsing
- Module calls are wrapped in `_timed()` — a per-call asyncio.wait_for so one
  slow/broken module never blocks the proxy
- `asyncio.gather(*tasks, return_exceptions=True)` used so all modules run
  concurrently; exceptions are caught and logged, not propagated
- Health sweep runs as a background asyncio Task every 60 s, started in
  `ScanAddon.running()` (mitmproxy lifecycle hook)
- runner.py is both a CLI entry point (`python -m proxy.core.runner`) and an
  importable async function (`await run_proxy(...)`) for test/embed use

## How to run the proxy (WSL2)
```bash
# Install (once)
pip install mitmproxy pytest pytest-asyncio

# Run tests
cd /path/to/project
pytest tests/test_proxy.py -v

# Start proxy (port 8080, SQLite at scan.db)
python -m proxy.core.runner --port 8080 --db scan.db --log-level DEBUG

# Configure browser to use 127.0.0.1:8080 as HTTP proxy
# Trust mitmproxy CA: browse to http://mitm.it and install cert
```

## Current state
- [x] Project skeleton — interfaces, store, journal, apply helper
- [x] SQLiteStore — write, read, query, pub/sub verified
- [x] EndpointMapper module — verified (v0.2.0, now emits Finding on discovery)
- [x] BrainGenerator — auto-generates this file
- [x] mitmproxy integration — proxy/core/proxy.py + runner.py complete
- [x] 15 tests covering: request/response hooks, slow/broken module tolerance,
      findings persistence, pub/sub, EndpointMapper deduplication + method splitting
- [ ] PassiveScanner module — not started
- [ ] FindingReporter module — not started
- [ ] Live browser smoke test — needs real WSL2 environment

## Discovered endpoints
- POST https://api.example.com/users  [None]
- GET https://api.example.com/users  [200]

## Findings
_None yet (from real traffic)._

## Last session journal
- 2026-05-27 11:32  [test]  session-001 skeleton committed
- 2026-05-28 09:34  [proxy] session-002 mitmproxy integration committed (48915b3)
  - proxy/core/proxy.py     ScanAddon — mitmproxy addon
  - proxy/core/runner.py    CLI + library launcher
  - proxy/modules/endpoint_mapper.py  v0.2.0 (emits Findings)
  - tests/test_proxy.py     15 tests, all parse-verified

## Next session goal
1. **Live smoke test** — start the proxy in WSL2, point a browser at it,
   confirm EndpointMapper finds real endpoints and writes them to scan.db
   (`SELECT * FROM endpoints;` in sqlite3).
2. **PassiveScanner module** (proxy/modules/passive_scanner.py) — detect:
   - Missing security headers (CSP, HSTS, X-Frame-Options)
   - Unauthenticated endpoints (no Authorization header on sensitive paths)
   - Sensitive data in URLs (tokens, passwords in query strings)
3. Wire PassiveScanner into runner.py alongside EndpointMapper.
