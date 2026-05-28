# PROJECT_BRAIN — API Scan Engine
_Auto-generated: 2026-05-28 16:10 UTC_
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
    generator.py        # regenerates this file from live store on every shutdown
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
- [x] BrainGenerator — implemented and wired to runner.py shutdown
- [x] Journal — wired to runner.py start/stop events
- [x] mitmproxy integration — proxy/core/proxy.py + runner.py complete
- [x] 16 tests passing (pytest tests/ -v), 0 warnings
- [x] VirtualBox VM deployment — 192.168.50.221, DHCP reserved lease
- [x] CA cert distributed — TLS interception working subnet-wide
- [x] store.open() fix — endpoint_mapper no longer raises on live traffic
- [ ] PassiveScanner module — not started
- [ ] FindingReporter module — not started

## Discovered endpoints
_Run `python -m proxy.brain.generator --db scan.db` to populate from live data._

## Findings
_None yet._

## Last session journal
- 2026-05-27 11:32  [test]    session-001 skeleton committed
- 2026-05-28 09:34  [proxy]   session-002 mitmproxy integration committed (48915b3)
- 2026-05-28 ~10:00 [fix]     session-002b import path + asyncio_mode=auto
- 2026-05-28 ~10:30 [fix]     session-002c utcnow() → datetime.now(timezone.utc)
- 2026-05-28 15:49  [fix]     session-003 store.open() missing — endpoint_mapper NoneType error
- 2026-05-28 16:10  [infra]   session-003 BrainGenerator + Journal wired to runner shutdown

## Next session goal
- Implement PassiveScanner module (proxy/modules/passive_scanner.py)
  Detections: missing security headers (CSP, HSTS, X-Frame-Options),
  sensitive data in URLs (tokens/passwords in query strings),
  unauthenticated endpoints on sensitive paths
- Wire PassiveScanner into runner.py alongside EndpointMapper
- Add tests/test_passive_scanner.py
