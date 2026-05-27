# PROJECT_BRAIN — API Scan Engine
_Auto-generated: 2026-05-27 17:24 UTC_
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
    interfaces.py   # IModule, IStore, shared dataclasses
    store.py        # SQLiteStore — concrete IStore implementation
  modules/
    endpoint_mapper.py  # discovers unique host+path+method combinations
  brain/
    generator.py    # generates this file from live store
    journal.py      # append-only session event log
apply.py            # patch helper (git apply wrapper)
patches/            # numbered .patch files from each session
tests/              # test suite (pytest)

## Current state
- [x] Project skeleton — interfaces, store, journal, apply helper
- [x] SQLiteStore — write, read, query, pub/sub verified
- [x] EndpointMapper module — verified
- [x] BrainGenerator — auto-generates this file
- [ ] PassiveScanner module — not started
- [ ] mitmproxy integration (proxy core) — not started
- [ ] FindingReporter module — not started

Endpoints discovered: 2
Findings logged: 0

## Discovered endpoints
- POST https://api.example.com/users  [None]
- GET https://api.example.com/users  [200]

## Findings
_None yet._

## Last session journal
- 2026-05-27 11:32  [test]  session-001 skeleton committed

## Next session goal
_Update this section before committing at session end._