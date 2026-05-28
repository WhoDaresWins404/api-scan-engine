# PROJECT_BRAIN — API Scan Engine
_Auto-generated: 2026-05-28 21:00 UTC_
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
    runner.py           # CLI launcher — wires store, journal, generator, brain_loop
  modules/
    endpoint_mapper.py  # discovers unique host+path+method combinations (v0.2.0)
  brain/
    generator.py        # generate() + brain_loop() — every 10 min + on shutdown
    journal.py          # append-only JSONL event log (scan.journal.jsonl)
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
patches/                # numbered .patch files from each session
tests/
  test_proxy.py         # 16 tests, all passing, 0 warnings

## Current state
- [x] Project skeleton — interfaces, store, journal, apply helper
- [x] SQLiteStore — write, read, query, pub/sub verified
- [x] EndpointMapper module — verified (v0.2.0, emits Finding on discovery)
- [x] BrainGenerator — generate() + brain_loop() wired to runner.py
- [x] Journal — full JSONL implementation, wired to runner start/stop
- [x] mitmproxy integration — ScanAddon + runner.py complete
- [x] 16 tests passing (pytest tests/ -v), 0 warnings
- [x] VirtualBox VM — 192.168.50.221, DHCP reserved, VS Code Remote-SSH
- [x] CA cert distributed — TLS interception working subnet-wide
- [x] Proxy confirmed running — 0.0.0.0:8080, EndpointMapper active
- [x] PROJECT_BRAIN.md auto-regenerates every 10 min + on shutdown
- [ ] PassiveScanner module — not started
- [ ] FindingReporter module — not started

## Hard-won operational notes
- Always run `fix-perms` after any manual file copy to the VM:
  `sudo chown -R lab:lab ~/api-scan-engine && find ~/api-scan-engine -name "*.py" -exec chmod 644 {} \;`
- Prefer `git checkout HEAD -- <file>` over SCP to restore files — avoids
  null-byte corruption and permission issues from Windows transfers
- `git apply` fails silently when patch context doesn't match VM file state;
  for wholesale file replacements, copy the file directly then `git add + commit`
- Proxy start command: `python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db`
- Manual brain regeneration: `python -m proxy.brain.generator --db scan.db`

## Discovered endpoints
_Populated automatically by BrainGenerator on next proxy shutdown._

## Findings
_None yet._

## Last session journal
- 2026-05-27 11:32  [test]    session-001 skeleton committed
- 2026-05-28 09:34  [proxy]   session-002 mitmproxy integration + 16 tests green
- 2026-05-28 ~10:00 [fix]     session-002b import path + asyncio_mode=auto
- 2026-05-28 ~10:30 [fix]     session-002c utcnow() → datetime.now(timezone.utc)
- 2026-05-28 15:49  [fix]     session-003 store.open() missing — NoneType error
- 2026-05-28 16:10  [infra]   session-003 BrainGenerator + Journal wired to runner
- 2026-05-28 ~17:00 [infra]   Migrated from WSL to VirtualBox VM (192.168.50.221)
- 2026-05-28 ~17:30 [fix]     VS Code Remote-SSH configured for VM
- 2026-05-28 ~18:00 [fix]     Proxy binding 0.0.0.0 — subnet access working
- 2026-05-28 ~18:30 [fix]     CA cert deployed — TLS interception working
- 2026-05-28 ~19:00 [fix]     store.open() call added to runner.py
- 2026-05-28 ~20:00 [fix]     journal.py + generator.py full implementations
                              delivered to VM — null bytes + perms resolved
- 2026-05-28 21:00  [commit]  session-003 closed — proxy stable and running

## Next session goal
- Implement PassiveScanner module (proxy/modules/passive_scanner.py)
  Detections:
    • Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
    • Sensitive data in URLs (tokens, passwords, API keys in query strings)
    • Unauthenticated endpoints (sensitive paths lacking Authorization header)
- Wire PassiveScanner into runner.py alongside EndpointMapper
- Add tests/test_passive_scanner.py
- Run live smoke test: confirm both modules capture real browser traffic
  and findings appear in scan.db
