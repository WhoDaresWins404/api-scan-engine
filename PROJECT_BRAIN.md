# PROJECT_BRAIN — API Scan Engine
_Session 005 start — 2026-05-30 UTC_
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
    passive_scanner.py  # passive security checks (v0.2.0) — 5 detection categories
  brain/
    generator.py        # writes PROJECT_BRAIN.md (lean) + SCAN_STATUS.md (traffic data)
    journal.py          # append-only JSONL event log (scan.journal.jsonl)
conftest.py             # pytest sys.path fix
pyproject.toml          # packaging + pytest config (asyncio_mode=auto)
.gitignore              # SCAN_STATUS.md, scan.db, *.journal.jsonl excluded
patches/                # numbered .patch files (pre-GitHub workflow era)
tests/
  test_proxy.py              # 16 tests — ScanAddon pipeline
  test_passive_scanner.py    # 35 tests — PassiveScanner + dedup

## Current state
- [x] Project skeleton, SQLiteStore, EndpointMapper, BrainGenerator, Journal
- [x] mitmproxy integration — ScanAddon + runner.py
- [x] PassiveScanner v0.2.0 — 5 detection categories, 24h dedup
- [x] Clean proxy shutdown — CancelledError handled, no traceback
- [x] 51 tests passing, 0 warnings
- [x] GitHub workflow — PC1 commits, PC2 git pull, no more SCP/patch drift
- [x] CA cert deployed — TLS interception working subnet-wide
- [x] Proxy live — 625 endpoints, 822 findings captured overnight
- [ ] generator.py split (SCAN_STATUS.md) not yet applied on VM — pending git pull
- [ ] FindingReporter module — not started
- [ ] SQLiteStore vacuum(max_age_days) — not started

## PassiveScanner detections (v0.2.0)
- [high]   Sensitive data in URL (token/api_key/password/jwt in query string)
- [medium] Sensitive path without auth (/api/, /admin/, /v1/ etc, no auth header)
- [medium] Missing HSTS header
- [medium] Missing Content-Security-Policy
- [low]    Missing X-Frame-Options / X-Content-Type-Options / Permissions-Policy
- [low]    Server version disclosure (Server / X-Powered-By headers)
- Dedup: (title, host) suppressed for 24h, resets on proxy restart

## Live traffic summary (as of session 005 start)
- Endpoints discovered: 625
- Findings logged: 822
- Sites visited: motorola.com, bbc.com, bbc.co.uk, duckduckgo.com,
  focus.de, google.com, brave.com (search)
- Full details in SCAN_STATUS.md on the VM (never paste into chat)

## Hard-won operational notes
- PROJECT_BRAIN.md = lean session handoff (~6KB). Never contains raw endpoints/findings.
- SCAN_STATUS.md = full traffic data. Never paste into chat. In .gitignore.
- Proxy start: python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db
- Manual brain regen: python -m proxy.brain.generator --db scan.db
- After git pull on VM: pytest tests/ -v before restarting proxy
- fix-perms alias (legacy): sudo chown -R lab:lab ~/api-scan-engine && find ~/api-scan-engine -name "*.py" -exec chmod 644 {} \;
- New workflow: push to GitHub on PC1, git pull on PC2 — no more manual file copies

## Last journal entries
- 2026-05-28 21:31  [proxy]  started on 0.0.0.0:8080
- 2026-05-28 21:33  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 08:28  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 08:51  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 08:58  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 09:08  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-29 09:26  [proxy]  started on 0.0.0.0:8080
- 2026-05-29 09:27  [proxy]  stopped — regenerating PROJECT_BRAIN.md

## Next session goal
1. git pull on VM — picks up generator.py split + all session-004 fixes
2. pytest tests/ -v — confirm 51 passed, 0 warnings
3. FindingReporter module (proxy/modules/finding_reporter.py)
   - Console output with colour-coded severity (rich or colorama)
   - JSON export (findings.json) and CSV export (findings.csv)
   - Configurable severity threshold (--min-severity medium)
   - Wire into runner.py; add tests/test_finding_reporter.py
4. SQLiteStore vacuum — vacuum(max_age_days=30) weekly background task
   to keep scan.db bounded as traffic accumulates