# PROJECT_BRAIN — API Scan Engine
_Auto-generated: 2026-05-28 21:33 UTC_
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
    generator.py        # regenerates this file — every 10 min + on shutdown
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
- [x] BrainGenerator — every 10 min + on shutdown, wired to runner.py
- [x] Journal — wired to runner.py start/stop events
- [x] mitmproxy integration — proxy/core/proxy.py + runner.py complete
- [x] 16 tests passing (pytest tests/ -v), 0 warnings
- [x] VirtualBox VM deployment — 192.168.50.221, DHCP reserved lease
- [x] CA cert distributed — TLS interception working subnet-wide
- [ ] PassiveScanner module — not started
- [ ] FindingReporter module — not started

## Discovered endpoints (15 total)
- GET http://detectportal.firefox.com/canonical.html   [last status: 200]
- GET http://detectportal.firefox.com/success.txt   [last status: 200]
- POST https://play.google.com/log   [last status: 200]
- GET https://search.brave.com/api/suggest   [last status: 422]
- GET https://www.google.com/   [last status: 200]
- POST https://www.google.com/adview   [last status: 204]
- GET https://www.google.com/async/hpba   [last status: 200]
- GET https://www.google.com/complete/s   [last status: 200]
- GET https://www.google.com/gen_204   [last status: 204]
- POST https://www.google.com/gen_204   [last status: 204]
- GET https://www.google.com/xjs/_/js/k=xjs.hd.de.j8s5Z0dD-o0.2019.O/ck=xjs.hd.2om9GWu2klQ.L.B1.O/am=AAACAgAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAiBAAAYAAAIgAAAAAEAgQEAAAAEAAAAAAAQeoAAQAMAAAAAAAAAAAAAAAAEAgQQAAAQAAAAAAAACBAAABAAQAAAgBAAAABgAAABAAEkEACABgUAAAAAAAIAAAAAAAAAABABAAAAhAAAfxhgDQAAAAAAgCERBgMBAAAAAMKABQAAAAUAAACAAAgAAAAAAAAISAACACBgAEAAAAAEAAAAAAACAgghCAACFEAAAAAQAAAQAAAAABQIEBAAAAAACACAAEBAIAQQAAAAgIACBAABAIIABAQAjKABAEhUCAAAQgcAACAAAAAAAAEAAAAAAAAAAAAAAJwAAAQEAAAgAWAIBAIABAAAAAA6AAIPMKSgAAAAAAAAAAAAAAAAAAAAAAAAAAEUwC4kUBAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAQGhTAAAAAACAxQ/d=0/dg=0/br=1/ujg=1/rs=ACT90oFscYaC8gLxuNuusCOeBUgZ1Uk4hQ/m=syxi,HGv0mf,sy1pi,syi4,sysc,VtMfj,U9EYge,sy11q,loL8vb,sy11t,sy11s,sy108,sy107,syzz,sy102,sy10w,sy10t,sy10r,sydb,sydc,syd6,sy10u,sy10z,sygv,sygu,sygt,sy10v,sy10x,sy110,sy111,sy10y,sy106,sy10f,sy10b,sy10a,sy109,syzw,sy10q,sy10h,sy10m,sy10i,sy10e,sy10d,sy10c,syzy,syzt,syym,sy100,ms4mZb,syx8,B2qlPe,sy140,NzU6V,sy14i,sy9b,WlNQGd,syzs,syzq,syzp,DPreE,sy14k,sy14j,nabPbb,abd,sy44q,TDFkye   [last status: 200]
- GET https://www.google.com/xjs/_/ss/k=xjs.hd.2om9GWu2klQ.L.B1.O/am=AAACAgAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAiBAAAYAAAAAAAAAAEAAAEAAAAEAAAAAAAQegAAQAMAAAAAAAAAAAAAAAAAAAQAAAAQAAAAAAAACBAAABAAAAAAgBAAAAAAAAABAAEkAACAAAUAAAAAAAIAAAAAAAAAAAABAAAAAAAAAAAACQAAAAAAgAEQBgMBAAAAAMIAAAAAAAAAAAAAAAAAAAAAAAAISAACACBgAAAAAAAEAAAAAAACAgghCAACFEAAAAAAAAAQAAAAABQIEBAAAAAAAACAAEBAIAQQAAAAgAAABAABAAIABAQAjKABAEhUCAAAQgcAACAAAAAAAAEAAAAAAAAAAAAAAIwAAAAAAAAgAWAIBAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUA/d=0/br=1/rs=ACT90oFEnt4LbuAMQTrTvjVt_DcqHyV_lg/m=aG3wVc,syr0,sysu,syrg,synt,sy146   [last status: 200]
- GET https://www.google.com/xjs/_/ss/k=xjs.hd.2om9GWu2klQ.L.B1.O/am=AAACAgAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAiBAAAYAAAAAAAAAAEAAAEAAAAEAAAAAAAQegAAQAMAAAAAAAAAAAAAAAAAAAQAAAAQAAAAAAAACBAAABAAAAAAgBAAAAAAAAABAAEkAACAAAUAAAAAAAIAAAAAAAAAAAABAAAAAAAAAAAACQAAAAAAgAEQBgMBAAAAAMIAAAAAAAAAAAAAAAAAAAAAAAAISAACACBgAAAAAAAEAAAAAAACAgghCAACFEAAAAAAAAAQAAAAABQIEBAAAAAAAACAAEBAIAQQAAAAgAAABAABAAIABAQAjKABAEhUCAAAQgcAACAAAAAAAAEAAAAAAAAAAAAAAIwAAAAAAAAgAWAIBAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUA/d=0/br=1/rs=ACT90oFEnt4LbuAMQTrTvjVt_DcqHyV_lg/m=syx7,sy1pk,sym5,sypb   [last status: 200]
- GET https://www.google.com/xjs/_/ss/k=xjs.hd.2om9GWu2klQ.L.B1.O/am=AAACAgAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAiBAAAYAAAAAAAAAAEAAAEAAAAEAAAAAAAQegAAQAMAAAAAAAAAAAAAAAAAAAQAAAAQAAAAAAAACBAAABAAAAAAgBAAAAAAAAABAAEkAACAAAUAAAAAAAIAAAAAAAAAAAABAAAAAAAAAAAACQAAAAAAgAEQBgMBAAAAAMIAAAAAAAAAAAAAAAAAAAAAAAAISAACACBgAAAAAAAEAAAAAAACAgghCAACFEAAAAAAAAAQAAAAABQIEBAAAAAAAACAAEBAIAQQAAAAgAAABAABAAIABAQAjKABAEhUCAAAQgcAACAAAAAAAAEAAAAAAAAAAAAAAIwAAAAAAAAgAWAIBAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUA/d=0/br=1/rs=ACT90oFEnt4LbuAMQTrTvjVt_DcqHyV_lg/m=y05UD,PPhKqf,vECdaf,sy1jj,sy151,sy1kq,sy1km,sy1n1,sy153,sy152,sy154,sy14y,syo5,syrj,sy1n2,sy14w,sy14v,sy14x,epYOx   [last status: 200]
- GET https://www.google.com/xjs/_/ss/k=xjs.hd.2om9GWu2klQ.L.B1.O/am=AAACAgAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAiBAAAYAAAAAAAAAAEAAAEAAAAEAAAAAAAQegAAQAMAAAAAAAAAAAAAAAAAAAQAAAAQAAAAAAAACBAAABAAAAAAgBAAAAAAAAABAAEkAACAAAUAAAAAAAIAAAAAAAAAAAABAAAAAAAAAAAACQAAAAAAgAEQBgMBAAAAAMIAAAAAAAAAAAAAAAAAAAAAAAAISAACACBgAAAAAAAEAAAAAAACAgghCAACFEAAAAAAAAAQAAAAABQIEBAAAAAAAACAAEBAIAQQAAAAgAAABAABAAIABAQAjKABAEhUCAAAQgcAACAAAAAAAAEAAAAAAAAAAAAAAIwAAAAAAAAgAWAIBAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUA/d=1/ed=1/br=1/rs=ACT90oFEnt4LbuAMQTrTvjVt_DcqHyV_lg/m=cdos,hsm,jsa,mb4ZUb,cEt90b,SNUn3,qddgKe,sTsDMc,dtl0hd,eHDfl,YV5bee,d,csi   [last status: 200]

## Findings (15 total)
- [INFO] New endpoint discovered — endpoint_mapper (request 115b7b48…)
- [INFO] New endpoint discovered — endpoint_mapper (request 7bef2f64…)
- [INFO] New endpoint discovered — endpoint_mapper (request e7d03a69…)
- [INFO] New endpoint discovered — endpoint_mapper (request 12d7bccd…)
- [INFO] New endpoint discovered — endpoint_mapper (request a620c521…)
- [INFO] New endpoint discovered — endpoint_mapper (request 83493816…)
- [INFO] New endpoint discovered — endpoint_mapper (request b3b7de8f…)
- [INFO] New endpoint discovered — endpoint_mapper (request ee4212ae…)
- [INFO] New endpoint discovered — endpoint_mapper (request 85292b89…)
- [INFO] New endpoint discovered — endpoint_mapper (request 2a0dabd7…)
- [INFO] New endpoint discovered — endpoint_mapper (request d9402cfb…)
- [INFO] New endpoint discovered — endpoint_mapper (request 9f8c6f07…)
- [INFO] New endpoint discovered — endpoint_mapper (request 5218b218…)
- [INFO] New endpoint discovered — endpoint_mapper (request af16f351…)
- [INFO] New endpoint discovered — endpoint_mapper (request 8fb53dc9…)

## Last session journal
- 2026-05-28 21:31  [proxy]  started on 0.0.0.0:8080
- 2026-05-28 21:32  [proxy]  stopped — regenerating PROJECT_BRAIN.md
- 2026-05-28 21:32  [proxy]  started on 0.0.0.0:8080
- 2026-05-28 21:33  [proxy]  stopped — regenerating PROJECT_BRAIN.md

## Next session goal
- Implement PassiveScanner module (proxy/modules/passive_scanner.py)
  Detections: missing security headers (CSP, HSTS, X-Frame-Options),
  sensitive data in URLs (tokens/passwords in query strings),
  unauthenticated endpoints on sensitive paths
- Wire PassiveScanner into runner.py alongside EndpointMapper
- Add tests/test_passive_scanner.py
