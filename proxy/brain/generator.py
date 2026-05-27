# proxy/brain/generator.py
# Generates PROJECT_BRAIN.md from live store state + journal.
# Called automatically every 5 minutes by the watcher (watcher.py).
# Also callable manually: python -m proxy.brain.generator
#
# Output is intentionally compact — every line costs tokens at session start.

from datetime import datetime, timezone
from pathlib import Path

from proxy.brain.journal import Journal
from proxy.core.store import SQLiteStore


BRAIN_PATH = Path(__file__).parent.parent.parent / "PROJECT_BRAIN.md"

ARCHITECTURE = """
## Architecture (immutable decisions)
- Proxy core: mitmproxy (Phase 1) → asyncio+httpx (Phase 3)
- Module model: in-process, IModule interface enforced
- Store: SQLite (Phase 1) → PostgreSQL (Phase 2), IStore abstraction
- Protocols: HTTP/HTTPS (Phase 1) → GraphQL/WS (Phase 2) → gRPC (Phase 3)
- Delta patch workflow: git apply / python apply.py for all code changes
- Lab environment: WSL2/Ubuntu inside Windows, VS Code WSL extension
""".strip()

INTERFACE_SUMMARY = """
## Core interfaces (proxy/core/interfaces.py)
- ProxyRequest: id, timestamp, method, url, headers, body
- ProxyResponse: request_id, timestamp, status_code, headers, body
- ModuleHealth: module_name, version, status, last_seen, detail
- Finding: module_name, severity, title, description, request_id, evidence, timestamp
- IModule: name, version, on_request(), on_response(), healthcheck()
- IStore: write(), read(), query(), subscribe(), publish()
""".strip()

FILE_STRUCTURE = """
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
""".strip()


class BrainGenerator:

    def __init__(self, store: SQLiteStore, journal: Journal):
        self._store = store
        self._journal = journal

    async def generate(self) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        endpoints = await self._store.query("endpoints")
        findings = await self._store.query("findings")
        journal_tail = self._journal.tail(10)

        sections = [
            f"# PROJECT_BRAIN — API Scan Engine",
            f"_Auto-generated: {now}_",
            f"_Paste this file at the start of every new session._",
            "",
            ARCHITECTURE,
            "",
            INTERFACE_SUMMARY,
            "",
            FILE_STRUCTURE,
            "",
            self._render_status(endpoints, findings),
            "",
            self._render_endpoints(endpoints),
            "",
            self._render_findings(findings),
            "",
            self._render_journal(journal_tail),
            "",
            "## Next session goal",
            "_Update this section before committing at session end._",
        ]

        return "\n".join(sections)

    def _render_status(self, endpoints: list, findings: list) -> str:
        lines = ["## Current state"]
        lines.append("- [x] Project skeleton — interfaces, store, journal, apply helper")
        lines.append("- [x] SQLiteStore — write, read, query, pub/sub verified")
        lines.append("- [x] EndpointMapper module — verified")
        lines.append("- [x] BrainGenerator — auto-generates this file")
        lines.append("- [ ] PassiveScanner module — not started")
        lines.append("- [ ] mitmproxy integration (proxy core) — not started")
        lines.append("- [ ] FindingReporter module — not started")
        lines.append(f"\nEndpoints discovered: {len(endpoints)}")
        lines.append(f"Findings logged: {len(findings)}")
        return "\n".join(lines)

    def _render_endpoints(self, endpoints: list) -> str:
        if not endpoints:
            return "## Discovered endpoints\n_None yet — run the proxy against a target._"
        lines = ["## Discovered endpoints"]
        for ep in endpoints[-20:]:  # cap at 20 to keep the file compact
            status = ep.get("last_status", "-")
            lines.append(
                f"- {ep.get('method','?')} {ep.get('scheme','https')}://"
                f"{ep.get('host','?')}{ep.get('path','/')}  [{status}]"
            )
        if len(endpoints) > 20:
            lines.append(f"_...and {len(endpoints) - 20} more in the store._")
        return "\n".join(lines)

    def _render_findings(self, findings: list) -> str:
        if not findings:
            return "## Findings\n_None yet._"
        lines = ["## Findings"]
        for f in findings[-10:]:
            lines.append(
                f"- [{f.get('severity','?').upper()}] {f.get('title','?')} "
                f"— {f.get('module_name','?')}"
            )
        return "\n".join(lines)

    def _render_journal(self, entries: list) -> str:
        if not entries:
            return "## Last session journal\n_No entries._"
        lines = ["## Last session journal"]
        for e in entries:
            ts = e.get("ts", "")[:16].replace("T", " ")
            lines.append(f"- {ts}  [{e.get('event','?')}]  {e.get('detail','')}")
        return "\n".join(lines)

    async def write(self) -> Path:
        content = await self.generate()
        BRAIN_PATH.write_text(content, encoding="utf-8")
        return BRAIN_PATH


async def _main():
    store = SQLiteStore()
    store.open()
    journal = Journal()
    gen = BrainGenerator(store, journal)
    path = await gen.write()
    print(f"PROJECT_BRAIN.md written → {path}")
    store.close()


if __name__ == "__main__":
    import asyncio
    asyncio.run(_main())