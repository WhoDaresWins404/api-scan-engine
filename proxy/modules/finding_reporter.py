"""
proxy/modules/finding_reporter.py
────────────────────────────────────────────────────────────────────
FindingReporter — subscribes to the findings pub/sub topic and
outputs new findings in real time to:

  * Console  — colour-coded by severity (uses ANSI codes, no deps)
  * JSON file — append-only newline-delimited JSON (findings.ndjson)
  * CSV file  — append-only, one row per finding (findings.csv)

All outputs are filtered by a configurable minimum severity.

Severity order (ascending): info < low < medium < high < critical

Usage in runner.py
──────────────────
    reporter = FindingReporter(
        store,
        min_severity="low",        # filter threshold
        console=True,              # print to stdout
        json_path="findings.ndjson",
        csv_path="findings.csv",
    )
    await reporter.start()         # subscribe to store pub/sub
    # ... proxy runs ...
    await reporter.stop()          # flush and close files
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from proxy.core.interfaces import Finding, IStore, ModuleHealth, ProxyRequest, ProxyResponse

log = logging.getLogger("scan.reporter")

# ── severity ordering ────────────────────────────────────────────
SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ── ANSI colour codes ────────────────────────────────────────────
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_COLOURS: dict[str, str] = {
    "critical": "\033[1;35m",   # bold magenta
    "high":     "\033[1;31m",   # bold red
    "medium":   "\033[1;33m",   # bold yellow
    "low":      "\033[1;34m",   # bold blue
    "info":     "\033[0;37m",   # grey
}

# ── CSV column order ─────────────────────────────────────────────
CSV_FIELDS = [
    "timestamp", "severity", "module_name",
    "title", "description", "request_id", "evidence",
]


class FindingReporter:
    name = "finding_reporter"
    version = "0.1.0"

    def __init__(
        self,
        store: IStore,
        min_severity: str = "info",
        console: bool = True,
        json_path: str | Path | None = "findings.ndjson",
        csv_path: str | Path | None = "findings.csv",
        use_colour: bool = True,
    ) -> None:
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(
                f"Invalid min_severity '{min_severity}'. "
                f"Choose from: {list(SEVERITY_ORDER)}"
            )
        self._store = store
        self._min_rank = SEVERITY_ORDER[min_severity]
        self._console = console
        self._json_path = Path(json_path) if json_path else None
        self._csv_path = Path(csv_path) if csv_path else None
        self._use_colour = use_colour and sys.stdout.isatty()
        self._json_file = None
        self._csv_file = None
        self._csv_writer = None
        self._reported_count = 0

    # ── lifecycle ─────────────────────────────────────────────────

    async def start(self) -> None:
        """Open output files and subscribe to the findings topic."""
        self._open_files()
        await self._store.subscribe("findings", self._on_finding)
        log.info(
            "FindingReporter started  (min=%s, console=%s, json=%s, csv=%s)",
            list(SEVERITY_ORDER)[self._min_rank],
            self._console,
            self._json_path or "off",
            self._csv_path or "off",
        )

    async def stop(self) -> None:
        """Flush and close output files."""
        self._close_files()
        log.info("FindingReporter stopped  (%d finding(s) reported)", self._reported_count)

    # ── IModule interface (passive — never modifies traffic) ──────

    async def on_request(self, req: ProxyRequest) -> list[Finding]:
        return []

    async def on_response(self, req: ProxyRequest, resp: ProxyResponse) -> list[Finding]:
        return []

    async def healthcheck(self) -> ModuleHealth:
        return ModuleHealth(
            module_name=self.name,
            version=self.version,
            status="ok",
            last_seen=datetime.now(timezone.utc),
            detail=f"{self._reported_count} finding(s) reported since start",
        )

    # ── pub/sub handler ───────────────────────────────────────────

    async def _on_finding(self, payload: Any) -> None:
        """Called by IStore.publish() for every new finding."""
        # payload may be a Finding dataclass or a plain dict (from store)
        if isinstance(payload, Finding):
            f = payload
        elif isinstance(payload, dict):
            f = _dict_to_finding(payload)
        else:
            return

        if SEVERITY_ORDER.get(f.severity, 0) < self._min_rank:
            return

        self._reported_count += 1

        if self._console:
            self._print_finding(f)

        if self._json_file:
            self._write_json(f)

        if self._csv_writer:
            self._write_csv(f)

    # ── output methods ────────────────────────────────────────────

    def _print_finding(self, f: Finding) -> None:
        colour = _COLOURS.get(f.severity, "") if self._use_colour else ""
        reset  = _RESET if self._use_colour else ""
        bold   = _BOLD  if self._use_colour else ""
        ts     = f.timestamp.strftime("%H:%M:%S") if f.timestamp else "?"
        print(
            f"{colour}[{f.severity.upper():8s}]{reset} "
            f"{bold}{ts}{reset} "
            f"{f.module_name}: {f.title} "
            f"— {f.description[:120]}"
            + (" …" if len(f.description) > 120 else ""),
            flush=True,
        )

    def _write_json(self, f: Finding) -> None:
        try:
            record = {
                "timestamp":   f.timestamp.isoformat() if f.timestamp else None,
                "severity":    f.severity,
                "module_name": f.module_name,
                "title":       f.title,
                "description": f.description,
                "request_id":  f.request_id,
                "evidence":    f.evidence,
            }
            self._json_file.write(json.dumps(record) + "\n")
            self._json_file.flush()
        except Exception as exc:
            log.error("FindingReporter JSON write error: %s", exc)

    def _write_csv(self, f: Finding) -> None:
        try:
            self._csv_writer.writerow({
                "timestamp":   f.timestamp.isoformat() if f.timestamp else "",
                "severity":    f.severity,
                "module_name": f.module_name,
                "title":       f.title,
                "description": f.description,
                "request_id":  f.request_id,
                "evidence":    json.dumps(f.evidence),
            })
            self._csv_file.flush()
        except Exception as exc:
            log.error("FindingReporter CSV write error: %s", exc)

    # ── file management ───────────────────────────────────────────

    def _open_files(self) -> None:
        if self._json_path:
            self._json_file = self._json_path.open("a", encoding="utf-8")

        if self._csv_path:
            write_header = not self._csv_path.exists() or self._csv_path.stat().st_size == 0
            self._csv_file = self._csv_path.open("a", newline="", encoding="utf-8")
            self._csv_writer = csv.DictWriter(
                self._csv_file, fieldnames=CSV_FIELDS, extrasaction="ignore"
            )
            if write_header:
                self._csv_writer.writeheader()

    def _close_files(self) -> None:
        for f in (self._json_file, self._csv_file):
            if f:
                try:
                    f.flush()
                    f.close()
                except Exception:
                    pass
        self._json_file = None
        self._csv_file = None
        self._csv_writer = None


# ── helpers ───────────────────────────────────────────────────────

def _dict_to_finding(d: dict) -> Finding:
    ts_raw = d.get("timestamp")
    if isinstance(ts_raw, str):
        try:
            ts = datetime.fromisoformat(ts_raw)
        except ValueError:
            ts = datetime.now(timezone.utc)
    elif isinstance(ts_raw, datetime):
        ts = ts_raw
    else:
        ts = datetime.now(timezone.utc)

    return Finding(
        module_name=d.get("module_name", "unknown"),
        severity=d.get("severity", "info"),
        title=d.get("title", ""),
        description=d.get("description", ""),
        request_id=d.get("request_id", ""),
        evidence=d.get("evidence", {}),
        timestamp=ts,
    )