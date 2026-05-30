"""
proxy/core/runner.py
────────────────────────────────────────────────────────────────────
Programmatic launcher for the scan proxy.

Usage (CLI)
───────────
    python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db
    python -m proxy.core.runner --host 0.0.0.0 --port 8080 --db scan.db \
        --min-severity medium

Usage (library)
───────────────
    asyncio.run(run_proxy(host="0.0.0.0", port=8080, db_path="scan.db"))
"""
from __future__ import annotations

import argparse
import asyncio
import logging

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from proxy.core.proxy import ScanAddon

log = logging.getLogger("scan.runner")

VACUUM_INTERVAL = 7 * 24 * 3600   # weekly, in seconds


async def run_proxy(
    host: str = "127.0.0.1",
    port: int = 8080,
    db_path: str = "scan.db",
    extra_modules: list = (),
    ssl_insecure: bool = False,
    min_severity: str = "info",
    report_console: bool = True,
    report_json: str | None = "findings.ndjson",
    report_csv: str | None = "findings.csv",
) -> None:
    from proxy.core.store import SQLiteStore
    from proxy.modules.endpoint_mapper import EndpointMapper
    from proxy.modules.passive_scanner import PassiveScanner
    from proxy.modules.finding_reporter import FindingReporter
    from proxy.brain.generator import generate, brain_loop
    from proxy.brain.journal import Journal

    store = SQLiteStore(db_path)
    store.open()

    journal = Journal(db_path)
    journal.log("proxy", f"started on {host}:{port}")

    # FindingReporter wired as IModule so ScanAddon calls on_request/on_response
    # AND as a subscriber via reporter.start() for real-time pub/sub output
    reporter = FindingReporter(
        store,
        min_severity=min_severity,
        console=report_console,
        json_path=report_json,
        csv_path=report_csv,
    )
    await reporter.start()

    modules = [
        EndpointMapper(store),
        PassiveScanner(store),
        reporter,            # wired as IModule — healthcheck included in sweep
        *extra_modules,
    ]

    addon = ScanAddon(modules=modules, store=store)

    opts = options.Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=ssl_insecure,
    )
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(addon)

    log.info("Starting proxy on %s:%d  (db=%s)", host, port, db_path)

    brain_task = asyncio.get_event_loop().create_task(
        brain_loop(db_path), name="brain-loop"
    )
    vacuum_task = asyncio.get_event_loop().create_task(
        _vacuum_loop(store), name="vacuum-loop"
    )

    try:
        await master.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Shutting down…")
    finally:
        brain_task.cancel()
        vacuum_task.cancel()
        for t in (brain_task, vacuum_task):
            try:
                await asyncio.wait_for(asyncio.shield(t), timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        master.shutdown()
        await reporter.stop()
        store.close()
        journal.log("proxy", "stopped — regenerating PROJECT_BRAIN.md")
        await generate(db_path)
        log.info("PROJECT_BRAIN.md updated")


async def _vacuum_loop(store) -> None:
    """Background task: vacuum old records weekly."""
    while True:
        await asyncio.sleep(VACUUM_INTERVAL)
        try:
            deleted = store.vacuum(max_age_days=30)
            log.info("Vacuum complete — %d record(s) deleted", deleted)
        except Exception as exc:
            log.error("Vacuum failed: %s", exc)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="API Scan Engine — mitmproxy runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", default="127.0.0.1", help="Listen host")
    p.add_argument("--port", type=int, default=8080, help="Listen port")
    p.add_argument("--db", default="scan.db", help="SQLite database path")
    p.add_argument(
        "--ssl-insecure", action="store_true",
        help="Disable upstream TLS verification",
    )
    p.add_argument(
        "--min-severity", default="info",
        choices=["info", "low", "medium", "high", "critical"],
        help="Minimum severity level to report",
    )
    p.add_argument(
        "--no-console", action="store_true",
        help="Suppress console finding output",
    )
    p.add_argument(
        "--report-json", default="findings.ndjson",
        help="Path for JSON findings output (empty string to disable)",
    )
    p.add_argument(
        "--report-csv", default="findings.csv",
        help="Path for CSV findings output (empty string to disable)",
    )
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(name)-20s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        asyncio.run(
            run_proxy(
                host=args.host,
                port=args.port,
                db_path=args.db,
                ssl_insecure=args.ssl_insecure,
                min_severity=args.min_severity,
                report_console=not args.no_console,
                report_json=args.report_json or None,
                report_csv=args.report_csv or None,
            )
        )
    except KeyboardInterrupt:
        pass  # shutdown handled inside run_proxy; suppress traceback