"""
proxy/core/runner.py
────────────────────────────────────────────────────────────────────
Programmatic launcher for the scan proxy.

Usage (CLI)
───────────
    python -m proxy.core.runner --host 127.0.0.1 --port 8080 --db scan.db

Usage (library)
───────────────
    from proxy.core.runner import run_proxy
    from proxy.modules.endpoint_mapper import EndpointMapper
    from proxy.core.store import SQLiteStore

    asyncio.run(
        run_proxy(
            host="127.0.0.1",
            port=8080,
            db_path="scan.db",
            extra_modules=[],
        )
    )
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import Sequence

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from proxy.core.proxy import ScanAddon

log = logging.getLogger("scan.runner")


async def run_proxy(
    host: str = "127.0.0.1",
    port: int = 8080,
    db_path: str = "scan.db",
    extra_modules: list = (),
    ssl_insecure: bool = False,
) -> None:
    """
    Boot mitmproxy with ScanAddon.

    Parameters
    ----------
    host, port      : listen address for the proxy
    db_path         : path for SQLiteStore
    extra_modules   : additional IModule instances beyond the defaults
    ssl_insecure    : pass --ssl-insecure (useful for testing)
    """
    # Late import so callers that don't use SQLiteStore can skip it
    from proxy.core.store import SQLiteStore
    from proxy.modules.endpoint_mapper import EndpointMapper
    from proxy.modules.passive_scanner import PassiveScanner
    from proxy.brain.generator import generate, brain_loop
    from proxy.brain.journal import Journal

    store = SQLiteStore(db_path)
    store.open()

    journal = Journal(db_path)
    journal.log("proxy", f"started on {host}:{port}")

    modules = [
        EndpointMapper(store),
        PassiveScanner(store),
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
        brain_loop(db_path),
        name="brain-loop",
    )
    try:
        await master.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Shutting down…")
    finally:
        brain_task.cancel()
        # Wait briefly for brain_task to cancel cleanly
        try:
            await asyncio.wait_for(asyncio.shield(brain_task), timeout=1.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        master.shutdown()
        store.close()
        journal.log("proxy", "stopped — regenerating PROJECT_BRAIN.md")
        await generate(db_path)
        log.info("PROJECT_BRAIN.md updated")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="API Scan Engine — mitmproxy runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", default="127.0.0.1", help="Listen host")
    p.add_argument("--port", type=int, default=8080, help="Listen port")
    p.add_argument("--db", default="scan.db", help="SQLite database path")
    p.add_argument(
        "--ssl-insecure",
        action="store_true",
        help="Disable upstream TLS verification",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
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
            )
        )
    except KeyboardInterrupt:
        pass  # shutdown handled inside run_proxy; suppress traceback
