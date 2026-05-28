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

    store = SQLiteStore(db_path)

    modules = [
        EndpointMapper(store),
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
    try:
        await master.run()
    except KeyboardInterrupt:
        log.info("Shutting down…")
    finally:
        master.shutdown()


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
    asyncio.run(
        run_proxy(
            host=args.host,
            port=args.port,
            db_path=args.db,
            ssl_insecure=args.ssl_insecure,
        )
    )
