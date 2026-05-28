"""
proxy/brain/journal.py
────────────────────────────────────────────────────────────────────
Append-only session event log.  Written to journal.jsonl alongside
the database file.  Each line is a JSON object — easy to tail, grep,
or parse without loading the whole file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class Journal:
    def __init__(self, db_path: str | Path) -> None:
        # journal sits next to the db file
        self._path = Path(db_path).with_suffix(".journal.jsonl")

    def log(self, event_type: str, detail: str) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            "type": event_type,
            "detail": detail,
        }
        with self._path.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def tail(self, n: int = 20) -> list[dict]:
        if not self._path.exists():
            return []
        lines = self._path.read_text().strip().splitlines()
        return [json.loads(l) for l in lines[-n:]]
