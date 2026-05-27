# proxy/brain/journal.py
# Append-only session event log.
# Written continuously — survives abrupt session termination.
# No dependencies outside the standard library.

import json
from datetime import datetime, timezone
from pathlib import Path


JOURNAL_PATH = Path(__file__).parent.parent.parent / "journal.jsonl"


class Journal:
    """
    Appends structured entries to journal.jsonl in the project root.
    Each line is a valid JSON object (JSON Lines format).
    The file is opened and closed per write — no data lost on crash.
    """

    def __init__(self, path: Path = JOURNAL_PATH):
        self.path = path
        self.path.touch(exist_ok=True)

    def log(self, event_type: str, detail: str, data: dict | None = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "detail": detail,
            "data": data or {},
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def tail(self, n: int = 20) -> list[dict]:
        """Return the last n entries — used by the brain generator."""
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        return [json.loads(line) for line in lines[-n:]]