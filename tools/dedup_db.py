#!/usr/bin/env python3
"""
tools/dedup_db.py
────────────────────────────────────────────────────────────────────
One-shot deduplication of an existing scan.db.

Removes duplicate findings and endpoints that accumulated before
content-based IDs were introduced, then runs VACUUM to reclaim disk.

Usage
─────
    python tools/dedup_db.py                    # default: scan.db
    python tools/dedup_db.py --db /path/to.db
    python tools/dedup_db.py --dry-run          # count only, no changes

Safety
──────
  - Creates a .bak copy of the database before making any changes
  - Prints before/after row counts and file sizes
  - Safe to run on a live database (single transaction)
  - Keeps the EARLIEST record when duplicates are found
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description="Deduplicate scan.db")
    p.add_argument("--db", default="scan.db", help="Path to SQLite database")
    p.add_argument("--dry-run", action="store_true", help="Count duplicates without deleting")
    args = p.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    # Stats before
    size_before = db_path.stat().st_size
    print(f"Database: {db_path}  ({size_before / 1024:.1f} KB)")

    # Open store
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from proxy.core.store import SQLiteStore, _content_key

    store = SQLiteStore(db_path)
    store.open()

    # Count rows before
    rows_before = store._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    by_col_before = dict(store._conn.execute(
        "SELECT collection, COUNT(*) FROM records GROUP BY collection"
    ).fetchall())
    print(f"\nRows before: {rows_before}")
    for col, count in sorted(by_col_before.items()):
        print(f"  {col}: {count}")

    # Find duplicates
    rows = store._conn.execute(
        "SELECT id, collection, data, created_at FROM records ORDER BY created_at ASC"
    ).fetchall()

    import json
    seen: dict[tuple[str, str], str] = {}  # (collection, content_key) -> id to keep
    to_delete: list[str] = []

    for row in rows:
        rec = json.loads(row["data"])
        col = row["collection"]
        key = _content_key(col, rec)
        full_key = (col, key)
        if full_key not in seen:
            seen[full_key] = row["id"]
        else:
            to_delete.append(row["id"])

    print(f"\nDuplicates found: {len(to_delete)}")

    if not to_delete:
        print("Nothing to do — database is already clean.")
        store.close()
        return

    if args.dry_run:
        # Count by collection
        dry_counts: dict[str, int] = {}
        for rid in to_delete:
            row = store._conn.execute(
                "SELECT collection FROM records WHERE id=?", (rid,)
            ).fetchone()
            if row:
                dry_counts[row["collection"]] = dry_counts.get(row["collection"], 0) + 1
        print("\nWould delete (dry-run):")
        for col, count in sorted(dry_counts.items()):
            print(f"  {col}: {count}")
        store.close()
        return

    # Backup
    bak_path = db_path.with_suffix(".db.bak")
    shutil.copy2(db_path, bak_path)
    print(f"\nBackup saved: {bak_path}")

    # Delete duplicates
    deleted_by_col: dict[str, int] = {}
    for rid in to_delete:
        row = store._conn.execute(
            "SELECT collection FROM records WHERE id=?", (rid,)
        ).fetchone()
        if row:
            col = row["collection"]
            deleted_by_col[col] = deleted_by_col.get(col, 0) + 1
        store._conn.execute("DELETE FROM records WHERE id=?", (rid,))
    store._conn.commit()

    # VACUUM
    store._conn.isolation_level = None
    store._conn.execute("VACUUM")
    store._conn.isolation_level = ""
    store.close()

    # Stats after
    rows_after = rows_before - len(to_delete)
    size_after = db_path.stat().st_size
    saved_kb = (size_before - size_after) / 1024

    print(f"\nDeleted:")
    for col, count in sorted(deleted_by_col.items()):
        print(f"  {col}: {count}")

    print(f"\nRows after:  {rows_after}  ({len(to_delete)} removed)")
    print(f"Size after:  {size_after / 1024:.1f} KB  (saved {saved_kb:.1f} KB)")
    print("\nDone. Backup preserved at", bak_path)


if __name__ == "__main__":
    main()