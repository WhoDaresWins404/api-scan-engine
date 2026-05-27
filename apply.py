# apply.py — patch helper for the Windows/WSL lab environment
# Usage:
#   python apply.py patches/session_001_fix.patch            # apply
#   python apply.py patches/session_001_fix.patch --dry-run  # check only
#   python apply.py patches/session_001_fix.patch --reverse  # undo

import sys
import subprocess
from pathlib import Path


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def apply_patch(patch_file: str, dry_run: bool = False, reverse: bool = False) -> None:
    path = Path(patch_file)

    if not path.exists():
        print(f"ERROR: Patch file not found: {patch_file}")
        sys.exit(1)

    # Always dry-run first
    check_cmd = ["git", "apply", "--check", str(path)]
    if reverse:
        check_cmd.append("--reverse")

    check = run(check_cmd)
    if check.returncode != 0:
        print("ERROR: Patch would not apply cleanly:")
        print(check.stderr)
        sys.exit(1)

    if dry_run:
        print(f"OK (dry run): {path.name} would apply cleanly.")
        return

    apply_cmd = ["git", "apply", str(path)]
    if reverse:
        apply_cmd.append("--reverse")

    result = run(apply_cmd)
    if result.returncode == 0:
        action = "Reversed" if reverse else "Applied"
        print(f"{action} successfully: {path.name}")
    else:
        print(f"ERROR applying patch: {result.stderr}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python apply.py <patch_file> [--dry-run] [--reverse]")
        sys.exit(1)

    apply_patch(
        patch_file=sys.argv[1],
        dry_run="--dry-run" in sys.argv,
        reverse="--reverse" in sys.argv,
    )