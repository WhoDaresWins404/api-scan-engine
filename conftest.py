"""
conftest.py — project root
──────────────────────────
Ensures the project root is on sys.path so that `import proxy.*`
works whether the package is installed (pip install -e .) or not.

pytest discovers this file automatically before collecting any tests.
"""
import sys
from pathlib import Path

# Insert project root at position 0 so our 'proxy' package takes
# precedence over any system package also named 'proxy'.
ROOT = Path(__file__).parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
