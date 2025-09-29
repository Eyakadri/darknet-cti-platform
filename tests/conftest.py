import sys
from pathlib import Path

# Make repository root importable for tests without installing the package.
# Keeps local iteration fast (pytest sees source directly).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
