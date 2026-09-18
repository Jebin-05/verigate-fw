"""Make the shared Stage-1 fixture helpers importable from the fleet tests too."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
