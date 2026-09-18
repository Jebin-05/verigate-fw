"""Copy the compiled contract ABIs into the Python package and the dashboard.

The gateway image contains no ``contracts/`` directory, so the ABIs the Python bindings need must
ship inside the package. Run after ``npx hardhat compile`` (``make contracts-build`` does this);
``tests/unit/common/test_chain_bindings.py`` fails if the committed copies drift from the artifacts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "contracts" / "artifacts" / "contracts"
TARGET = ROOT / "src" / "verigate" / "common" / "abi"
DASHBOARD_TARGET = ROOT / "dashboard" / "src" / "chain" / "abi"
CONTRACTS = (
    "PublisherRegistry",
    "ModelRegistry",
    "FirmwareRegistry",
    "PolicyContract",
    "VerdictRegistry",
)


def extract(name: str) -> str:
    """Return the canonical JSON text of ``name``'s ABI from its Hardhat artifact."""
    artifact = ARTIFACTS / f"{name}.sol" / f"{name}.json"
    abi = json.loads(artifact.read_text())["abi"]
    return json.dumps(abi, indent=2, sort_keys=True) + "\n"


def main(check_only: bool = False) -> int:
    """Write (or, with ``--check``, compare) every ABI. Returns a process exit code."""
    TARGET.mkdir(parents=True, exist_ok=True)
    DASHBOARD_TARGET.mkdir(parents=True, exist_ok=True)
    drift: list[str] = []
    for name in CONTRACTS:
        text = extract(name)
        for out in (TARGET / f"{name}.json", DASHBOARD_TARGET / f"{name}.json"):
            if check_only:
                if not out.exists() or out.read_text() != text:
                    drift.append(name)
            else:
                out.write_text(text)
    if drift:
        sys.stderr.write(f"ABI drift: {', '.join(drift)} — run scripts/sync_abi.py\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(check_only="--check" in sys.argv[1:]))
