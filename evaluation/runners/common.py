"""Shared plumbing for experiment runners (Manual §12): config, results directory, env.json."""

from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evaluation" / "results"


def load_config(path: Path) -> dict[str, Any]:
    """Read one experiment YAML."""
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict) or "experiment" not in doc:
        raise SystemExit(f"{path}: expected a mapping with an 'experiment' key")
    return doc


def git_sha() -> str:
    """Current commit; results directories embed it."""
    git = shutil.which("git")
    if git is None:
        return "unknown"
    try:
        out = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [git, "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=ROOT,
        )  # noqa: S603
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.stdout.strip()


def new_results_dir(experiment: str) -> Path:
    """``evaluation/results/<experiment>/<YYYY-MM-DD_HHMM>_<sha>/`` (append-only: never reused)."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d_%H%M")
    path = RESULTS / experiment / f"{stamp}_{git_sha()}"
    suffix = 1
    while path.exists():
        path = RESULTS / experiment / f"{stamp}_{git_sha()}_{suffix}"
        suffix += 1
    path.mkdir(parents=True)
    return path


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _ram_gb() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        return None
    return None


def _node_version() -> str | None:
    node = shutil.which("node")
    if node is None:
        return None
    try:
        return subprocess.run(  # noqa: S603 — fixed argv, no shell
            [node, "--version"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def write_env(out_dir: Path, config: dict[str, Any], extra: dict[str, Any] | None = None) -> None:
    """``env.json``: machine, versions, git sha, config, plus whatever the runner adds."""
    env = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "git_sha": git_sha(),
        "cpu": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "ram_gb": _ram_gb(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "node": _node_version(),
        "config": config,
        **(extra or {}),
    }
    (out_dir / "env.json").write_text(json.dumps(env, indent=2, default=str) + "\n")


def write_raw(out_dir: Path, rows: list[dict[str, Any]]) -> None:
    """``raw.csv``: one row per measurement, never edited afterwards."""
    if not rows:
        (out_dir / "raw.csv").write_text("")
        return
    with (out_dir / "raw.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_summary(out_dir: Path, summary: dict[str, Any]) -> None:
    """``summary.json`` (median, IQR, n per metric — computed by the runner)."""
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str) + "\n")


def median_iqr(values: list[float]) -> dict[str, float | int]:
    """Median, first/third quartile and n of a list of measurements."""
    import numpy as np  # noqa: PLC0415

    arr = np.asarray(values, dtype=float)
    return {
        "median": float(np.median(arr)),
        "q1": float(np.percentile(arr, 25)),
        "q3": float(np.percentile(arr, 75)),
        "n": int(arr.size),
    }
