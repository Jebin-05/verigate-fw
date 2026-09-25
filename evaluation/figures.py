"""The only producer of figures (Manual §12): ``evaluation/results/`` → ``evaluation/figures/``.

``python evaluation/figures.py [--latest]`` — for every experiment the newest results directory
(by name, i.e. timestamp) is used; every figure states the results directory it came from in its
caption so a figure can always be traced to raw data. Nothing here is typed by hand.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
# Embed TrueType (Type 42) fonts: IEEE PDF eXpress rejects the Type 3 default.
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
FIGURES = ROOT / "figures"


def latest(experiment: str) -> Path | None:
    """Newest results directory of ``experiment`` that has a summary."""
    base = RESULTS / experiment
    if not base.is_dir():
        return None
    dirs = sorted(d for d in base.iterdir() if (d / "summary.json").is_file())
    return dirs[-1] if dirs else None


def load(run: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    summary = json.loads((run / "summary.json").read_text())
    with (run / "raw.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    return summary, rows


def _save(fig: Figure, name: str, run: Path) -> None:
    fig.text(0.01, 0.005, f"source: {run.relative_to(ROOT.parent)}", fontsize=6, alpha=0.7)
    fig.tight_layout(rect=(0, 0.02, 1, 1))
    for ext in ("png", "pdf"):
        fig.savefig(FIGURES / f"{name}.{ext}", dpi=160)
    plt.close(fig)
    print(f"  {name}.png/.pdf ← {run.name}")


def fig_latency(run1: Path | None, run2: Path | None) -> None:
    """Box plots of the Stage-1 and Stage-2 timings (ms, log scale)."""
    series: list[tuple[str, list[float]]] = []
    for run, metrics in (
        (run1, ["checks_ms", "verify_warm_ms", "verify_cold_ms"]),
        (
            run2,
            [
                "sbom_warm_ms",
                "sbom_cold_ms",
                "img_warm_ms",
                "img_cold_ms",
                "verify_warm_ms",
                "http_device_verify_ms",
            ],
        ),
    ):
        if run is None:
            continue
        _, rows = load(run)
        kept = [r for r in rows if r.get("warmup", "False") == "False"]
        stage = "S1" if run.parent.name == "latency_stage1" else "S2"
        for m in metrics:
            vals = [float(r[m]) for r in kept if r.get(m) not in (None, "", "None")]
            if vals:
                series.append((f"{stage} {m.removesuffix('_ms')}", vals))
    if not series:
        return
    fig, ax = plt.subplots(figsize=(8, 3.6))
    ax.boxplot([v for _, v in series], tick_labels=[n for n, _ in series], showfliers=False)
    ax.set_yscale("log")
    ax.set_ylabel("ms (log)")
    ax.set_title("Verification latency per stage (median box, IQR; warm-up discarded)")
    ax.tick_params(axis="x", rotation=30)
    _save(fig, "latency", run2 or run1)  # type: ignore[arg-type]


def fig_gas(run: Path | None) -> None:
    """Gas per anchored verdict vs batch size."""
    if run is None:
        return
    summary, _ = load(run)
    sizes = [int(s) for s in summary["batch_sizes"]]
    per = [summary["per_size"][str(s)]["gas_per_verdict"]["median"] for s in sizes]
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    ax.plot(sizes, per, marker="o")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("verdicts per commitBatch")
    ax.set_ylabel("gas per verdict")
    ax.set_title("On-chain cost per verdict (local Hardhat receipts)")
    for s, g in zip(sizes, per, strict=True):
        ax.annotate(f"{g:,.0f}", (s, g), textcoords="offset points", xytext=(4, 4), fontsize=7)
    _save(fig, "gas_per_verdict", run)


def fig_detection(run: Path | None) -> None:
    """Per-class recall/precision at the operating point plus the threshold sweep."""
    if run is None:
        return
    summary, _ = load(run)
    point = summary["point_estimates"]
    classes = list(point)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 3.4))
    x = range(len(classes))
    ax1.bar([i - 0.2 for i in x], [point[c]["recall"] for c in classes], 0.4, label="recall")
    ax1.bar([i + 0.2 for i in x], [point[c]["auroc"] for c in classes], 0.4, label="AUROC")
    ax1.set_xticks(list(x), classes, rotation=25)
    ax1.set_ylim(0, 1.05)
    ax1.axhline(0.5, ls=":", c="grey", lw=0.8)
    ax1.set_title(f"Image anomaly detector per mutation (r_img ≥ {summary['threshold']})")
    ax1.legend(fontsize=8)
    sweep = summary["threshold_sweep_all_classes"]
    ax2.plot([s["threshold"] for s in sweep], [s["recall"] for s in sweep], label="recall (all)")
    ax2.plot(
        [s["threshold"] for s in sweep], [s["fpr"] for s in sweep], label="false-positive rate"
    )
    ax2.set_xlabel("r_img threshold")
    ax2.set_title("Threshold sweep")
    ax2.legend(fontsize=8)
    _save(fig, "detection_f1", run)


def fig_sbom_ranking(run: Path | None) -> None:
    """Model vs baseline bootstrap distributions."""
    if run is None:
        return
    _, rows = load(run)
    metrics = ["spearman", "mae"]
    fig, axes = plt.subplots(1, len(metrics), figsize=(7, 3.2))
    for ax, m in zip(axes, metrics, strict=True):
        data = [
            [float(r[m]) for r in rows if r["scorer"] == s and r[m]] for s in ("model", "baseline")
        ]
        ax.boxplot(
            data, tick_labels=["sbom_risk (HGBR)", "CVSS/EPSS/KEV baseline"], showfliers=False
        )
        ax.set_title(f"{m} on held-out releases (bootstrap)")
    _save(fig, "sbom_ranking", run)


def fig_revocation(run: Path | None) -> None:
    """Replay time vs fleet size."""
    if run is None:
        return
    summary, rows = load(run)
    sizes = [int(s) for s in summary["fleet_sizes"]]
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    data = [
        [float(r["handle_ms"]) / 1000 for r in rows if int(r["fleet_size"]) == s] for s in sizes
    ]
    ax.boxplot(data, tick_labels=[str(s) for s in sizes], showfliers=False)
    ax.set_xlabel("devices with a stale verdict")
    ax.set_ylabel("replay time (s)")
    ax.set_title(f"Model revocation → all verdicts replayed (poll {summary['poll_s']} s excluded)")
    _save(fig, "revocation_propagation", run)


def table_attack_matrix(run: Path | None) -> None:
    """Markdown table: one row per attack (expected, observed, runs, pass rate)."""
    if run is None:
        return
    summary, _ = load(run)
    lines = [
        f"<!-- generated by evaluation/figures.py from {run.relative_to(ROOT.parent)} -->",
        "| attack | expected | observed | runs | pass rate | median s |",
        "|---|---|---|---|---|---|",
    ]
    for name, m in summary["matrix"].items():
        lines.append(
            f"| {name} | {m['expected']} | {', '.join(m['observed'])} | {m['runs']} | "
            f"{m['pass_rate'] * 100:.0f} % | {m['duration_s']['median']:.1f} |"
        )
    (FIGURES / "attack_matrix.md").write_text("\n".join(lines) + "\n")
    print(f"  attack_matrix.md ← {run.name}")


def table_summary() -> None:
    """One markdown file with the headline numbers of every latest run (for the README/paper)."""
    lines = [
        "<!-- generated by evaluation/figures.py; every number traces to a results directory -->",
        "",
    ]
    for exp in sorted(p.name for p in RESULTS.iterdir() if p.is_dir()):
        run = latest(exp)
        if run is None:
            continue
        summary, _ = load(run)
        lines.append(f"## {exp} — `{run.relative_to(ROOT.parent)}`")
        block: dict[str, Any] = {}
        for key in ("overall", "per_size", "per_fleet_size", "point_estimates", "matrix", "llm"):
            if key in summary:
                block[key] = summary[key]
        lines.append("```json")
        lines.append(json.dumps(block, indent=1)[:6000])
        lines.append("```")
        lines.append("")
    (FIGURES / "SUMMARY.md").write_text("\n".join(lines))
    print("  SUMMARY.md")


def main() -> int:
    FIGURES.mkdir(exist_ok=True)
    runs = {
        exp: latest(exp)
        for exp in (
            "latency_stage1",
            "latency_stage2",
            "gas_per_verdict_vs_batched",
            "detection_f1",
            "sbom_ranking",
            "revocation_propagation",
            "attack_matrix",
        )
    }
    print("▶ figures from:")
    for exp, run in runs.items():
        print(f"  {exp}: {run.name if run else '— no results yet'}")
    fig_latency(runs["latency_stage1"], runs["latency_stage2"])
    fig_gas(runs["gas_per_verdict_vs_batched"])
    fig_detection(runs["detection_f1"])
    fig_sbom_ranking(runs["sbom_ranking"])
    fig_revocation(runs["revocation_propagation"])
    table_attack_matrix(runs["attack_matrix"])
    table_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
