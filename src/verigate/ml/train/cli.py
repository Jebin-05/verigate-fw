"""``verigate-train`` — dataset pipeline and model training (seeded, ONNX export, model cards)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from verigate.common.logging import configure_logging
from verigate.common.settings import get_settings

app = typer.Typer(
    help="Data pipeline and model training.", add_completion=False, pretty_exceptions_enable=False
)
data_app = typer.Typer(help="Dataset pipeline (data/sources.yaml → data/raw → data/processed).")
app.add_typer(data_app, name="data")

DATA_DIR = Path("data")


@app.callback()
def main() -> None:
    """Training entry point (``verigate-train all --seed 42``)."""


def _emit(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


@data_app.command("fetch")
def data_fetch(
    sources: Annotated[Path, typer.Option("--sources")] = DATA_DIR / "sources.yaml",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = DATA_DIR,
) -> None:
    """Download every pinned upstream manifest into data/raw (idempotent)."""
    from verigate.ml.data.sources import fetch_manifests, load_sources  # noqa: PLC0415

    configure_logging(get_settings())
    manifests = fetch_manifests(load_sources(sources), data_dir / "raw")
    _emit({"manifests": len(manifests), "raw_dir": str(data_dir / "raw" / "openwrt")})


@data_app.command("sbom")
def data_sbom(
    sources: Annotated[Path, typer.Option("--sources")] = DATA_DIR / "sources.yaml",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = DATA_DIR,
) -> None:
    """Convert fetched manifests to CycloneDX SBOMs and write data/MANIFEST.sha256."""
    from verigate.ml.data.sbom import write_manifest_sha256, write_sboms  # noqa: PLC0415
    from verigate.ml.data.sources import fetch_manifests, load_sources  # noqa: PLC0415

    configure_logging(get_settings())
    manifests = fetch_manifests(
        load_sources(sources), data_dir / "raw"
    )  # cache hits only after fetch
    index = write_sboms(manifests, data_dir / "processed")
    n = write_manifest_sha256(data_dir, data_dir / "MANIFEST.sha256")
    _emit(
        {
            "sboms": len(index),
            "manifest_entries": n,
            "index": str(data_dir / "processed" / "index.json"),
        }
    )


MODELS_DIR = Path("models")


@app.command("sbom")
def train_sbom(
    seed: Annotated[int, typer.Option("--seed")] = 42,
    t0: Annotated[
        str, typer.Option("--t0", help="feature snapshot date (EPSS/KEV as of)")
    ] = "2025-09-18",
    t1: Annotated[str, typer.Option("--t1", help="label date (KEV as of)")] = "2026-09-18",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = DATA_DIR,
    models_dir: Annotated[Path, typer.Option("--models-dir")] = MODELS_DIR,
    test_fraction: Annotated[float, typer.Option("--test-fraction", min=0.05, max=0.5)] = 0.2,
) -> None:
    """Train models/sbom_risk.onnx from the corpus (seeded, deterministic) and write its card."""
    import csv  # noqa: PLC0415
    import hashlib  # noqa: PLC0415
    from datetime import date  # noqa: PLC0415

    import numpy as np  # noqa: PLC0415

    from verigate.ml.features.sbom_features import FEATURE_NAMES  # noqa: PLC0415
    from verigate.ml.train import sbom as trainer  # noqa: PLC0415
    from verigate.ml.vulndb.cache import DiskCache  # noqa: PLC0415
    from verigate.ml.vulndb.epss import EpssSnapshot  # noqa: PLC0415
    from verigate.ml.vulndb.kev import KevCatalogue  # noqa: PLC0415
    from verigate.ml.vulndb.osv import OsvClient  # noqa: PLC0415

    settings = get_settings()
    configure_logging(settings)
    d0, d1 = date.fromisoformat(t0), date.fromisoformat(t1)
    cache = DiskCache(settings.vuln_cache_dir, offline=settings.vuln_cache_only)
    osv = OsvClient(settings.osv_api, cache)
    epss = EpssSnapshot.load(settings.epss_url, d0, cache)
    kev = KevCatalogue.load(settings.kev_url, cache)
    rows = trainer.load_corpus(data_dir)
    dataset = trainer.build_dataset(rows, trainer.VulnLookup(osv, epss, kev, d0), kev, d1)
    train, test = trainer.temporal_split(dataset, test_fraction)
    x_train, y_train = trainer.matrix(train)
    x_test, y_test = trainer.matrix(test)
    model = trainer.train_model(x_train, y_train, seed)
    onnx_bytes = trainer.export_onnx(model, x_train.shape[1])
    sk_pred = np.asarray(model.predict(x_test), dtype=np.float64)
    onnx_pred = trainer.onnx_predict(onnx_bytes, x_test)
    max_diff = float(np.max(np.abs(sk_pred - onnx_pred))) if len(x_test) else 0.0
    if max_diff > 1e-6:
        raise typer.Exit(
            code=_fail(f"ONNX != sklearn on the test set (max abs diff {max_diff:.3e})")
        )
    model_metrics = trainer.metrics(y_test, np.clip(onnx_pred, 0.0, 1.0))
    baseline_metrics = trainer.metrics(y_test, np.array([d["baseline_bp"] / 10_000 for d in test]))

    models_dir.mkdir(parents=True, exist_ok=True)
    (models_dir / f"{trainer.MODEL_NAME}.onnx").write_bytes(onnx_bytes)
    context = trainer.corpus_context(rows, d0)
    (models_dir / f"{trainer.MODEL_NAME}.context.json").write_text(
        json.dumps(
            {
                "latest_version": dict(sorted(context.latest_version.items())),
                "first_seen": {
                    f"{n}@{v}": d.isoformat() for (n, v), d in sorted(context.first_seen.items())
                },
                "background": [float(m) for m in np.median(x_train, axis=0)],
                "feature_names": list(FEATURE_NAMES),
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    datasets_dir = data_dir / "processed" / "datasets"
    datasets_dir.mkdir(parents=True, exist_ok=True)
    csv_path = datasets_dir / f"{trainer.MODEL_NAME}_{t0}_{t1}.csv"
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(dataset[0].keys()))
        writer.writeheader()
        writer.writerows(dataset)
    manifest_path = data_dir / "MANIFEST.sha256"
    data_sha = (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else "n/a"
    )
    fields = trainer.card_fields(
        onnx_bytes,
        dataset,
        train,
        test,
        seed,
        d0,
        d1,
        model_metrics,
        baseline_metrics,
        max_diff,
        data_sha,
        epss.model_version,
        kev.released,
    )
    trainer.write_card(models_dir / f"{trainer.MODEL_NAME}.card.md", fields)
    summary = {
        "model": str(models_dir / f"{trainer.MODEL_NAME}.onnx"),
        "model_hash": fields["model_hash"],
        "rows": len(dataset),
        "train_rows": len(train),
        "test_rows": len(test),
        "onnx_max_abs_diff": max_diff,
        "metrics": {"model": model_metrics, "baseline": baseline_metrics},
        "dataset_csv": str(csv_path),
        "seed": seed,
        "t0": t0,
        "t1": t1,
    }
    (models_dir / f"{trainer.MODEL_NAME}.metrics.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    _emit(summary)


def _fail(message: str) -> int:
    _emit({"error": message})
    return 1


@app.command("all")
def train_all(seed: Annotated[int, typer.Option("--seed")] = 42) -> None:
    """Train every model (P5: sbom_risk; P6 adds image_anomaly)."""
    train_sbom(seed=seed)


if __name__ == "__main__":
    app()
