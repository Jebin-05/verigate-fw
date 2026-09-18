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


@data_app.command("snapshot")
def data_snapshot(
    sboms: Annotated[list[Path], typer.Argument(help="CycloneDX SBOMs the demo will score")],
    out: Annotated[Path, typer.Option("--out")] = Path("data/vulndb-demo"),
) -> None:
    """Export the vulnerability-cache entries the given SBOMs need (offline demo snapshot).

    Scores each SBOM through the configured SBOM model with a recording cache and copies every
    entry it touched (OSV queries + records, the EPSS snapshot of ``STAGE2_EPSS_DATE``, KEV) to
    ``--out``; point ``VULN_CACHE_DIR`` there with ``VULN_CACHE_ONLY=true`` for a demo without
    network access (Manual §16).
    """
    from verigate.gateway.stage2 import sbom as stage2  # noqa: PLC0415
    from verigate.ml.vulndb.cache import RecordingCache  # noqa: PLC0415

    settings = get_settings()
    configure_logging(settings)
    if not settings.sbom_model:
        raise typer.BadParameter("SBOM_MODEL must be configured")
    cache = RecordingCache(settings.vuln_cache_dir, offline=settings.vuln_cache_only)
    scorer = stage2.build_sbom_scorer(settings, cache=cache)
    assert scorer is not None  # noqa: S101 — guarded above
    scored = {str(path): scorer.score(path.read_bytes()).r_sbom_bp for path in sboms}
    copied = cache.export(out)
    _emit(
        {
            "out": str(out),
            "entries": copied,
            "scored": scored,
            "epssDate": settings.stage2_epss_date,
        }
    )


@data_app.command("images")
def data_images(
    sources: Annotated[Path, typer.Option("--sources")] = DATA_DIR / "sources.yaml",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = DATA_DIR,
) -> None:
    """Download the benign ELF corpus (OpenWrt package binaries) and refresh MANIFEST.sha256."""
    from verigate.ml.data.images import (  # noqa: PLC0415
        fetch_elf_corpus,
        load_image_sources,
        write_images_index,
    )
    from verigate.ml.data.sbom import write_manifest_sha256  # noqa: PLC0415

    configure_logging(get_settings())
    src = load_image_sources(sources)
    samples = fetch_elf_corpus(src, data_dir / "raw")
    rows = write_images_index(samples, data_dir / "processed", src)
    n = write_manifest_sha256(data_dir, data_dir / "MANIFEST.sha256")
    _emit(
        {
            "binaries": len(rows),
            "with_previous": sum(1 for r in rows if r["previous"]),
            "manifest_entries": n,
        }
    )


MODELS_DIR = Path("models")


@app.command("sbom")
def train_sbom(
    seed: Annotated[int, typer.Option("--seed")] = 42,
    t0: Annotated[
        str, typer.Option("--t0", help="feature snapshot date (EPSS/KEV as of)")
    ] = "2025-09-18",
    t1: Annotated[str, typer.Option("--t1", help="label date (EPSS snapshot)")] = "2026-09-17",
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
    epss_t1 = EpssSnapshot.load(settings.epss_url, d1, cache)
    kev = KevCatalogue.load(settings.kev_url, cache)
    rows = trainer.load_corpus(data_dir)
    dataset = trainer.build_dataset(
        rows, trainer.VulnLookup(osv, epss, kev, d0), trainer.VulnLookup(osv, epss_t1, kev, d1)
    )
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
    model_metrics = trainer.metrics(y_test, trainer.expected_from_ratio(x_test, onnx_pred))
    baseline_metrics = trainer.metrics(
        y_test, -np.log1p(-np.array([d["baseline_bp"] / 10_000 for d in test]).clip(0, 0.9999))
    )  # the baseline's composition mapped back to an expected-count scale (−ln(1 − p))

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
                "r_scale": trainer.R_SCALE,
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
        writer = csv.DictWriter(fh, fieldnames=list(dataset[0].keys()), lineterminator="\n")
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


@app.command("image")
def train_image(
    seed: Annotated[int, typer.Option("--seed")] = 42,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = DATA_DIR,
    models_dir: Annotated[Path, typer.Option("--models-dir")] = MODELS_DIR,
) -> None:
    """Train models/image_anomaly.onnx on benign binaries; evaluate per mutation class."""
    import csv  # noqa: PLC0415
    import hashlib  # noqa: PLC0415

    import numpy as np  # noqa: PLC0415

    from verigate.ml.features.image_features import FEATURE_NAMES  # noqa: PLC0415
    from verigate.ml.train import image as trainer  # noqa: PLC0415

    settings = get_settings()
    configure_logging(settings)
    samples = trainer.load_corpus(data_dir)
    if not samples:
        raise typer.Exit(
            code=_fail("no benign samples with a predecessor; run verigate-train data images")
        )
    benign = trainer.benign_rows(samples)
    tampered = trainer.tampered_rows(samples, seed)
    x_benign = trainer.matrix(benign)
    x_tampered = trainer.matrix(tampered)
    model = trainer.train_model(x_benign, seed)
    onnx_bytes = trainer.export_onnx(model, x_benign.shape[1])
    offset = float(model.offset_)
    everything = np.vstack([x_benign, x_tampered])
    sk = trainer.anomaly_scores(model, everything)
    ox = trainer.onnx_anomaly_scores(onnx_bytes, everything, offset)
    max_diff = float(np.max(np.abs(sk - ox)))
    if max_diff > 1e-5:
        raise typer.Exit(code=_fail(f"ONNX != sklearn (max abs diff {max_diff:.3e})"))
    calibration = trainer.calibrate(ox[: len(benign)])
    r_benign = calibration.r_img(ox[: len(benign)])
    r_tampered = calibration.r_img(ox[len(benign) :])
    metrics = trainer.per_class_metrics(r_benign, tampered, r_tampered, 0.5)

    models_dir.mkdir(parents=True, exist_ok=True)
    (models_dir / f"{trainer.MODEL_NAME}.onnx").write_bytes(onnx_bytes)
    (models_dir / f"{trainer.MODEL_NAME}.context.json").write_text(
        json.dumps(
            {
                "offset": offset,
                "s_median": calibration.s_median,
                "s_p99": calibration.s_p99,
                "feature_names": list(FEATURE_NAMES),
                "background": [float(v) for v in np.median(x_benign, axis=0)],
            },
            indent=1,
            sort_keys=True,
        )
        + "\n"
    )
    datasets_dir = data_dir / "processed" / "datasets"
    datasets_dir.mkdir(parents=True, exist_ok=True)
    csv_path = datasets_dir / f"{trainer.MODEL_NAME}_seed{seed}.csv"
    rows = [
        {**r, "r_img": float(v)}
        for r, v in zip(benign + tampered, np.concatenate([r_benign, r_tampered]), strict=True)
    ]
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    manifest_path = data_dir / "MANIFEST.sha256"
    data_sha = (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.is_file() else "n/a"
    )
    fields = trainer.card_fields(
        onnx_bytes, samples, benign, tampered, seed, calibration, metrics, max_diff, data_sha
    )
    trainer.write_card(models_dir / f"{trainer.MODEL_NAME}.card.md", fields)
    summary = {
        "model": str(models_dir / f"{trainer.MODEL_NAME}.onnx"),
        "model_hash": fields["model_hash"],
        "benign": len(benign),
        "tampered": len(tampered),
        "onnx_max_abs_diff": max_diff,
        "calibration": {"s_median": calibration.s_median, "s_p99": calibration.s_p99},
        "metrics": metrics,
        "dataset_csv": str(csv_path),
        "seed": seed,
    }
    (models_dir / f"{trainer.MODEL_NAME}.metrics.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    _emit(summary)


@app.command("all")
def train_all(seed: Annotated[int, typer.Option("--seed")] = 42) -> None:
    """Train every model: sbom_risk (P5) and image_anomaly (P6)."""
    train_sbom(seed=seed)
    train_image(seed=seed)


if __name__ == "__main__":
    app()
