"""Trainer on a tiny synthetic corpus: split, determinism, ONNX == sklearn, card, context."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from verigate.ml.data.sbom import Component, cyclonedx
from verigate.ml.features.sbom_features import FEATURE_NAMES, VulnRecord
from verigate.ml.train import sbom as trainer
from verigate.ml.vulndb.kev import KevCatalogue


class FakeOsv:
    def __init__(self, table: dict[str, set[str]]) -> None:
        self.table = table

    def cves_for_many(self, components: list[Component]) -> dict[Component, frozenset[str]]:
        return {c: frozenset(self.table.get(c.name, set())) for c in components}

    def vuln(self, cve: str) -> Any:
        class Info:
            cvss = 7.5 if cve.endswith("1") else 9.8
            published = None

        return Info()


class FakeEpss:
    model_version = "test"
    date = date(2025, 1, 1)

    def get(self, cve: str) -> float:
        return 0.5 if cve.endswith("1") else 0.05


def make_corpus(tmp_path: Path, n_releases: int = 8) -> Path:
    data = tmp_path / "data"
    (data / "processed" / "sboms").mkdir(parents=True)
    index = []
    for i in range(n_releases):
        for target in ("x86", "arm"):
            comps = [
                Component("busybox", f"1.{30 + i}.0-1"),
                Component("dropbear", "2022.82-1"),
                Component(f"extra{i}", "1.0"),
            ]
            if i % 2:
                comps.append(Component("openssl", "1.1.1k-1"))
            doc = cyclonedx(f"openwrt-{target}", f"2{i}.0", comps, {})
            path = data / "processed" / "sboms" / f"r{i}-{target}.json"
            path.write_text(json.dumps(doc))
            index.append(
                {
                    "id": f"r{i}-{target}",
                    "release": f"2{i}.0",
                    "target": target,
                    "released_at": f"202{i % 5}-0{1 + i % 8}-15",
                    "sbom": str(path.relative_to(data)),
                    "components": len(comps),
                }
            )
    (data / "processed" / "index.json").write_text(json.dumps(index))
    (data / "MANIFEST.sha256").write_text("abc  x\n")
    return data


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    return make_corpus(tmp_path)


def test_corpus_context_and_lookup(corpus: Path) -> None:
    rows = trainer.load_corpus(corpus)
    assert len(rows) == 16 and rows[0].released_at <= rows[-1].released_at
    ctx = trainer.corpus_context(rows, date(2026, 1, 1))
    assert ctx.latest_version["busybox"].startswith("1.3")
    assert ("dropbear", "2022.82-1") in ctx.first_seen
    kev = KevCatalogue({"CVE-2021-0001": date(2022, 1, 1)}, "x")
    lookup = trainer.VulnLookup(
        FakeOsv({"busybox": {"CVE-2021-0001", "CVE-2021-0002"}, "openssl": {"CVE-2021-0002"}}),
        FakeEpss(),
        kev,
        date(2025, 1, 1),
    )  # type: ignore[arg-type]
    records = lookup.records(rows[0].components)
    assert len(records[Component("busybox", rows[0].components[0].version)]) == 2
    assert records[Component("dropbear", "2022.82-1")] == []
    assert isinstance(next(iter(records.values()))[0], VulnRecord)
    assert trainer.kev_exposure(records, kev, date(2025, 1, 1)) == 0.5
    assert trainer.kev_exposure({}, kev, date(2025, 1, 1)) == 0.0


def test_build_split_train_export_deterministic(corpus: Path, tmp_path: Path) -> None:
    rows = trainer.load_corpus(corpus)
    kev = KevCatalogue({"CVE-2021-0001": date(2022, 1, 1), "CVE-2021-0002": date(2025, 6, 1)}, "x")
    lookup = trainer.VulnLookup(
        FakeOsv(
            {
                "busybox": {"CVE-2021-0001", "CVE-2021-0002"},
                "openssl": {"CVE-2021-0002", "CVE-2021-0003"},
            }
        ),
        FakeEpss(),
        kev,
        date(2025, 1, 1),
    )  # type: ignore[arg-type]
    dataset = trainer.build_dataset(rows, lookup, kev, date(2026, 1, 1))
    assert len(dataset) == 16 and set(FEATURE_NAMES) <= set(dataset[0])
    assert all(0.0 <= d["label"] <= 1.0 for d in dataset) and all(
        0 <= d["baseline_bp"] <= 10_000 for d in dataset
    )
    train, test = trainer.temporal_split(dataset, 0.25)
    assert len(train) + len(test) == 16 and {d["release"] for d in train}.isdisjoint(
        {d["release"] for d in test}
    )
    assert max(d["released_at"] for d in train) <= min(d["released_at"] for d in test)
    x, y = trainer.matrix(train)
    assert x.shape == (len(train), len(FEATURE_NAMES)) and x.dtype == np.float32
    model_a = trainer.train_model(x, y, 42)
    model_b = trainer.train_model(x, y, 42)
    onnx_a, onnx_b = (
        trainer.export_onnx(model_a, x.shape[1]),
        trainer.export_onnx(model_b, x.shape[1]),
    )
    assert onnx_a == onnx_b  # byte-identical models from the same seed and data
    x_test, y_test = trainer.matrix(test)
    diff = np.abs(model_a.predict(x_test) - trainer.onnx_predict(onnx_a, x_test)).max()
    assert diff <= 1e-6
    m = trainer.metrics(y_test, trainer.onnx_predict(onnx_a, x_test))
    assert "mae" in m and "median_ae" in m
    fields = trainer.card_fields(
        onnx_a,
        dataset,
        train,
        test,
        42,
        date(2025, 1, 1),
        date(2026, 1, 1),
        m,
        {"mae": 0.1},
        float(diff),
        "sha",
        "epss-v",
        "kev-rel",
    )
    card = tmp_path / "card.md"
    trainer.write_card(card, fields)
    text = card.read_text()
    assert "sbom_risk.onnx" in text and "KEV exposure" in text and "| mae |" in text
    assert fields["model_hash"] in text and "mean_dep_age_days" in text
    assert trainer.git_sha()


def test_metrics_edge_cases() -> None:
    m = trainer.metrics(np.array([0.0, 0.0]), np.array([0.1, 0.2]))
    assert "spearman" not in m and "auroc_any_kev" not in m
    m2 = trainer.metrics(np.array([0.0, 0.5, 1.0, 0.2]), np.array([0.1, 0.4, 0.9, 0.3]))
    assert m2["spearman"] > 0.9 and m2["auroc_any_kev"] == 1.0
