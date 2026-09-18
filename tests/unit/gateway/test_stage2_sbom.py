"""Stage-2 SBOM scorer with a tiny ONNX model: scoring, caching, SHAP top-3, composition."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from verigate.common.errors import VerigateError
from verigate.common.settings import Settings
from verigate.gateway.stage2.sbom import SbomScorer, build_sbom_scorer, load_context
from verigate.gateway.stage2.scores import NullScorer, Stage2Scorer, build_scorer
from verigate.ml.data.sbom import Component
from verigate.ml.features.sbom_features import FEATURE_NAMES, CorpusContext
from verigate.ml.train import sbom as trainer
from verigate.ml.vulndb.cache import OfflineMissError
from verigate.ml.vulndb.kev import KevCatalogue

SBOM = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "busybox", "version": "1.30.1-1"},
            {"name": "dropbear", "version": "2019.78-1"},
        ],
    }
).encode()


class FakeOsv:
    def __init__(self, cves: dict[str, set[str]], offline: bool = False) -> None:
        self.cves = cves
        self.offline = offline

    def cves_for_many(self, components: list[Component]) -> dict[Component, frozenset[str]]:
        if self.offline:
            raise OfflineMissError("offline")
        return {c: frozenset(self.cves.get(c.name, set())) for c in components}

    def vuln(self, cve: str) -> Any:
        return type("Info", (), {"cvss": 9.8, "published": None})()


class FakeEpss:
    def get(self, cve: str) -> float:
        return 0.9


@pytest.fixture
def model_path(tmp_path: Path) -> Path:
    rng = np.random.default_rng(0)
    x = rng.integers(0, 50, size=(60, len(FEATURE_NAMES))).astype(np.float32)
    y = np.clip(
        x[:, FEATURE_NAMES.index("kev_count")] / 50.0 + x[:, FEATURE_NAMES.index("n_cves")] / 200.0,
        0,
        1,
    )
    model = trainer.train_model(x, y, 42)
    path = tmp_path / "sbom_risk.onnx"
    path.write_bytes(trainer.export_onnx(model, x.shape[1]))
    (tmp_path / "sbom_risk.context.json").write_text(
        json.dumps(
            {
                "latest_version": {"busybox": "1.36.1-1"},
                "first_seen": {"busybox@1.30.1-1": "2020-01-01"},
                "background": [float(v) for v in np.median(x, axis=0)],
                "feature_names": list(FEATURE_NAMES),
            }
        )
    )
    return path


def make_scorer(model_path: Path, osv: FakeOsv) -> SbomScorer:
    kev = KevCatalogue({"CVE-2021-0001": date(2022, 1, 1)}, "x")
    lookup = trainer.VulnLookup(osv, FakeEpss(), kev, date(2025, 1, 1))  # type: ignore[arg-type]
    context = load_context(model_path.with_suffix(".context.json"), date(2025, 1, 1))
    background = json.loads(model_path.with_suffix(".context.json").read_text())["background"]
    return SbomScorer(model_path, lookup, context, background)


def test_score_features_shap_and_cache(model_path: Path) -> None:
    scorer = make_scorer(model_path, FakeOsv({"busybox": {"CVE-2021-0001", "CVE-2021-0002"}}))
    result = scorer.score(SBOM)
    assert 0 <= result.r_sbom_bp <= 10_000
    assert result.model_hash.startswith("0x") and len(result.model_hash) == 66
    assert result.features["n_cves"] == 2 and result.features["kev_count"] == 1
    assert result.features["n_outdated"] == 1 and result.features["mean_dep_age_days"] > 1000
    assert len(result.top_features) == 3 and all(
        name in FEATURE_NAMES for name, _ in result.top_features
    )
    assert scorer.score(SBOM) is result  # cached by content
    assert scorer.score(SBOM) == scorer.score(SBOM)  # deterministic


def test_bad_sbom_and_offline(model_path: Path) -> None:
    scorer = make_scorer(model_path, FakeOsv({}))
    with pytest.raises(VerigateError, match="CycloneDX"):
        scorer.score(b"not json")
    offline = make_scorer(model_path, FakeOsv({}, offline=True))
    with pytest.raises(VerigateError, match="offline"):
        offline.score(SBOM)


def test_stage2_scorer_composition(model_path: Path) -> None:
    sbom = make_scorer(model_path, FakeOsv({"busybox": {"CVE-2021-0001"}}))
    scores = Stage2Scorer(sbom).score(b"fw", SBOM)
    assert scores.r_sbom_bp == sbom.score(SBOM).r_sbom_bp and scores.r_img_bp == 0
    assert scores.model_hashes == (sbom.model_hash,)
    assert (
        scores.features["sbom"]["model"] == sbom.model_hash
        and len(scores.features["sbom"]["top3"]) == 3
    )
    assert scores.feature_hash.startswith("0x")
    empty = Stage2Scorer(None).score(b"fw", SBOM)
    assert empty.r_sbom_bp == 0 and empty.model_hashes == () and empty.features == {}


def test_build_scorer_from_settings(
    model_path: Path, settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert isinstance(build_scorer(settings), NullScorer)
    assert build_sbom_scorer(settings) is None
    cfg = settings.model_copy(
        update={
            "models_dir": model_path.parent,
            "sbom_model": model_path.name,
            "vuln_cache_dir": model_path.parent / "vulndb",
        }
    )
    import verigate.gateway.stage2.sbom as mod  # noqa: PLC0415
    import verigate.ml.vulndb.epss as epss_mod  # noqa: PLC0415
    import verigate.ml.vulndb.kev as kev_mod  # noqa: PLC0415

    monkeypatch.setattr(epss_mod.EpssSnapshot, "load", classmethod(lambda cls, *a, **k: FakeEpss()))
    monkeypatch.setattr(
        kev_mod.KevCatalogue, "load", classmethod(lambda cls, *a, **k: KevCatalogue({}, "x"))
    )
    scorer = mod.build_sbom_scorer(cfg)
    assert isinstance(scorer, SbomScorer) and isinstance(scorer.context, CorpusContext)
    assert isinstance(build_scorer(cfg), Stage2Scorer)
