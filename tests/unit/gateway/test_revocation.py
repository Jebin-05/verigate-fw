"""Model revocation flow (P6-06): stale query → successor swap by hash → replay → report."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.chain import STATUS_REVOKED
from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend
from verigate.common.manifest import SemVer
from verigate.common.settings import Settings
from verigate.gateway.api.main import create_app
from verigate.gateway.revocation import RevocationJob
from verigate.gateway.service import REFERENCE_DEVICE_ID, GatewayService
from verigate.gateway.stage1.inputs import DeviceView
from verigate.gateway.stage2.image import ImageScorer
from verigate.gateway.stage2.scores import NullScorer, Stage2Scorer, find_model_file, swap_model
from verigate.gateway.store import DeviceRecord
from verigate.ml.features.image_features import FEATURE_NAMES, as_vector, image_features
from verigate.ml.train import image as trainer

DID = "did:verigate:rev"
FW = {v: (FIXTURES / f"v{v}" / "firmware.bin").read_bytes() for v in ("1.0.0", "1.1.0", "2.0.0")}
GATEWAY_KEY = "0x" + "44" * 32


def write_model(path: Path, seed: int) -> str:
    """A tiny IsolationForest on the fixture binaries; returns its 0x hash."""
    x = np.array(
        [as_vector(image_features(FW[v], None)) for v in ("1.0.0", "1.1.0", "2.0.0")] * 4,
        dtype=np.float32,
    )
    model = trainer.train_model(x, seed, n_estimators=8, max_samples=6)
    onnx_bytes = trainer.export_onnx(model, x.shape[1])
    cal = trainer.calibrate(trainer.onnx_anomaly_scores(onnx_bytes, x, float(model.offset_)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(onnx_bytes)
    path.with_suffix(".context.json").write_text(
        json.dumps(
            {
                "offset": float(model.offset_),
                "s_median": cal.s_median,
                "s_p99": cal.s_p99,
                "feature_names": list(FEATURE_NAMES),
                "background": [float(v) for v in np.median(x, axis=0)],
            }
        )
    )
    return "0x" + hashlib.sha256(onnx_bytes).hexdigest()


@pytest.fixture(scope="module")
def models(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    root = tmp_path_factory.mktemp("models")
    v1 = write_model(root / "image_anomaly.onnx", 1)
    v2 = write_model(root / "successor" / "image_anomaly.onnx", 2)
    assert v1 != v2
    return {"dir": root, "v1": v1, "v2": v2}


@pytest.fixture
def world(tmp_path: Path, settings: Settings, models: dict[str, Any]) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    chain.add_publisher(DID, key)
    chain.add_model(bytes.fromhex(models["v1"][2:]))
    chain.add_model(bytes.fromhex(models["v2"][2:]))
    rid, _ = publish(chain, ipfs, key, DID, "1.0.0", FW["1.0.0"])
    cfg = settings.model_copy(
        update={
            "gateway_private_key": GATEWAY_KEY,
            "batch_max_size": 1,  # every verdict is its own committed batch
            "batch_max_wait_s": 60,
            "models_dir": models["dir"],
            "image_model": "image_anomaly.onnx",
            "stage2_model_hashes": models["v1"],
        }
    )
    service = GatewayService(settings=cfg, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state")  # type: ignore[arg-type]
    service.scorer = Stage2Scorer(
        None,
        ImageScorer(
            models["dir"] / "image_anomaly.onnx",
            json.loads((models["dir"] / "image_anomaly.context.json").read_text()),
        ),
    )
    service.devices.put(
        DeviceRecord("dev-1", "demo-device", "ed25519:" + "00" * 32, "0.9.0", 0, 0, None, 0)
    )
    job = RevocationJob(service, tmp_path / "state" / "revocations.json", poll_s=0.01)
    return {"chain": chain, "service": service, "job": job, "rid": rid, "cfg": cfg}


def test_find_model_file_and_swap(models: dict[str, Any], settings: Settings) -> None:
    root: Path = models["dir"]
    assert find_model_file(root, models["v2"]) == root / "successor" / "image_anomaly.onnx"
    assert find_model_file(root, models["v2"].upper()) is not None
    assert find_model_file(root, "0x" + "00" * 32) is None
    cfg = settings.model_copy(update={"models_dir": root, "image_model": "image_anomaly.onnx"})
    image = ImageScorer(
        root / "image_anomaly.onnx", json.loads((root / "image_anomaly.context.json").read_text())
    )
    scorer = Stage2Scorer(None, image)
    swapped = swap_model(scorer, cfg, models["v1"], models["v2"])
    assert isinstance(swapped, Stage2Scorer) and swapped.image is not None
    assert swapped.image.model_hash == models["v2"] and swapped.sbom is None
    assert swap_model(scorer, cfg, "0x" + "ab" * 32, models["v2"]) is None  # not in use
    assert swap_model(scorer, cfg, models["v1"], "0x" + "ab" * 32) is None  # no such file
    assert swap_model(NullScorer(), cfg, models["v1"], models["v2"]) is None


async def test_revocation_replays_stale_verdicts(
    world: dict[str, Any], models: dict[str, Any]
) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    job: RevocationJob = world["job"]
    await service.refresh_releases()
    first = await service.verify(world["rid"])
    second = await service.verify(world["rid"], DeviceView("dev-1", "demo-device", SemVer(0, 9, 0)))
    assert first.verdict.value == "APPROVE" and second.verdict.value == "APPROVE"
    v1, v2 = bytes.fromhex(models["v1"][2:]), bytes.fromhex(models["v2"][2:])
    assert [b["modelHashes"] for b in chain.committed] == [[v1], [v1]]
    assert await job.check_once() == []  # nothing revoked yet

    chain.revoke_model(bytes.fromhex(models["v1"][2:]), bytes.fromhex(models["v2"][2:]))
    # Until the job runs, the gate fails closed on the revoked model.
    rejected = await service.verify(world["rid"])
    assert rejected.verdict.value == "REJECT" and rejected.stage1 is not None
    assert rejected.stage1.failed == "model_active"

    reports = await job.check_once()
    assert len(reports) == 1
    report = reports[0]
    assert report.model_hash == models["v1"] and report.successor == models["v2"]
    assert report.swapped is True and report.error is None
    assert report.stale_batches == [0, 1]  # the REJECT batch did not use the model
    assert service.model_hashes() == (bytes.fromhex(models["v2"][2:]),)
    assert isinstance(service.scorer, Stage2Scorer)
    assert service.scorer.image is not None and service.scorer.image.model_hash == models["v2"]
    pairs = {(p.release_id, p.device_id): p for p in report.pairs}
    assert set(pairs) == {(first.release_id, REFERENCE_DEVICE_ID), (first.release_id, "dev-1")}
    for p in pairs.values():
        assert p.before == "APPROVE" and p.after == "APPROVE" and p.after_id != p.before_id
        assert p.r_after is not None
    assert chain.committed[-1]["modelHashes"] == [v2]
    assert await job.check_once() == []  # idempotent
    # Persisted and reloaded by a fresh job (a restart does not replay).
    again = RevocationJob(service, job.path)
    assert [r.to_dict() for r in again.reports] == [report.to_dict()]
    assert again.reports[0].to_dict()["changed"] == 0
    assert chain.get_model(bytes.fromhex(models["v1"][2:])).status == STATUS_REVOKED


async def test_revocation_without_successor_stays_closed(
    world: dict[str, Any], models: dict[str, Any]
) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    job: RevocationJob = world["job"]
    await service.refresh_releases()
    before = await service.verify(world["rid"])
    chain.revoke_model(bytes.fromhex(models["v1"][2:]))  # no successor
    (report,) = await job.check_once()
    assert report.swapped is False and report.stale_batches == [0]
    assert service.model_hashes() == (bytes.fromhex(models["v1"][2:]),)
    (pair,) = report.pairs
    assert (
        pair.before == "APPROVE" and pair.after == "REJECT" and pair.before_id == before.verdict_id
    )
    assert report.to_dict()["changed"] == 1


async def test_chain_outage_does_not_mark_handled(world: dict[str, Any]) -> None:
    chain: FakeChain = world["chain"]
    job: RevocationJob = world["job"]
    chain.down = True
    assert await job.check_once() == [] and job.handled() == set()


def test_revocation_endpoints(world: dict[str, Any], models: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    chain: FakeChain = world["chain"]
    with TestClient(create_app(service, start_listener=False)) as c:
        assert c.get("/revocations").json() == []
        assert c.post("/verify/" + "0x" + world["rid"].hex()).json()["verdict"] == "APPROVE"
        chain.revoke_model(bytes.fromhex(models["v1"][2:]), bytes.fromhex(models["v2"][2:]))
        (report,) = c.post("/revocations/check").json()
        assert report["swapped"] is True and report["pairs"][0]["after"] == "APPROVE"
        assert c.get("/revocations").json() == [report]
        assert c.post("/revocations/check").json() == []
