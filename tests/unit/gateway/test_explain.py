"""LLM explainer (P6-05): strict schema, retry, disabled switch, IPFS pinning, service wiring."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fake_chain import FIXTURES, FakeChain, publish
from fastapi.testclient import TestClient

from verigate.common.crypto import KeyPair
from verigate.common.ipfs import LocalCidBackend
from verigate.common.settings import Settings
from verigate.gateway.api.main import create_app
from verigate.gateway.service import GatewayService
from verigate.gateway.stage2.explain import (
    MAX_DIFF_ITEMS,
    Explainer,
    ExplainInput,
    Rationale,
    SbomDiff,
    build_explainer,
    build_prompt,
    sbom_diff,
)
from verigate.gateway.stage2.scores import Stage2Scores
from verigate.ml.data.sbom import Component

SBOM_V1 = (FIXTURES / "v1.0.0" / "sbom.json").read_bytes()
SBOM_V2 = (FIXTURES / "v1.1.0" / "sbom.json").read_bytes()
GOOD = {"summary": "Routine update.", "top_risks": ["n_cves"], "recommended_action": "review"}


def ollama(answers: list[Any]) -> tuple[httpx.MockTransport, list[dict[str, Any]]]:
    """A fake ``/api/chat`` that pops one canned answer per call and records requests."""
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        answer = answers.pop(0)
        if isinstance(answer, int):
            return httpx.Response(answer, text="boom")
        if isinstance(answer, Exception):
            raise answer
        content = answer if isinstance(answer, str) else json.dumps(answer)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})

    return httpx.MockTransport(handler), seen


def explain_input(**overrides: Any) -> ExplainInput:
    base: dict[str, Any] = {
        "release_id": "0x" + "ab" * 32,
        "version": "1.1.0",
        "device_model": "demo-device",
        "diff": sbom_diff(SBOM_V2, SBOM_V1),
        "r_sbom_bp": 4823,
        "r_img_bp": 4026,
        "verdict": "DEFER",
        "top_sbom": [["sum_epss_x1e4", -155]],
        "top_img": [["n_segments", 1024]],
        "expected_exploited": 2.9,
        "cves": 79,
    }
    return ExplainInput(**{**base, **overrides})


def test_sbom_diff_and_prompt_are_bounded() -> None:
    diff = sbom_diff(SBOM_V2, SBOM_V1)
    assert diff.added and diff.removed and diff.changed
    assert ("busybox", "1.35.0-5", "1.36.1-1") in diff.changed
    doc = diff.to_json()
    assert doc["counts"] == {
        "added": len(diff.added),
        "removed": len(diff.removed),
        "changed": len(diff.changed),
    }
    assert len(doc["changed"]) == MAX_DIFF_ITEMS + 1 and doc["changed"][-1].startswith("... and ")
    assert sbom_diff(SBOM_V2, None).removed == () and sbom_diff(b"not json", SBOM_V1).added == ()
    small = SbomDiff((Component("a", "1"),), (), ()).to_json()
    assert small["added"] == ["a@1"] and small["changed"] == []
    prompt = build_prompt(explain_input())
    assert '"verdict_from_deterministic_gate":"DEFER"' in prompt and len(prompt) < 3000


def test_rationale_schema_is_strict() -> None:
    Rationale.model_validate(GOOD)
    for bad in (
        {**GOOD, "recommended_action": "yolo"},
        {**GOOD, "summary": ""},
        {**GOOD, "top_risks": ["x"] * 6},
        {**GOOD, "extra": 1},
        {"summary": "s", "top_risks": []},
    ):
        with pytest.raises(ValueError):
            Rationale.model_validate(bad)


def test_explainer_pins_validated_rationale(tmp_path: Path) -> None:
    transport, seen = ollama([GOOD])
    ipfs = LocalCidBackend(tmp_path)
    ex = Explainer("http://llm/", "m", ipfs, transport=transport)
    out = ex.explain(explain_input())
    assert out is not None and out.attempts == 1 and out.model == "m"
    assert json.loads(ipfs.get(out.cid)) == GOOD
    body = seen[0]
    assert body["model"] == "m" and body["stream"] is False and body["format"]["type"] == "object"
    assert body["options"] == {"temperature": 0, "seed": 42, "num_predict": 400}
    assert ex.explain(explain_input()) is out and len(seen) == 1  # cached per release


def test_explainer_retries_once_then_gives_up(tmp_path: Path) -> None:
    ipfs = LocalCidBackend(tmp_path)
    transport, seen = ollama([{"summary": "no action key", "top_risks": []}, GOOD])
    out = Explainer("http://llm", "m", ipfs, transport=transport).explain(explain_input())
    assert out is not None and out.attempts == 2 and len(seen) == 2

    for answers in (
        [500, httpx.ConnectError("down")],
        ["not json at all", {"summary": "x", "top_risks": [], "recommended_action": "delete"}],
    ):
        transport, seen = ollama(list(answers))
        ex = Explainer("http://llm", "m", ipfs, transport=transport)
        assert ex.explain(explain_input()) is None and len(seen) == 2
        assert ex.explain(explain_input()) is None and len(seen) == 2  # failure cached too


def test_disabled_explainer_never_calls_out(tmp_path: Path, settings: Settings) -> None:
    transport, seen = ollama([GOOD])
    ex = Explainer("http://llm", "m", LocalCidBackend(tmp_path), enabled=False, transport=transport)
    assert ex.explain(explain_input()) is None and seen == []
    built = build_explainer(settings.model_copy(update={"llm_enabled": False}), ex.ipfs)
    assert built.enabled is False and built.url == settings.ollama_url.rstrip("/")


class FakeScorer:
    """Stage-2 scores with model hashes so the explainer path is taken."""

    def score(self, firmware: bytes, sbom: bytes, previous: bytes | None = None) -> Stage2Scores:  # noqa: ARG002
        return Stage2Scores(
            r_sbom_bp=1000,
            r_img_bp=500,
            features={"sbom": {"n_cves": 3, "top3": [["n_cves", 40]]}},
            model_hashes=("0x" + "11" * 32,),
            cves=3,
        )


@pytest.fixture
def world(tmp_path: Path, settings: Settings) -> dict[str, Any]:
    chain = FakeChain()
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    key = KeyPair.generate()
    chain.add_publisher("did:verigate:x", key)
    fw = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
    rid1, _ = publish(chain, ipfs, key, "did:verigate:x", "1.0.0", fw, sbom=SBOM_V1)
    rid2, _ = publish(chain, ipfs, key, "did:verigate:x", "1.1.0", fw, sbom=SBOM_V2)
    service = GatewayService(settings=settings, chain=chain, ipfs=ipfs, state_dir=tmp_path / "s")  # type: ignore[arg-type]
    service.scorer = FakeScorer()
    return {"service": service, "ipfs": ipfs, "rid1": rid1, "rid2": rid2}


async def test_release_verify_waits_for_rationale_devices_do_not(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    gate = asyncio.Event()
    loop = asyncio.get_running_loop()

    seen_prompt: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_prompt.append(body["messages"][1]["content"])
        asyncio.run_coroutine_threadsafe(gate.wait(), loop).result(timeout=10)
        content = json.dumps({**GOOD, "summary": body["messages"][1]["content"][:40]})
        return httpx.Response(200, json={"message": {"content": content}})

    service.explainer = Explainer(
        "http://llm", "m", world["ipfs"], transport=httpx.MockTransport(handler)
    )
    await service.refresh_releases()  # what the listener does at start-up
    # A device-level verification starts the task but does not wait for it.
    from verigate.common.manifest import SemVer  # noqa: PLC0415
    from verigate.gateway.stage1.inputs import DeviceView  # noqa: PLC0415

    view = DeviceView("dev-1", "demo-device", SemVer(1, 0, 0))
    quick = await asyncio.wait_for(service.verify(world["rid2"], view), timeout=2)
    assert quick.scores is not None and quick.scores.rationale_cid is None
    assert quick.to_dict()["rationaleCid"] is None
    # The release-level verification waits for the same task; the next device call reuses it.
    gate.set()
    release = await service.verify(world["rid2"])
    assert release.scores is not None and release.scores.rationale_cid is not None
    pinned = json.loads(world["ipfs"].get(release.scores.rationale_cid))
    assert pinned["recommended_action"] == "review" and pinned["summary"].startswith("Facts")
    assert seen_prompt and '"changed":["' in seen_prompt[0]  # diff against the previous SBOM
    again = await service.verify(world["rid2"], view)
    assert again.scores is not None and again.scores.rationale_cid == release.scores.rationale_cid
    assert len(service._rationales) == 1  # noqa: SLF001 — one task per release
    # The diff the prompt was built from used the previous release's SBOM.
    assert (await service.previous_sbom(await service.bundle(world["rid2"]))) == SBOM_V1
    assert (await service.previous_sbom(await service.bundle(world["rid1"]))) is None


async def test_no_explainer_or_no_models_means_no_rationale(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    assert (await service.verify(world["rid2"])).scores.rationale_cid is None  # type: ignore[union-attr]
    service.explainer = Explainer("http://llm", "m", world["ipfs"], enabled=False)
    assert (await service.verify(world["rid2"])).scores.rationale_cid is None  # type: ignore[union-attr]
    assert service._rationales == {}  # noqa: SLF001


def test_rationale_endpoint(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    cid = world["ipfs"].put(json.dumps(GOOD).encode())
    bad = world["ipfs"].put(b"[1, 2]")
    with TestClient(create_app(service, start_listener=False)) as c:
        assert c.get(f"/rationales/{cid}").json() == {"cid": cid, **GOOD}
        assert c.get(f"/rationales/{bad}").status_code == 404
        assert c.get("/rationales/bafkreinotthere").status_code == 404
