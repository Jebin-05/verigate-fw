"""LLM explainer (P6-05): strict schema, retry, disabled switch, IPFS pinning, service wiring."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

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
    ACTION_FOR_VERDICT,
    MAX_DIFF_ITEMS,
    RATIONALE_SCHEMA,
    Explainer,
    ExplainInput,
    Rationale,
    SbomDiff,
    build_explainer,
    build_prompt,
    sbom_diff,
)
from verigate.gateway.stage2.scores import Stage2Scores
from verigate.gateway.verdicts.types import Verdict
from verigate.ml.data.sbom import Component

SBOM_V1 = (FIXTURES / "v1.0.0" / "sbom.json").read_bytes()
SBOM_V2 = (FIXTURES / "v1.1.0" / "sbom.json").read_bytes()
GOOD = {"summary": "Routine update.", "top_risks": ["n_cves"], "recommended_action": "review"}


def completion(content: str) -> dict[str, Any]:
    """An OpenRouter ``/chat/completions`` body carrying ``content``."""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def openrouter(answers: list[Any]) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """A fake ``/chat/completions`` that pops one canned answer per call and records requests."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = answers.pop(0)
        if isinstance(answer, int):
            return httpx.Response(answer, text="boom")
        if isinstance(answer, Exception):
            raise answer
        content = answer if isinstance(answer, str) else json.dumps(answer)
        return httpx.Response(200, json=completion(content))

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
    assert '"verdict from the deterministic gate":"DEFER"' in prompt and len(prompt) < 3000


@pytest.mark.parametrize(
    ("check", "reason", "words"),
    [
        ("firmware_hash", "hash mismatch", "not the file the publisher signed"),
        ("registry_record", "release revoked in FirmwareRegistry", "withdrawn"),
        ("publisher_active", "publisher revoked at block 9", "key has been revoked"),
        ("model_active", "model 0xabcdef… revoked", "inspection models"),
        ("expiry", "expired at 2020-01-01", "expiry date"),
    ],
)
def test_stopped_prompt_names_the_failed_check_and_no_scores(
    check: str, reason: str, words: str
) -> None:
    verdict = "DEFER" if check == "expiry" else "REJECT"
    inp = explain_input(
        r_sbom_bp=None,
        r_img_bp=None,
        verdict=verdict,
        top_sbom=[],
        top_img=[],
        stopped_at=check,
        stop_reason=reason,
        passed_checks=("firmware_hash",) if check != "firmware_hash" else (),
    )
    prompt = build_prompt(inp)
    assert words in prompt and "did not run" in prompt
    assert "0xabcdef" not in prompt and "scores from 0 to 1" not in prompt
    assert f"must be '{ACTION_FOR_VERDICT[verdict]}'" in prompt


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
    transport, seen = openrouter([GOOD])
    ipfs = LocalCidBackend(tmp_path)
    ex = Explainer("http://llm/", "m", ipfs, api_key="sk-test", transport=transport)
    out = ex.explain(explain_input())
    assert out is not None and out.attempts == 1 and out.model == "m"
    assert json.loads(ipfs.get(out.cid)) == GOOD
    request = seen[0]
    assert str(request.url) == "http://llm/chat/completions"
    assert request.headers["authorization"] == "Bearer sk-test"
    body = json.loads(request.content)
    assert body["model"] == "m" and body["provider"] == {"require_parameters": True}
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["response_format"]["json_schema"]["schema"] == RATIONALE_SCHEMA
    assert (body["temperature"], body["seed"], body["max_tokens"]) == (0, 42, 400)
    assert ex.explain(explain_input()) is out and len(seen) == 1  # cached per release


@pytest.mark.parametrize("status", [401, 402, 403])
def test_refused_credentials_back_off_without_retry(tmp_path: Path, status: int) -> None:
    transport, seen = openrouter([status, GOOD])
    ex = Explainer("http://llm", "m", LocalCidBackend(tmp_path), transport=transport)
    assert ex.explain(explain_input()) is None and len(seen) == 1
    ex._unavailable_until = 0.0  # noqa: SLF001 — cooldown elapsed
    assert ex.explain(explain_input()) is not None and len(seen) == 2  # was not cached as failed


def test_explainer_retries_once_then_gives_up(tmp_path: Path) -> None:
    ipfs = LocalCidBackend(tmp_path)
    transport, seen = openrouter([{"summary": "no action key", "top_risks": []}, GOOD])
    out = Explainer("http://llm", "m", ipfs, transport=transport).explain(explain_input())
    assert out is not None and out.attempts == 2 and len(seen) == 2

    for answers in (
        [500, httpx.ConnectError("down")],
        ["not json at all", {"summary": "x", "top_risks": [], "recommended_action": "delete"}],
    ):
        transport, seen = openrouter(list(answers))
        ex = Explainer("http://llm", "m", ipfs, transport=transport)
        assert ex.explain(explain_input()) is None and len(seen) == 2
        assert ex.explain(explain_input()) is None and len(seen) == 2  # failure cached too


def test_disabled_explainer_never_calls_out(tmp_path: Path, settings: Settings) -> None:
    transport, seen = openrouter([GOOD])
    ex = Explainer("http://llm", "m", LocalCidBackend(tmp_path), enabled=False, transport=transport)
    assert ex.explain(explain_input()) is None and seen == []
    keyed = settings.model_copy(update={"llm_enabled": True, "openrouter_api_key": "sk-test"})
    built = build_explainer(keyed.model_copy(update={"llm_enabled": False}), ex.ipfs)
    assert built.enabled is False and built.url == settings.openrouter_url.rstrip("/")
    assert build_explainer(keyed, ex.ipfs).enabled is True
    # No key: switched off rather than failing every request.
    no_key = settings.model_copy(update={"llm_enabled": True, "openrouter_api_key": " "})
    assert build_explainer(no_key, ex.ipfs).enabled is False


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


async def test_rationale_never_blocks_a_verdict_and_is_picked_up_later(
    world: dict[str, Any],
) -> None:
    service: GatewayService = world["service"]
    service.settings = service.settings.model_copy(update={"llm_auto_explain": True})
    gate = asyncio.Event()
    loop = asyncio.get_running_loop()

    seen_prompt: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_prompt.append(body["messages"][1]["content"])
        asyncio.run_coroutine_threadsafe(gate.wait(), loop).result(timeout=10)
        content = json.dumps({**GOOD, "summary": body["messages"][1]["content"][:40]})
        return httpx.Response(200, json=completion(content))

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
    rid_hex = "0x" + world["rid2"].hex()
    assert (await service.rationale_status(rid_hex))["status"] == "writing"
    # The release-level verification does not wait either (ADR-0002 amendment): the first verdict
    # goes out without a CID and the explanation is picked up once the background task is done.
    gate.set()
    release = await service.verify(world["rid2"])
    assert release.scores is not None
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    status = await service.rationale_status(rid_hex)
    # The writer answered "review"; the pinned action follows the verdict (APPROVE → install).
    assert status["status"] == "ready" and status["rationale"]["recommended_action"] == "install"
    pinned = json.loads(world["ipfs"].get(status["cid"]))
    assert pinned["summary"].startswith("Facts") and pinned["recommended_action"] == "install"
    assert "must be 'install'" in seen_prompt[0]
    assert seen_prompt and '"changed":["' in seen_prompt[0]  # diff against the previous SBOM
    again = await service.verify(world["rid2"], view)
    assert again.scores is not None and again.scores.rationale_cid == status["cid"]
    later = await service.verify(world["rid2"])
    assert later.scores is not None and later.scores.rationale_cid == status["cid"]
    assert len(service._rationales) == 1  # noqa: SLF001 — one task per release
    # The diff the prompt was built from used the previous release's SBOM.
    assert (await service.previous_sbom(await service.bundle(world["rid2"]))) == SBOM_V1
    assert (await service.previous_sbom(await service.bundle(world["rid1"]))) is None


async def test_no_explainer_or_no_models_means_no_rationale(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    assert (await service.verify(world["rid2"])).scores.rationale_cid is None  # type: ignore[union-attr]
    assert (await service.rationale_status("0x" + world["rid2"].hex()))["status"] == "off"
    service.explainer = Explainer("http://llm", "m", world["ipfs"], enabled=False)
    assert (await service.verify(world["rid2"])).scores.rationale_cid is None  # type: ignore[union-attr]
    assert service._rationales == {}  # noqa: SLF001
    assert (await service.rationale_status("0x" + world["rid2"].hex()))["status"] == "off"


def test_rationale_endpoint(world: dict[str, Any]) -> None:
    service: GatewayService = world["service"]
    cid = world["ipfs"].put(json.dumps(GOOD).encode())
    bad = world["ipfs"].put(b"[1, 2]")
    with TestClient(create_app(service, start_listener=False)) as c:
        assert c.get(f"/rationales/{cid}").json() == {"cid": cid, **GOOD}
        assert c.get(f"/rationales/{bad}").status_code == 404
        assert c.get("/rationales/bafkreinotthere").status_code == 404


def test_connection_failure_backs_off_without_caching(tmp_path: Path) -> None:
    transport, seen = openrouter([httpx.ConnectError("refused"), GOOD])
    ex = Explainer("http://llm", "m", LocalCidBackend(tmp_path), transport=transport)
    assert ex.explain(explain_input()) is None and len(seen) == 1  # no retry on connect errors
    assert ex.explain(explain_input(release_id="0x" + "cd" * 32)) is None and len(seen) == 1
    ex._unavailable_until = 0.0  # noqa: SLF001 — cooldown elapsed
    assert ex.explain(explain_input()) is not None and len(seen) == 2  # was not cached as failed


async def test_explanation_on_request_only(world: dict[str, Any]) -> None:
    """Default (``LLM_AUTO_EXPLAIN=false``): verdicts never start the writer; the button does."""
    service: GatewayService = world["service"]
    assert service.settings.llm_auto_explain is False
    answers: list[Any] = [httpx.ConnectError("refused"), GOOD, GOOD]
    calls = 0
    prompts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        prompts.append(json.loads(request.content)["messages"][1]["content"])
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return httpx.Response(200, json=completion(json.dumps(answer)))

    service.explainer = Explainer(
        "http://llm", "m", world["ipfs"], transport=httpx.MockTransport(handler)
    )
    await service.refresh_releases()
    rid_hex = "0x" + world["rid2"].hex()
    first = await service.verify(world["rid2"])
    assert first.scores is not None and first.scores.rationale_cid is None
    assert (await service.rationale_status(rid_hex))["status"] == "none"
    assert service._rationales == {}  # noqa: SLF001 — nothing started by the verdict
    # First request: OpenRouter is unreachable → failed, and nothing is cached for that.
    assert (await service.explain_now(rid_hex))["status"] in {"writing", "failed"}
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    assert (await service.rationale_status(rid_hex))["status"] == "failed"
    # Asking again after a failure discards the attempt and asks the model again.
    assert (await service.explain_now(rid_hex, again=True))["status"] in {"writing", "ready"}
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    status = await service.rationale_status(rid_hex)
    assert status["status"] == "ready" and status["rationale"]["summary"] == GOOD["summary"]
    # A finished explanation is returned, not rewritten, unless ``again`` is asked for.
    assert (await service.explain_now(rid_hex))["cid"] == status["cid"]
    assert calls == 2
    # The next verdict picks the CID up even though it never started the writer itself.
    later = await service.verify(world["rid2"])
    assert later.scores is not None and later.scores.rationale_cid == status["cid"]
    # A release that Stage 1 stops is explained from the failed check; no scores are invented.
    from verigate.gateway.stage1.checks import CheckResult  # noqa: PLC0415
    from verigate.gateway.stage1.runner import Stage1Result  # noqa: PLC0415

    stopped = Stage1Result(
        ok=False,
        results=(CheckResult("firmware_hash", True), CheckResult("signature", False, "bad sig")),
        failed="signature",
        reason="bad sig",
        outcome=Verdict.REJECT,
    )
    rid1_hex = "0x" + world["rid1"].hex()
    with patch("verigate.gateway.service.run_stage1", return_value=stopped):
        assert (await service.explain_now(rid1_hex))["status"] in {"writing", "ready"}
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    status = await service.rationale_status(rid1_hex)
    # The writer answered "review"; the pinned action follows the REJECT verdict.
    assert status["status"] == "ready" and status["rationale"]["recommended_action"] == "block"
    assert calls == 3
    assert "the signature does not verify" in prompts[-1]
    assert "the firmware file matches its fingerprint" in prompts[-1]  # passed before it
    assert "ingredient list risk" not in prompts[-1] and "must be 'block'" in prompts[-1]


async def test_recorded_rejection_is_explained_as_recorded(world: dict[str, Any]) -> None:
    """A release rejected by the checks is explained as the console shows it, even if re-running
    the gate today would pass (e.g. the revoked model it was rejected for has been replaced)."""
    from verigate.gateway.stage1.checks import CheckResult  # noqa: PLC0415
    from verigate.gateway.stage1.runner import Stage1Result  # noqa: PLC0415

    service: GatewayService = world["service"]
    prompts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        prompts.append(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(200, json=completion(json.dumps(GOOD)))

    service.explainer = Explainer(
        "http://llm", "m", world["ipfs"], transport=httpx.MockTransport(handler)
    )
    await service.refresh_releases()
    stopped = Stage1Result(
        ok=False,
        results=(CheckResult("firmware_hash", True), CheckResult("model_active", False, "revoked")),
        failed="model_active",
        reason="model 0xabc… revoked",
        outcome=Verdict.REJECT,
    )
    with patch("verigate.gateway.service.run_stage1", return_value=stopped):
        recorded = await service.verify(world["rid2"])
    assert recorded.verdict is Verdict.REJECT
    rid_hex = "0x" + world["rid2"].hex()
    await service.explain_now(rid_hex)  # the real checks would pass now
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    status = await service.rationale_status(rid_hex)
    assert status["status"] == "ready" and status["rationale"]["recommended_action"] == "block"
    assert "inspection models" in prompts[0] and "scores from 0 to 1" not in prompts[0]


def test_prompt_explains_why_the_ai_judged_it_with_values() -> None:
    inp = explain_input(
        top_sbom=[["max_cvss_x10", 900], ["mean_dep_age_days", -120]],
        sbom_values={"max_cvss_x10": 98, "mean_dep_age_days": 412},
    )
    prompt = build_prompt(inp)
    assert "highest severity rating = 9.8 (pushed the risk up)" in prompt
    assert "age of the packages = 412 (pushed the risk down)" in prompt
    assert '"risk":"moderate (0.48 of 1)"' in prompt  # r_sbom_bp=4823
    assert "judged this release safe or risky" in prompt
    assert "overall risk" in build_prompt(explain_input(overall_bp=4371))
    assert "low (0.44 of 1)" in build_prompt(explain_input(overall_bp=4371))


async def test_ai_analysis_on_request_for_a_stopped_release(world: dict[str, Any]) -> None:
    """The AI button scores a release the checks stopped; the verdict is untouched and the
    explanation then describes both the failed check and the models' view."""
    from verigate.gateway.stage1.checks import CheckResult  # noqa: PLC0415
    from verigate.gateway.stage1.runner import Stage1Result  # noqa: PLC0415

    service: GatewayService = world["service"]
    prompts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        prompts.append(json.loads(request.content)["messages"][1]["content"])
        return httpx.Response(200, json=completion(json.dumps(GOOD)))

    service.explainer = Explainer(
        "http://llm", "m", world["ipfs"], transport=httpx.MockTransport(handler)
    )
    await service.refresh_releases()
    stopped = Stage1Result(
        ok=False,
        results=(CheckResult("firmware_hash", False, "hash mismatch"),),
        failed="firmware_hash",
        reason="hash mismatch",
        outcome=Verdict.REJECT,
    )
    with patch("verigate.gateway.service.run_stage1", return_value=stopped):
        await service.verify(world["rid2"])
    rid_hex = "0x" + world["rid2"].hex()
    logged = len(service.verdicts.recent(1000))
    assert service.analysis_status(rid_hex) == {"status": "none"}

    # An explanation written before the analysis says the models did not run …
    await service.explain_now(rid_hex)
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    assert "did not run" in prompts[-1]

    result = await service.analyse_now(rid_hex)
    assert result["status"] == "ready" and result["rSbom"] == 1000 and result["rImg"] == 500
    assert result["verdictFromScores"] == "APPROVE"
    assert service.analysis_status(rid_hex) == result
    assert len(service.verdicts.recent(1000)) == logged  # never enters the verdict log
    # … and is dropped, so the next one describes the models' view too.
    assert (await service.rationale_status(rid_hex))["status"] == "none"
    await service.explain_now(rid_hex)
    await asyncio.gather(*service._rationales.values())  # noqa: SLF001
    assert "run on request after the decision" in prompts[-1]
    assert "number of known vulnerabilities = 3 (pushed the risk up)" in prompts[-1]
    status = await service.rationale_status(rid_hex)
    assert status["rationale"]["recommended_action"] == "block"  # still the gate's verdict

    with TestClient(create_app(service, start_listener=False)) as c:
        assert c.get(f"/releases/{rid_hex}/analysis").json()["status"] == "ready"
        assert c.post(f"/releases/{rid_hex}/analyse").json()["verdictFromScores"] == "APPROVE"
