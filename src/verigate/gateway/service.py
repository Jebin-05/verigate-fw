"""The gateway verifier: fetch inputs, run the gate, serve devices (Guide §4, Phase B).

Blocking clients (web3, IPFS) are called through ``asyncio.to_thread`` so the API stays async.
Everything that can fail on the way in (chain, IPFS) turns into a ``DEFER`` verdict, never an
exception that leaks ``APPROVE`` by omission.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient, ModelRecord, PublisherRecord, ReleaseRecord
from verigate.common.crypto import parse_signature, sha256, verify
from verigate.common.errors import ChainError, IpfsError, VerificationError, VerigateError
from verigate.common.ipfs import IpfsBackend
from verigate.common.logging import get_logger
from verigate.common.manifest import SemVer, SignedManifest
from verigate.common.protocol import InstallReceipt, SignedMessage, verify_message
from verigate.common.settings import Settings
from verigate.gateway.policy.engine import BASIS, Decision, PolicyEngine
from verigate.gateway.reputation import ReputationUpdater
from verigate.gateway.stage1.checks import CheckResult
from verigate.gateway.stage1.inputs import DeviceView, Stage1Input
from verigate.gateway.stage1.runner import Stage1Result, run_stage1
from verigate.gateway.stage2.explain import (
    AiReading,
    Explainer,
    ExplainInput,
    Explanation,
    SbomDiff,
    sbom_diff,
)
from verigate.gateway.stage2.scores import NullScorer, Scorer, Stage2Scores, swap_model
from verigate.gateway.store import (
    Cursor,
    DeviceRecord,
    DeviceStore,
    Review,
    ReviewStore,
    VerdictLog,
)
from verigate.gateway.verdicts.batch import VerdictBatcher
from verigate.gateway.verdicts.record import VerdictRecord, feature_hash
from verigate.gateway.verdicts.types import Verdict

log = get_logger(__name__)

REFERENCE_DEVICE_ID = "release-level"
RELEASE_LEVEL_CHECKS = frozenset({"firmware_hash", "signature", "sbom_hash", "registry_record"})
REVIEWABLE_CHECKS = frozenset({"release_delta"})
"""Stage-1 holds a person may resolve. ``expiry`` is not one: the publisher must re-issue."""
REVIEW_DEVICE_ID = "human-review"


class ReviewError(VerigateError):
    """A review request that cannot be applied; ``status`` is the HTTP status to return."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(message)


"""Stage-1 failures that are evidence against the release (its publisher), not the device."""


@dataclass(frozen=True)
class ReleaseBundle:
    """Everything fetched for one release. ``None`` fields could not be obtained."""

    release_id: bytes
    release: ReleaseRecord | None
    publisher: PublisherRecord | None
    manifest: SignedManifest | None
    firmware: bytes | None
    sbom: bytes | None
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationResult:
    """What ``/verify`` returns and what the verdict log records."""

    release_id: str
    device_id: str
    verdict: Verdict
    stage1: Stage1Result | None
    reason: str | None
    checked_at: str
    version: str | None = None
    device_model: str | None = None
    errors: tuple[str, ...] = ()
    verdict_id: str | None = None
    r_bp: int | None = None
    policy_version: int | None = None
    scores: Stage2Scores | None = None
    reputation_bp: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "releaseId": self.release_id,
            "deviceId": self.device_id,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "stage1": self.stage1.to_dict() if self.stage1 else None,
            "checkedAt": self.checked_at,
            "version": self.version,
            "deviceModel": self.device_model,
            "errors": list(self.errors),
            "verdictId": self.verdict_id,
            "R": self.r_bp,
            "policyVersion": self.policy_version,
            "rSbom": self.scores.r_sbom_bp if self.scores else None,
            "rImg": self.scores.r_img_bp if self.scores else None,
            "reputation": self.reputation_bp,
            "modelHashes": list(self.scores.model_hashes) if self.scores else [],
            "rationaleCid": self.scores.rationale_cid if self.scores else None,
            "stage2": self.scores.features if self.scores else None,
        }


def _values(scores: Stage2Scores, model: str) -> dict[str, Any]:
    """The feature values one model saw (without its hash and attributions)."""
    block = scores.features.get(model, {})
    if not isinstance(block, dict):
        return {}
    return {k: v for k, v in block.items() if k not in {"model", "top3", "previous"}}


@dataclass
class GatewayService:
    """Application state shared by the API routes and the listener."""

    settings: Settings
    chain: ChainClient
    ipfs: IpfsBackend
    state_dir: Path
    devices: DeviceStore = field(init=False)
    verdicts: VerdictLog = field(init=False)
    reviews: ReviewStore = field(init=False)
    cursor: Cursor = field(init=False)
    _bundles: dict[bytes, ReleaseBundle] = field(default_factory=dict, init=False)
    _known_releases: dict[bytes, ReleaseRecord] = field(default_factory=dict, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    started_at: float = field(default_factory=time.time, init=False)
    policy: PolicyEngine = field(init=False)
    scorer: Scorer = field(default_factory=NullScorer)
    explainer: Explainer | None = None
    _model_hashes: list[bytes] = field(default_factory=list, init=False)
    _analyses: dict[str, tuple[dict[str, Any], AiReading]] = field(default_factory=dict, init=False)
    _rationales: dict[str, asyncio.Task[Explanation | None]] = field(
        default_factory=dict, init=False
    )
    batcher: VerdictBatcher | None = field(default=None, init=False)
    reputation: ReputationUpdater | None = field(default=None, init=False)
    gateway_account: LocalAccount | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        """Open the stores under ``state_dir``; wire batching/reputation if a gateway key exists."""
        self.devices = DeviceStore(self.state_dir / "devices.json")
        self.verdicts = VerdictLog(self.state_dir / "verdicts.jsonl")
        self.reviews = ReviewStore(self.state_dir / "reviews.json")
        self.cursor = Cursor(self.state_dir / "listener.json")
        self.policy = PolicyEngine(self.chain)
        raw = [h.strip() for h in self.settings.stage2_model_hashes.split(",") if h.strip()]
        self._model_hashes = [bytes.fromhex(h.removeprefix("0x")) for h in raw]
        if self.settings.gateway_private_key:
            self.gateway_account = self.chain.account(self.settings.gateway_private_key)
            self.batcher = VerdictBatcher(
                self.chain,
                self.gateway_account,
                self.state_dir / "batches",
                max_size=self.settings.batch_max_size,
                max_wait_s=self.settings.batch_max_wait_s,
            )
            self.reputation = ReputationUpdater(
                self.chain, self.gateway_account, self.settings.reputation_alpha_bp
            )

    # ------------------------------------------------------------------ helpers

    def now(self) -> datetime:
        """The gateway clock (UTC, tz-aware) — overridable in tests."""
        return datetime.now(UTC)

    def model_hashes(self) -> tuple[bytes, ...]:
        """Model hashes the gate uses: ``STAGE2_MODEL_HASHES`` until a revocation swaps one."""
        return tuple(self._model_hashes)

    async def swap_model(self, revoked: str, successor: str) -> bool:
        """Replace a revoked model by its registry successor (P6-06); ``False`` = fail closed.

        Only the slot that ran ``revoked`` changes; the successor file is found by hash under
        ``MODELS_DIR``. On success ``model_hashes()`` names the successor, so Stage 1's
        ``model_active`` check reads the new record and Stage 2 runs the new model.
        """
        digest = bytes.fromhex(revoked.removeprefix("0x"))
        if digest not in self._model_hashes or int(successor, 16) == 0:
            log.warning("model.swap_unavailable", revoked=revoked, successor=successor)
            return False
        replacement = await asyncio.to_thread(
            swap_model, self.scorer, self.settings, revoked, successor
        )
        if replacement is None:
            log.warning("model.swap_unavailable", revoked=revoked, successor=successor)
            return False
        self.scorer = replacement
        self._model_hashes[self._model_hashes.index(digest)] = bytes.fromhex(successor[2:])
        self._rationales.clear()  # a rationale describes the scores of the model that ran
        log.warning("model.swapped", revoked=revoked, successor=successor)
        return True

    # ------------------------------------------------------------------ health

    async def health(self) -> dict[str, Any]:
        """Liveness plus dependency status (never raises)."""
        connected = await asyncio.to_thread(self.chain.is_connected)
        block: int | None = None
        if connected:
            try:
                block = await asyncio.to_thread(self.chain.block_number)
            except ChainError:
                connected = False
        return {
            "status": "ok",
            "chain": connected,
            "block": block,
            "chainId": self.settings.chain_id,
            "ipfsBackend": self.settings.ipfs_backend,
            "listenerLastBlock": self.cursor.last_block,
            "knownReleases": len(self._known_releases),
            "devices": len(self.devices.all()),
            "uptimeS": int(time.time() - self.started_at),
            "gateway": self.gateway_account.address if self.gateway_account else None,
            "contracts": {
                "PublisherRegistry": self.chain.addresses.publisher_registry,
                "ModelRegistry": self.chain.addresses.model_registry,
                "FirmwareRegistry": self.chain.addresses.firmware_registry,
                "PolicyContract": self.chain.addresses.policy_contract,
                "VerdictRegistry": self.chain.addresses.verdict_registry,
            },
            "pendingVerdicts": self.batcher.pending if self.batcher else None,
            "batches": self.batcher.commits if self.batcher else None,
        }

    # ------------------------------------------------------------------ releases

    async def refresh_releases(self) -> int:
        """(Re)load every release record from the chain; returns how many are known.

        Re-reading known records picks up revocations that happened without a new event.
        """
        ids = await asyncio.to_thread(self.chain.release_ids, 0, 10_000)
        for rid in ids:
            self._known_releases[rid] = await asyncio.to_thread(self.chain.get_release, rid)
        return len(self._known_releases)

    async def note_release(self, release_id: bytes) -> ReleaseRecord:
        """Record a release announced by the listener (also refreshes its on-chain record)."""
        record = await asyncio.to_thread(self.chain.get_release, release_id)
        self._known_releases[release_id] = record
        self._bundles.pop(release_id, None)
        return record

    def known_releases(self) -> list[ReleaseRecord]:
        """Releases in registration order."""
        return sorted(self._known_releases.values(), key=lambda r: r.registered_at)

    def latest_for(self, device_model: str, above: SemVer) -> ReleaseRecord | None:
        """Newest non-revoked release for ``device_model`` with version > ``above``."""
        candidates = [
            r
            for r in self._known_releases.values()
            if r.device_model == device_model and not r.revoked and r.version > above.as_tuple()
        ]
        return max(candidates, key=lambda r: r.version) if candidates else None

    def previous_release(self, release: ReleaseRecord) -> ReleaseRecord | None:
        """The newest known release of the same publisher + model with a lower version."""
        candidates = [
            r
            for r in self._known_releases.values()
            if r.publisher_id == release.publisher_id
            and r.device_model_id == release.device_model_id
            and r.version < release.version
        ]
        return max(candidates, key=lambda r: r.version) if candidates else None

    async def previous_firmware(self, bundle: ReleaseBundle) -> bytes | None:
        """Firmware bytes of the previous release (for version-delta features), if any."""
        if bundle.release is None or not bundle.release.exists:
            return None
        if bundle.release.release_id not in self._known_releases:
            self._known_releases[bundle.release.release_id] = bundle.release
        previous = self.previous_release(bundle.release)
        if previous is None:
            return None
        prev_bundle = await self.bundle(previous.release_id)
        return prev_bundle.firmware

    async def trusted_firmware(self, bundle: ReleaseBundle) -> tuple[bytes | None, bool]:
        """(image of the last trusted release, whether it exists but could not be fetched).

        Trusted = an earlier, non-revoked release of the same publisher and device model that
        this gateway approved and whose served image still matches its on-chain hash. A held,
        rejected or tampered release is never the reference for Stage-1 check #9.
        """
        release = bundle.release
        if release is None or not release.exists:
            return None, False
        earlier = sorted(
            (
                r
                for r in self._known_releases.values()
                if r.publisher_id == release.publisher_id
                and r.device_model_id == release.device_model_id
                and r.version < release.version
                and not r.revoked
                and self.verdicts.ever_approved("0x" + r.release_id.hex())
            ),
            key=lambda r: r.version,
            reverse=True,
        )
        for candidate in earlier:
            # the image is content-addressed: a complete cached bundle needs no chain refresh
            cached = self._bundles.get(candidate.release_id)
            if cached is not None and not cached.errors and cached.firmware is not None:
                firmware: bytes | None = cached.firmware
            else:
                firmware = (await self.bundle(candidate.release_id)).firmware
            if firmware is None:
                return None, True
            if sha256(firmware) == candidate.firmware_hash:
                return firmware, False
        return None, False

    async def previous_sbom(self, bundle: ReleaseBundle) -> bytes | None:
        """SBOM bytes of the previous release (for the explainer's diff), if any."""
        if bundle.release is None or not bundle.release.exists:
            return None
        previous = self.previous_release(bundle.release)
        if previous is None:
            return None
        return (await self.bundle(previous.release_id)).sbom

    async def rationale_for(
        self,
        rid: str,
        bundle: ReleaseBundle,
        scores: Stage2Scores,
        decision: Decision,
        device_model: str,
        wait: bool,
    ) -> Explanation | None:
        """The LLM rationale for a release (ADR-0002): one background task per release.

        No verification waits for it (a CPU-bound language model takes a minute or more): the
        first verdict for a release is issued without a CID, later verdicts pick the CID up once
        the task has finished, and ``rationale_status`` exposes the text to the console as soon
        as it exists. ``wait=True`` is kept for callers that explicitly want the result (tests,
        evaluation). The rationale content is never read back by the gate.
        """
        if self.explainer is None or not self.explainer.enabled or not scores.model_hashes:
            return None
        task = self._rationales.get(rid)
        if task is None:
            assert bundle.sbom is not None  # noqa: S101 — Stage 2 ran
            diff = sbom_diff(bundle.sbom, await self.previous_sbom(bundle))
            inp = ExplainInput(
                release_id=rid,
                version=str(bundle.manifest.version) if bundle.manifest else "",
                device_model=device_model,
                diff=diff,
                r_sbom_bp=scores.r_sbom_bp,
                r_img_bp=scores.r_img_bp,
                verdict=decision.verdict.value,
                top_sbom=scores.top("sbom"),
                top_img=scores.top("img"),
                expected_exploited=scores.expected_exploited,
                cves=scores.cves,
                sbom_values=_values(scores, "sbom"),
                img_values=_values(scores, "img"),
                overall_bp=decision.r_bp,
            )
            task = self._start_rationale(rid, inp)
        if wait or task.done():
            return await task
        return None

    def _start_rationale(self, rid: str, inp: ExplainInput) -> asyncio.Task[Explanation | None]:
        assert self.explainer is not None  # noqa: S101
        task = asyncio.create_task(asyncio.to_thread(self.explainer.explain, inp))
        self._rationales[rid] = task
        return task

    def _recorded_stop(self, rid: str) -> Stage1Result | None:
        """The failed checks of the latest release-level verdict for ``rid``, if they failed.

        This is the verdict the console shows. It is explained as recorded, because re-running
        the gate later can decide differently (e.g. a revoked model has since been replaced).
        """
        last = next(
            (
                v
                for v in reversed(self.verdicts.recent(500))
                if v.get("releaseId") == rid and v.get("deviceId") == REFERENCE_DEVICE_ID
            ),
            None,
        )
        if last is None or "verdict" not in last:
            return None
        stage1 = last.get("stage1") or {}
        if stage1.get("ok") is not False or not stage1.get("failed"):
            return None
        checks = tuple(
            CheckResult(c["name"], bool(c["ok"]), c.get("reason")) for c in stage1.get("checks", [])
        )
        return Stage1Result(
            False, checks, stage1["failed"], stage1.get("reason"), Verdict(last["verdict"])
        )

    async def _explain_stopped(
        self, rid: str, bundle: ReleaseBundle, device_model: str, stage1: Stage1Result
    ) -> None:
        """Start the explanation for a release the checks stopped (no scores exist)."""
        assert stage1.outcome is not None and stage1.failed is not None  # noqa: S101
        self._start_rationale(
            rid,
            ExplainInput(
                release_id=rid,
                version=str(bundle.manifest.version) if bundle.manifest else "",
                device_model=device_model,
                diff=SbomDiff((), (), ()),  # the stopped prompt describes the check, not the SBOM
                r_sbom_bp=None,
                r_img_bp=None,
                verdict=stage1.outcome.value,
                top_sbom=[],
                top_img=[],
                stopped_at=stage1.failed,
                stop_reason=stage1.reason,
                passed_checks=tuple(r.name for r in stage1.results if r.ok),
                ai_after_stop=self._analyses.get(rid, (None, None))[1],
            ),
        )

    async def analyse_now(self, rid: str) -> dict[str, Any]:
        """Run the two risk models on a release on request (the console's AI button).

        For a release the checks stopped, this is the only way to see the models' view. The
        result is informational: it is kept in memory for the console and the explainer and
        never enters a verdict, the verdict log or the chain. A finished explanation is dropped
        so the next one can describe the models' view too.
        """
        release_id = bytes.fromhex(rid.removeprefix("0x"))
        bundle = await self.bundle(release_id)
        if bundle.errors or bundle.release is None or not bundle.release.exists:
            return {"status": "none", "reason": "release not available"}
        if bundle.firmware is None or bundle.sbom is None:
            return {"status": "none", "reason": "the firmware or its ingredient list is missing"}
        previous = await self.previous_firmware(bundle)
        scores = await asyncio.to_thread(self.scorer.score, bundle.firmware, bundle.sbom, previous)
        if not scores.model_hashes:
            return {"status": "none", "reason": "no risk models are configured"}
        reputation_bp = bundle.publisher.reputation_bp if bundle.publisher else None
        decision = await self.policy.decide(scores.r_sbom_bp, scores.r_img_bp, reputation_bp)
        reading = AiReading(
            scores.r_sbom_bp,
            scores.r_img_bp,
            scores.top("sbom"),
            scores.top("img"),
            _values(scores, "sbom"),
            _values(scores, "img"),
            scores.expected_exploited,
            scores.cves,
            decision.verdict.value,
            decision.r_bp,
        )
        result = {
            "status": "ready",
            "rSbom": scores.r_sbom_bp,
            "rImg": scores.r_img_bp,
            "R": decision.r_bp,
            "verdictFromScores": decision.verdict.value,
            "reason": decision.reason,
            "stage2": scores.features,
        }
        self._analyses[rid] = (result, reading)
        task = self._rationales.get(rid)
        if task is not None and task.done() and self.explainer is not None:
            self._rationales.pop(rid, None)
            self.explainer.forget(rid)
        return result

    def analysis_status(self, rid: str) -> dict[str, Any]:
        """The on-request analysis for ``rid``, if one was run since the gateway started."""
        entry = self._analyses.get(rid)
        return entry[0] if entry else {"status": "none"}

    async def explain_now(self, rid: str, again: bool = False) -> dict[str, Any]:
        """Start the written explanation for ``rid`` on request (the console's button).

        Re-runs the gate deterministically (same checks, models, features and decision) so the
        writer describes exactly what the gate saw: the scores when the checks passed, the failed
        check when they did not. ``again`` discards a finished or failed attempt first. Returns
        the same shape as ``rationale_status``.
        """
        if self.explainer is None or not self.explainer.enabled:
            return {"status": "off"}
        task = self._rationales.get(rid)
        if task is not None and not task.done():
            return await self.rationale_status(rid)
        if task is not None and not again:
            return await self.rationale_status(rid)
        release_id = bytes.fromhex(rid.removeprefix("0x"))
        bundle = await self.bundle(release_id)
        if bundle.errors or bundle.release is None or not bundle.release.exists:
            return {"status": "none", "reason": "release not available"}
        device_model = bundle.manifest.deviceModel if bundle.manifest else ""
        if again:
            self._rationales.pop(rid, None)
            self.explainer.forget(rid)
        recorded = self._recorded_stop(rid)
        if recorded is not None:
            await self._explain_stopped(rid, bundle, device_model, recorded)
            return await self.rationale_status(rid)
        models = tuple(
            [await asyncio.to_thread(self.chain.get_model, h) for h in self.model_hashes()]
        )
        trusted, trusted_unavailable = await self.trusted_firmware(bundle)
        stage1 = await asyncio.to_thread(
            run_stage1,
            Stage1Input(
                manifest=bundle.manifest,
                firmware=bundle.firmware,
                sbom=bundle.sbom,
                release=bundle.release,
                publisher=bundle.publisher,
                device=DeviceView(REFERENCE_DEVICE_ID, device_model, SemVer(0, 0, 0)),
                models=models,
                now=self.now(),
                trusted_firmware=trusted,
                trusted_unavailable=trusted_unavailable,
            ),
            rid,
        )
        if stage1.outcome is not None:
            await self._explain_stopped(rid, bundle, device_model, stage1)
            return await self.rationale_status(rid)
        assert bundle.firmware is not None and bundle.sbom is not None  # noqa: S101 — checks passed
        previous = await self.previous_firmware(bundle)
        scores = await asyncio.to_thread(self.scorer.score, bundle.firmware, bundle.sbom, previous)
        if not scores.model_hashes:
            return {"status": "none", "reason": "the models did not run for this release"}
        reputation_bp = bundle.publisher.reputation_bp if bundle.publisher else None
        decision = await self.policy.decide(scores.r_sbom_bp, scores.r_img_bp, reputation_bp)
        await self.rationale_for(rid, bundle, scores, decision, device_model, wait=False)
        return await self.rationale_status(rid)

    async def rationale_status(self, rid: str) -> dict[str, Any]:
        """Where the explanation for ``rid`` stands: off / none / writing / ready / failed."""
        if self.explainer is None or not self.explainer.enabled:
            return {"status": "off"}
        task = self._rationales.get(rid)
        if task is None:
            return {"status": "none"}
        if not task.done():
            return {"status": "writing"}
        result = None if task.cancelled() or task.exception() else task.result()
        if result is None:
            return {"status": "failed"}
        return {
            "status": "ready",
            "cid": result.cid,
            "model": result.model,
            "rationale": result.rationale.model_dump(),
        }

    def _fetch_bundle(self, release_id: bytes) -> ReleaseBundle:
        errors: list[str] = []
        release = publisher = manifest = firmware = sbom = None
        try:
            release = self.chain.get_release(release_id)
            if release.exists:
                publisher = self.chain.get_publisher(release.publisher_id)
        except ChainError as exc:
            errors.append(f"chain: {exc}")
        if release is not None and release.exists:
            try:
                manifest = SignedManifest.model_validate_json(self.ipfs.get(release.manifest_cid))
            except (IpfsError, ValueError) as exc:
                errors.append(f"manifest: {exc}")
            try:
                firmware = self.ipfs.get(release.firmware_cid)
            except IpfsError as exc:
                errors.append(f"firmware: {exc}")
            try:
                sbom = self.ipfs.get(release.sbom_cid)
            except IpfsError as exc:
                errors.append(f"sbom: {exc}")
        return ReleaseBundle(
            release_id, release, publisher, manifest, firmware, sbom, tuple(errors)
        )

    async def bundle(self, release_id: bytes, refresh: bool = False) -> ReleaseBundle:
        """Fetched artefacts for a release (cached while complete and error-free)."""
        cached = self._bundles.get(release_id)
        if cached is not None and not refresh and not cached.errors:
            # artefacts are content-addressed and immutable; only the on-chain state can change
            try:
                fresh = await asyncio.to_thread(self.chain.get_release, release_id)
                publisher = (
                    await asyncio.to_thread(self.chain.get_publisher, fresh.publisher_id)
                    if fresh.exists
                    else None
                )
            except ChainError as exc:
                return replace(cached, errors=(f"chain: {exc}",))
            return replace(cached, release=fresh, publisher=publisher)
        fetched = await asyncio.to_thread(self._fetch_bundle, release_id)
        self._bundles[release_id] = fetched
        if fetched.release is not None and fetched.release.exists:
            self._known_releases[release_id] = fetched.release
        return fetched

    # ------------------------------------------------------------------ verification

    async def verify(
        self, release_id: bytes, device: DeviceView | None = None
    ) -> VerificationResult:
        """Run the gate for ``release_id`` (release-level if ``device`` is ``None``)."""
        rid = "0x" + release_id.hex()
        view = device or DeviceView(REFERENCE_DEVICE_ID, "", SemVer(0, 0, 0))
        bundle = await self.bundle(release_id)
        if device is None:
            model = (
                bundle.manifest.deviceModel
                if bundle.manifest
                else (
                    bundle.release.device_model if bundle.release and bundle.release.exists else ""
                )
            )
            view = DeviceView(REFERENCE_DEVICE_ID, model, SemVer(0, 0, 0))
        checked_at = self.now()
        chain_down = any(e.startswith("chain:") for e in bundle.errors)
        ipfs_down = any(not e.startswith("chain:") for e in bundle.errors)
        models: tuple[ModelRecord | None, ...] = ()
        if not chain_down and self.model_hashes():
            try:
                models = tuple(
                    [await asyncio.to_thread(self.chain.get_model, h) for h in self.model_hashes()]
                )
            except ChainError as exc:
                chain_down = True
                bundle = replace(bundle, errors=(*bundle.errors, f"chain: {exc}"))
        if chain_down or (ipfs_down and bundle.release is not None and bundle.release.exists):
            # A dependency outage is not evidence against the release: hold, do not reject.
            result = VerificationResult(
                rid,
                view.device_id,
                Verdict.DEFER,
                None,
                "dependency unavailable: " + "; ".join(bundle.errors),
                checked_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                errors=bundle.errors,
            )
            log.warning(
                "verify.deferred",
                release_id=rid,
                device_id=view.device_id,
                errors=list(bundle.errors),
            )
            self.verdicts.append(result.to_dict())
            return result
        trusted, trusted_unavailable = await self.trusted_firmware(bundle)
        inp = Stage1Input(
            manifest=bundle.manifest,
            firmware=bundle.firmware,
            sbom=bundle.sbom,
            release=bundle.release,
            publisher=bundle.publisher,
            device=view,
            models=models,
            now=checked_at,
            trusted_firmware=trusted,
            trusted_unavailable=trusted_unavailable,
        )
        stage1 = await asyncio.to_thread(run_stage1, inp, rid)
        ts = int(checked_at.timestamp())
        reputation_bp = bundle.publisher.reputation_bp if bundle.publisher else None
        if stage1.outcome is not None:
            # Stage 1 decided; nothing can override it. Record R as maximal risk.
            verdict, r_bp, policy_version, scores = stage1.outcome, BASIS, None, None
            record_features = feature_hash({"stage1Failed": stage1.failed})
            model_hashes: list[str] = []
        else:
            assert bundle.firmware is not None and bundle.sbom is not None  # noqa: S101
            previous = await self.previous_firmware(bundle)
            scores = await asyncio.to_thread(
                self.scorer.score, bundle.firmware, bundle.sbom, previous
            )
            decision: Decision = await self.policy.decide(
                scores.r_sbom_bp, scores.r_img_bp, reputation_bp
            )
            verdict, r_bp, policy_version = decision.verdict, decision.r_bp, decision.policy_version
            record_features = scores.feature_hash
            model_hashes = list(scores.model_hashes)
            if self.settings.llm_auto_explain or rid in self._rationales:
                # Auto mode starts the writer here; on-request mode only picks up a finished one.
                explanation = await self.rationale_for(
                    rid, bundle, scores, decision, view.device_model, wait=False
                )
                if explanation is not None:
                    scores = replace(scores, rationale_cid=explanation.cid)
        reason = stage1.reason if stage1.outcome is not None else decision.reason
        review = self.reviews.get(rid)
        if review is not None and verdict is Verdict.DEFER and self._reviewable(stage1):
            # A person resolved this hold; the decision is anchored as its own record.
            verdict = Verdict(review.decision)
            reason = _review_reason(review)
        record = VerdictRecord(
            releaseId=rid,
            deviceId=view.device_id,
            modelHashes=model_hashes,
            featureHash=record_features,
            r_sbom=scores.r_sbom_bp if scores else 0,
            r_img=scores.r_img_bp if scores else 0,
            reputation=reputation_bp if reputation_bp is not None else 0,
            R=r_bp,
            verdict=verdict,
            rationaleCid=scores.rationale_cid if scores else None,
            ts=ts,
        )
        verdict_id = "0x" + record.leaf().hex()
        if self.batcher is not None and self.gateway_account is not None:
            record = record.sign(self.settings.gateway_private_key)
            verdict_id = await self.batcher.add(record)
        result = VerificationResult(
            rid,
            view.device_id,
            verdict,
            stage1,
            reason,
            checked_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            version=str(bundle.manifest.version) if bundle.manifest else None,
            device_model=bundle.manifest.deviceModel if bundle.manifest else None,
            errors=bundle.errors,
            verdict_id=verdict_id,
            r_bp=r_bp,
            policy_version=policy_version,
            scores=scores,
            reputation_bp=reputation_bp,
        )
        log.info(
            "verify.verdict",
            release_id=rid,
            device_id=view.device_id,
            verdict=verdict.value,
            failed=stage1.failed,
            reason=result.reason,
            r_bp=r_bp,
            verdict_id=verdict_id,
        )
        self.verdicts.append(result.to_dict())
        if (
            verdict is Verdict.REJECT
            and self.reputation is not None
            and bundle.publisher is not None
            and bundle.publisher.exists
            and (stage1.failed is None or stage1.failed in RELEASE_LEVEL_CHECKS)
            and review is None  # a reviewer's rejection lowers reputation once, when it is made
        ):
            await self.reputation.on_reject(
                bundle.publisher.publisher_id, stage1.failed or "policy"
            )
        return result

    # ------------------------------------------------------------------ human review

    @staticmethod
    def _reviewable(stage1: Stage1Result) -> bool:
        """A DEFER from the risk policy or from a check a person may resolve (not expiry)."""
        return stage1.outcome is None or stage1.failed in REVIEWABLE_CHECKS

    async def review(
        self, release_id: bytes, decision: Verdict, reviewer: str, note: str = ""
    ) -> dict[str, Any]:
        """Record a person's APPROVE / REJECT for a release the gate holds for review.

        The gate is re-run first: only a release that is *currently* held for review by the
        policy or by a reviewable check can be decided, once. The decision is signed and anchored
        as its own verdict record (device ``human-review``) whose feature hash commits to the
        decision, the reviewer, the note and the held verdict it resolves; later verifications of
        the release turn that DEFER into the reviewer's decision.
        """
        rid = "0x" + release_id.hex()
        if decision not in (Verdict.APPROVE, Verdict.REJECT):
            raise ReviewError(422, "a review decides APPROVE or REJECT")
        if self.reviews.get(rid) is not None:
            raise ReviewError(409, "this release has already been reviewed")
        bundle = await self.bundle(release_id)
        if bundle.release is None or not bundle.release.exists:
            raise ReviewError(404, "unknown release")
        held = await self.verify(release_id)
        if (
            held.verdict is not Verdict.DEFER
            or held.stage1 is None
            or not self._reviewable(held.stage1)
        ):
            raise ReviewError(
                409,
                f"only a release held for review can be decided; the gate says {held.verdict.value}"
                + (f" ({held.reason})" if held.reason else ""),
            )
        decided_at = self.now()
        scores = held.scores
        record = VerdictRecord(
            releaseId=rid,
            deviceId=REVIEW_DEVICE_ID,
            modelHashes=list(scores.model_hashes) if scores else [],
            featureHash=feature_hash(
                {
                    "review": {
                        "decision": decision.value,
                        "reviewer": reviewer,
                        "note": note,
                        "heldVerdictId": held.verdict_id,
                    }
                }
            ),
            r_sbom=scores.r_sbom_bp if scores else 0,
            r_img=scores.r_img_bp if scores else 0,
            reputation=held.reputation_bp if held.reputation_bp is not None else 0,
            R=held.r_bp if held.r_bp is not None else BASIS,
            verdict=decision,
            rationaleCid=None,
            ts=int(decided_at.timestamp()),
        )
        review_verdict_id = "0x" + record.leaf().hex()
        if self.batcher is not None and self.gateway_account is not None:
            review_verdict_id = await self.batcher.add(
                record.sign(self.settings.gateway_private_key)
            )
        review = Review(
            release_id=rid,
            decision=decision.value,
            reviewer=reviewer,
            note=note,
            decided_at=decided_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            held_because=held.reason,
            held_verdict_id=held.verdict_id,
            review_verdict_id=review_verdict_id,
        )
        self.reviews.put(review)
        log.warning(
            "review.decided",
            release_id=rid,
            decision=decision.value,
            reviewer=reviewer,
            verdict_id=review_verdict_id,
        )
        if (
            decision is Verdict.REJECT
            and self.reputation is not None
            and bundle.publisher is not None
            and bundle.publisher.exists
        ):
            await self.reputation.on_reject(bundle.publisher.publisher_id, "review")
        after = await self.verify(release_id)
        return {"review": review.to_dict(), "verdict": after.to_dict()}

    # ------------------------------------------------------------------ registries

    def _publisher_ids_from_events(self) -> list[bytes]:
        logs = self.chain.publishers.events.PublisherRegistered().get_logs(from_block=0)
        return [bytes(entry["args"]["publisherId"]) for entry in logs]

    def _model_hashes_from_events(self) -> list[bytes]:
        logs = self.chain.models.events.ModelRegistered().get_logs(from_block=0)
        return [bytes(entry["args"]["modelHash"]) for entry in logs]

    async def list_publishers(self) -> list[dict[str, Any]]:
        """Publishers from ``PublisherRegistered`` events joined with their current record."""
        try:
            ids = await asyncio.to_thread(self._publisher_ids_from_events)
            records = [await asyncio.to_thread(self.chain.get_publisher, pid) for pid in ids]
        except Exception as exc:  # noqa: BLE001 — web3 raises many transport error types
            log.warning("publishers.unavailable", error=str(exc))
            return []
        return [
            {
                "publisherId": "0x" + r.publisher_id.hex(),
                "did": r.did,
                "owner": r.owner,
                "publicKey": "ed25519:" + r.pub_key.hex(),
                "status": r.status,
                "reputation": r.reputation_bp,
                "keyVersion": r.key_version,
                "registeredAt": r.registered_at,
                "revokedAt": r.revoked_at,
            }
            for r in records
        ]

    async def list_models(self) -> list[dict[str, Any]]:
        """Models from ``ModelRegistered`` events joined with their current record."""
        try:
            hashes = await asyncio.to_thread(self._model_hashes_from_events)
            records = [await asyncio.to_thread(self.chain.get_model, h) for h in hashes]
        except Exception as exc:  # noqa: BLE001 — web3 raises many transport error types
            log.warning("models.unavailable", error=str(exc))
            return []
        return [
            {
                "modelHash": "0x" + r.model_hash.hex(),
                "name": r.name,
                "status": r.status,
                "successor": "0x" + r.successor.hex(),
                "registeredAt": r.registered_at,
                "revokedAt": r.revoked_at,
            }
            for r in records
        ]

    # ------------------------------------------------------------------ device protocol

    def _check_message(self, msg: SignedMessage, expect_known: bool) -> DeviceRecord | None:
        """Verify signature/nonce/window against the pinned key; TOFU on first ``hello``."""
        record = self.devices.get(msg.deviceId)
        now = int(time.time())
        if record is None:
            if expect_known:
                raise VerificationError(f"unknown device {msg.deviceId}; send hello first")
            key = msg.payload.get("publicKey")
            if not isinstance(key, str):
                raise VerificationError("hello must carry publicKey")
            check = verify_message(msg, key, now, 0, self.settings.protocol_window_s)
        else:
            check = verify_message(
                msg, record.public_key, now, record.last_nonce, self.settings.protocol_window_s
            )
        if not check.ok:
            log.warning("protocol.rejected", device_id=msg.deviceId, reason=check.reason)
            raise VerificationError(f"message rejected: {check.reason}")
        return record

    async def device_hello(self, msg: SignedMessage) -> DeviceRecord:
        """Pin the device key on first contact; afterwards only the pinned key is accepted."""
        async with self._lock:
            record = self._check_message(msg, expect_known=False)
            payload = msg.payload
            model = str(payload.get("deviceModel", ""))
            version = str(payload.get("installedVersion", "0.0.0"))
            SemVer.parse(version)
            updated = DeviceRecord(
                device_id=msg.deviceId,
                device_model=record.device_model if record else model,
                public_key=record.public_key if record else str(payload["publicKey"]),
                installed_version=version,
                last_nonce=msg.nonce,
                last_seen=int(time.time()),
                installed_release_id=record.installed_release_id if record else None,
                receipts=record.receipts if record else 0,
            )
            self.devices.put(updated)
            log.info(
                "device.hello", device_id=msg.deviceId, model=updated.device_model, version=version
            )
            return updated

    async def device_poll(self, msg: SignedMessage) -> dict[str, Any]:
        """Answer "is there an approved update for me?" with the manifest and publisher key."""
        async with self._lock:
            record = self._check_message(msg, expect_known=True)
            assert record is not None  # noqa: S101 — guaranteed by expect_known
            version = str(msg.payload.get("installedVersion", record.installed_version))
            installed = SemVer.parse(version)
            self.devices.put(
                DeviceRecord(
                    **{
                        **record.__dict__,
                        "installed_version": version,
                        "last_nonce": msg.nonce,
                        "last_seen": int(time.time()),
                    }
                )
            )
        candidate = self.latest_for(record.device_model, installed)
        if candidate is None:
            return {"update": None, "reason": "no newer release for this model"}
        view = DeviceView(record.device_id, record.device_model, installed)
        result = await self.verify(candidate.release_id, view)
        if result.verdict is not Verdict.APPROVE:
            return {"update": None, "verdict": result.to_dict()}
        bundle = await self.bundle(candidate.release_id)
        assert bundle.manifest is not None and bundle.publisher is not None  # noqa: S101
        return {
            "update": {
                "releaseId": result.release_id,
                "manifest": bundle.manifest.model_dump(mode="json"),
                "publisherKey": "ed25519:" + bundle.publisher.pub_key.hex(),
                "firmwareUrl": f"/releases/{result.release_id}/firmware",
            },
            "verdict": result.to_dict(),
        }

    async def device_receipt(self, msg: SignedMessage) -> DeviceRecord:
        """Accept a signed install receipt and update the device's installed version."""
        async with self._lock:
            record = self._check_message(msg, expect_known=True)
            assert record is not None  # noqa: S101
            try:
                receipt = InstallReceipt.model_validate(msg.payload.get("receipt"))
            except ValueError as exc:
                raise VerificationError(f"malformed receipt: {exc}") from exc
            if receipt.deviceId != msg.deviceId:
                raise VerificationError("receipt deviceId != message deviceId")
            if not verify(
                bytes.fromhex(record.public_key.removeprefix("ed25519:")),
                receipt.signed_bytes(),
                parse_signature(receipt.signature),
            ):
                raise VerificationError("receipt signature invalid")
            SemVer.parse(receipt.version)
            updated = DeviceRecord(
                **{
                    **record.__dict__,
                    "installed_version": receipt.version,
                    "installed_release_id": receipt.releaseId,
                    "last_nonce": msg.nonce,
                    "last_seen": int(time.time()),
                    "receipts": record.receipts + 1,
                }
            )
            self.devices.put(updated)
            log.info(
                "device.receipt",
                device_id=msg.deviceId,
                release_id=receipt.releaseId,
                version=receipt.version,
            )
            self.verdicts.append(
                {
                    "event": "receipt",
                    "deviceId": msg.deviceId,
                    "releaseId": receipt.releaseId,
                    "version": receipt.version,
                    "installedAt": receipt.installedAt,
                }
            )
        if self.reputation is not None:
            release = self._known_releases.get(bytes.fromhex(receipt.releaseId[2:]))
            if release is not None and release.exists:
                await self.reputation.on_receipt(release.publisher_id)
        return updated

    async def firmware(self, release_id: bytes) -> bytes:
        """Firmware bytes for a release (the device re-verifies them itself).

        Raises:
            VerigateError: If the release or its firmware cannot be fetched.
        """
        bundle = await self.bundle(release_id)
        if bundle.firmware is None:
            raise VerigateError("firmware unavailable: " + "; ".join(bundle.errors))
        return bundle.firmware


def _review_reason(review: Review) -> str:
    """The verdict reason when a reviewer resolved the hold."""
    word = "accepted" if review.decision == Verdict.APPROVE.value else "rejected"
    return f"{word} by reviewer {review.reviewer}" + (f": {review.note}" if review.note else "")
