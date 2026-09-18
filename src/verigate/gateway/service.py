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
from verigate.common.crypto import parse_signature, verify
from verigate.common.errors import ChainError, IpfsError, VerificationError, VerigateError
from verigate.common.ipfs import IpfsBackend
from verigate.common.logging import get_logger
from verigate.common.manifest import SemVer, SignedManifest
from verigate.common.protocol import SignedMessage, verify_message
from verigate.common.settings import Settings
from verigate.fleet.device import InstallReceipt
from verigate.gateway.policy.engine import BASIS, Decision, PolicyEngine
from verigate.gateway.reputation import ReputationUpdater
from verigate.gateway.stage1.inputs import DeviceView, Stage1Input
from verigate.gateway.stage1.runner import Stage1Result, run_stage1
from verigate.gateway.stage2.scores import NullScorer, Stage2Scores
from verigate.gateway.store import Cursor, DeviceRecord, DeviceStore, VerdictLog
from verigate.gateway.verdicts.batch import VerdictBatcher
from verigate.gateway.verdicts.record import VerdictRecord, feature_hash
from verigate.gateway.verdicts.types import Verdict

log = get_logger(__name__)

REFERENCE_DEVICE_ID = "release-level"
RELEASE_LEVEL_CHECKS = frozenset({"firmware_hash", "signature", "sbom_hash", "registry_record"})
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
        }


@dataclass
class GatewayService:
    """Application state shared by the API routes and the listener."""

    settings: Settings
    chain: ChainClient
    ipfs: IpfsBackend
    state_dir: Path
    devices: DeviceStore = field(init=False)
    verdicts: VerdictLog = field(init=False)
    cursor: Cursor = field(init=False)
    _bundles: dict[bytes, ReleaseBundle] = field(default_factory=dict, init=False)
    _known_releases: dict[bytes, ReleaseRecord] = field(default_factory=dict, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    started_at: float = field(default_factory=time.time, init=False)
    policy: PolicyEngine = field(init=False)
    scorer: NullScorer = field(default_factory=NullScorer)
    batcher: VerdictBatcher | None = field(default=None, init=False)
    reputation: ReputationUpdater | None = field(default=None, init=False)
    gateway_account: LocalAccount | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        """Open the stores under ``state_dir``; wire batching/reputation if a gateway key exists."""
        self.devices = DeviceStore(self.state_dir / "devices.json")
        self.verdicts = VerdictLog(self.state_dir / "verdicts.jsonl")
        self.cursor = Cursor(self.state_dir / "listener.json")
        self.policy = PolicyEngine(self.chain)
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
        """Model hashes the gate uses (``STAGE2_MODEL_HASHES``), empty until P5."""
        raw = [h.strip() for h in self.settings.stage2_model_hashes.split(",") if h.strip()]
        return tuple(bytes.fromhex(h.removeprefix("0x")) for h in raw)

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
        inp = Stage1Input(
            manifest=bundle.manifest,
            firmware=bundle.firmware,
            sbom=bundle.sbom,
            release=bundle.release,
            publisher=bundle.publisher,
            device=view,
            models=models,
            now=checked_at,
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
            scores = await asyncio.to_thread(self.scorer.score, bundle.firmware, bundle.sbom)
            decision: Decision = await self.policy.decide(
                scores.r_sbom_bp, scores.r_img_bp, reputation_bp
            )
            verdict, r_bp, policy_version = decision.verdict, decision.r_bp, decision.policy_version
            record_features = scores.feature_hash
            model_hashes = list(scores.model_hashes)
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
            stage1.reason if stage1.outcome is not None else decision.reason,
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
        ):
            await self.reputation.on_reject(
                bundle.publisher.publisher_id, stage1.failed or "policy"
            )
        return result

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
