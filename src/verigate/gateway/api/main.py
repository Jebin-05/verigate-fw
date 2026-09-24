"""FastAPI app: ``/health``, ``/releases``, ``/verify/{releaseId}``, device protocol, ``/logs``.

``create_app(service)`` builds an app around an explicit :class:`GatewayService` (tests inject
fakes); ``run()`` is the ``verigate-gateway`` entry point and wires real clients from settings.
OpenAPI docs are served at ``/docs``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import shutil
import sys
import tempfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import uvicorn
from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware

from verigate.common.chain import ChainClient, device_model_id, publisher_id
from verigate.common.errors import ChainError, IpfsError, VerificationError, VerigateError
from verigate.common.ipfs import make_backend
from verigate.common.logging import configure_logging, get_logger
from verigate.common.manifest import SemVer
from verigate.common.protocol import SignedMessage
from verigate.common.settings import Settings, get_settings
from verigate.gateway.api.logs import hub
from verigate.gateway.listener import NewReleaseListener
from verigate.gateway.revocation import RevocationJob
from verigate.gateway.service import GatewayService
from verigate.gateway.stage1.inputs import DeviceView
from verigate.gateway.stage2.explain import build_explainer
from verigate.gateway.stage2.scores import build_scorer

log = get_logger(__name__)

FIXTURE_DIRS = (Path("tests/fixtures/releases"), Path("/app/fixtures/releases"))
STORY_FIXTURES = frozenset({"v1.0.0", "v1.1.0", "v2.0.0", "legacy-19.07.10"})


def _release_id(text: str) -> bytes:
    try:
        raw = bytes.fromhex(text.removeprefix("0x"))
    except ValueError as exc:
        raise HTTPException(400, "releaseId must be hex") from exc
    if len(raw) != 32:
        raise HTTPException(400, "releaseId must be 32 bytes")
    return raw


def _release_json(service: GatewayService, record: Any) -> dict[str, Any]:  # noqa: ANN401
    last = next(
        (
            v
            for v in reversed(service.verdicts.recent(500))
            if v.get("releaseId") == "0x" + record.release_id.hex() and "verdict" in v
        ),
        None,
    )
    return {
        "releaseId": "0x" + record.release_id.hex(),
        "publisherId": "0x" + record.publisher_id.hex(),
        "deviceModel": record.device_model,
        "version": ".".join(str(v) for v in record.version),
        "manifestCid": record.manifest_cid,
        "firmwareCid": record.firmware_cid,
        "sbomCid": record.sbom_cid,
        "expiry": record.expiry,
        "registeredAt": record.registered_at,
        "revoked": record.revoked,
        "lastVerdict": last["verdict"] if last else None,
        "lastVerdictAt": last["checkedAt"] if last else None,
    }


def create_app(service: GatewayService, start_listener: bool = True) -> FastAPI:
    """Build the API around ``service``. ``start_listener=False`` for tests."""

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        hub.bind(asyncio.get_running_loop())
        stop = asyncio.Event()
        tasks: list[asyncio.Task[None]] = []
        with contextlib.suppress(ChainError):
            await service.refresh_releases()
        if start_listener:

            async def on_release(release_id: bytes, _block: int) -> None:
                await service.note_release(release_id)
                await service.verify(release_id)

            listener = NewReleaseListener(
                service.chain, service.cursor, on_release, service.settings.listener_poll_s
            )
            tasks.append(asyncio.create_task(listener.run(stop)))
        if service.batcher is not None:
            tasks.append(asyncio.create_task(service.batcher.run(stop)))
        if start_listener:
            tasks.append(asyncio.create_task(revocations.run(stop)))
        log.info("gateway.started", releases=len(service.known_releases()))
        try:
            yield
        finally:
            stop.set()
            for task in tasks:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    revocations = RevocationJob(
        service, service.state_dir / "revocations.json", service.settings.listener_poll_s
    )
    app = FastAPI(title="VeriGate-FW gateway", version="1.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )
    app.state.service = service

    @app.exception_handler(VerificationError)
    async def _verification_error(_req: Request, exc: VerificationError) -> Response:
        return Response(
            json.dumps({"detail": str(exc)}), status_code=403, media_type="application/json"
        )

    @app.exception_handler(VerigateError)
    async def _verigate_error(_req: Request, exc: VerigateError) -> Response:
        return Response(
            json.dumps({"detail": str(exc)}), status_code=503, media_type="application/json"
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        """Liveness + dependency status."""
        return await service.health()

    @app.get("/releases")
    async def releases(refresh: bool = False) -> list[dict[str, Any]]:
        """Every release the gateway knows (registration order) with its last verdict."""
        if refresh:
            await service.refresh_releases()
        return [_release_json(service, r) for r in service.known_releases()]

    @app.get("/releases/{release_id}")
    async def release(release_id: str) -> dict[str, Any]:
        """One release with its manifest (if fetchable)."""
        rid = _release_id(release_id)
        bundle = await service.bundle(rid)
        if bundle.release is None or not bundle.release.exists:
            raise HTTPException(404, "unknown release")
        body = _release_json(service, bundle.release)
        body["manifest"] = bundle.manifest.model_dump(mode="json") if bundle.manifest else None
        body["errors"] = list(bundle.errors)
        return body

    @app.get("/releases/{release_id}/manifest")
    async def manifest(release_id: str) -> dict[str, Any]:
        """The signed manifest as stored on IPFS."""
        bundle = await service.bundle(_release_id(release_id))
        if bundle.manifest is None:
            raise HTTPException(404, "manifest unavailable: " + "; ".join(bundle.errors))
        return bundle.manifest.model_dump(mode="json")

    @app.get("/releases/{release_id}/firmware")
    async def firmware(release_id: str) -> Response:
        """Raw firmware bytes (devices re-verify hash + signature themselves)."""
        data = await service.firmware(_release_id(release_id))
        return Response(content=data, media_type="application/octet-stream")

    @app.post("/verify/{release_id}")
    async def verify(
        release_id: str,
        device_id: str | None = Query(default=None, pattern=r"^[a-zA-Z0-9\-_]+$"),
    ) -> dict[str, Any]:
        """Run the gate for a release; with ``device_id`` the device's installed version counts."""
        rid = _release_id(release_id)
        view = None
        if device_id is not None:
            record = service.devices.get(device_id)
            if record is None:
                raise HTTPException(404, "unknown device")
            view = DeviceView(
                device_id, record.device_model, SemVer.parse(record.installed_version)
            )
        result = await service.verify(rid, view)
        return result.to_dict()

    @app.get("/verdicts")
    async def verdicts(limit: int = Query(default=100, ge=1, le=1000)) -> list[dict[str, Any]]:
        """Most recent verification results and receipts (newest last)."""
        return service.verdicts.recent(limit)

    @app.get("/verdicts/{verdict_id}/proof")
    async def verdict_proof(verdict_id: str) -> dict[str, Any]:
        """Merkle proof of a verdict (its id is the leaf) against the committed batch root."""
        if service.batcher is None:
            raise HTTPException(503, "no gateway key configured; verdicts are not batched")
        proof = service.batcher.proof(verdict_id)
        if proof is None:
            raise HTTPException(404, "unknown verdict id")
        return proof

    @app.get("/revocations")
    async def revocation_reports() -> list[dict[str, Any]]:
        """Model revocations this gateway has replayed (before/after per stale verdict)."""
        return [r.to_dict() for r in revocations.reports]

    @app.post("/revocations/check")
    async def revocation_check() -> list[dict[str, Any]]:
        """Poll model status now instead of waiting for the job (the demo/attack path)."""
        return [r.to_dict() for r in await revocations.check_once()]

    @app.get("/releases/{release_id}/rationale")
    async def release_rationale(release_id: str) -> dict[str, Any]:
        """The written explanation for a release, or where it stands (writing / off / none)."""
        rid = _release_id(release_id)
        return await service.rationale_status("0x" + rid.hex())

    @app.post("/releases/{release_id}/explain")
    async def release_explain(release_id: str, again: bool = False) -> dict[str, Any]:
        """Ask the local language model to write (or rewrite) the explanation for a release."""
        rid = _release_id(release_id)
        return await service.explain_now("0x" + rid.hex(), again=again)

    @app.get("/models/cards")
    async def model_cards() -> list[dict[str, Any]]:
        """The configured models' cards and measured metrics, for the console's model panel."""
        models_dir = service.settings.models_dir
        out: list[dict[str, Any]] = []
        for rel in (service.settings.sbom_model, service.settings.image_model):
            if not rel:
                continue
            path = models_dir / rel
            if not path.is_file():
                continue
            metrics_path = path.with_suffix(".metrics.json")
            card_path = path.with_suffix(".card.md")
            out.append(
                {
                    "name": path.stem,
                    "file": rel,
                    "modelHash": "0x" + hashlib.sha256(path.read_bytes()).hexdigest(),
                    "metrics": json.loads(metrics_path.read_text())
                    if metrics_path.is_file()
                    else None,
                    "card": card_path.read_text() if card_path.is_file() else None,
                }
            )
        return out

    @app.get("/rationales/{cid}")
    async def rationale(cid: str) -> dict[str, Any]:
        """The LLM rationale pinned under ``cid`` (ADR-0002: explanatory only, never part of R)."""
        try:
            raw = await asyncio.to_thread(service.ipfs.get, cid)
            doc = json.loads(raw)
        except (IpfsError, ValueError) as exc:
            raise HTTPException(404, f"no rationale at {cid}: {exc}") from exc
        if not isinstance(doc, dict):
            raise HTTPException(404, "rationale is not a JSON object")
        return {"cid": cid, **doc}

    @app.get("/batches")
    async def batches() -> list[dict[str, Any]]:
        """Committed verdict batches (oldest first) without the per-record payloads."""
        if service.batcher is None:
            return []
        return [
            {k: v for k, v in b.to_dict().items() if k != "records"}
            for b in service.batcher.batches()
        ]

    @app.post("/batches/flush")
    async def flush_batches() -> dict[str, Any]:
        """Commit pending verdicts now (demo/evaluation helper)."""
        if service.batcher is None:
            raise HTTPException(503, "no gateway key configured")
        batch = await service.batcher.flush()
        return {"committed": batch.to_dict() if batch else None, "pending": service.batcher.pending}

    @app.get("/policy")
    async def policy() -> dict[str, Any]:
        """The policy in force on-chain (None if unreachable)."""
        current = await asyncio.to_thread(service.policy.policy)
        return {"policy": current.__dict__ if current else None}

    @app.get("/publishers")
    async def publishers() -> list[dict[str, Any]]:
        """Every publisher that ever registered (from events) with its live record."""
        return await service.list_publishers()

    @app.get("/models")
    async def models() -> list[dict[str, Any]]:
        """Every model hash ever registered (from events) with its live status."""
        return await service.list_models()

    @app.get("/devices")
    async def devices() -> list[dict[str, Any]]:
        """Every device that said hello."""
        return [d.__dict__ for d in service.devices.all()]

    @app.post("/devices/hello")
    async def device_hello(msg: SignedMessage) -> dict[str, Any]:
        """First contact: pins the device key (TOFU); later hellos must use the pinned key."""
        return (await service.device_hello(msg)).__dict__

    @app.post("/devices/poll")
    async def device_poll(msg: SignedMessage) -> dict[str, Any]:
        """Ask for an approved update newer than ``installedVersion``."""
        return await service.device_poll(msg)

    @app.post("/devices/receipt")
    async def device_receipt(msg: SignedMessage) -> dict[str, Any]:
        """Submit a signed install receipt."""
        return (await service.device_receipt(msg)).__dict__

    # ------------------------------------------------------------ publisher portal
    # The portal acts for the publisher configured in ``.env`` (``PUBLISHER_DID`` + the key under
    # ``KEYS_DIR``). Signing and the chain transaction happen in the ``verigate-publish`` CLI,
    # spawned as a subprocess like the attack scripts, so the gateway keeps its dependency rule.
    background: set[asyncio.Task[Any]] = set()

    @app.get("/publisher/me")
    async def publisher_me() -> dict[str, Any]:
        """The portal's publisher identity and on-chain standing."""
        did = service.settings.publisher_did
        pid = publisher_id(did)
        record = await asyncio.to_thread(service.chain.get_publisher, pid)
        return {
            "did": did,
            "publisherId": "0x" + pid.hex(),
            "registered": record.exists,
            "status": record.status,
            "reputation": record.reputation_bp if record.exists else None,
            "publicKey": "ed25519:" + record.pub_key.hex() if record.exists else None,
            "keyVersion": record.key_version,
        }

    @app.post("/publisher/releases")
    async def publisher_release(
        firmware: Annotated[UploadFile, File()],
        sbom: Annotated[UploadFile, File()],
        version: Annotated[str, Form()],
        device_model: Annotated[str, Form()],
        expiry: Annotated[str, Form()],
    ) -> dict[str, Any]:
        """Publish: hash → IPFS → signed manifest → on-chain record; verification runs after."""
        try:
            SemVer.parse(version)
        except ValueError as exc:
            raise HTTPException(400, f"version must be MAJOR.MINOR.PATCH: {exc}") from exc
        try:
            when = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(400, "expiry must be an ISO-8601 date") from exc
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        if when <= datetime.now(UTC):
            raise HTTPException(400, "expiry must be in the future")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", device_model):
            raise HTTPException(400, "device model: letters, digits, . _ - only")
        with tempfile.TemporaryDirectory(prefix="verigate-publish-") as tmp:
            fw_path, sbom_path = Path(tmp) / "firmware.bin", Path(tmp) / "sbom.json"
            fw_path.write_bytes(await firmware.read())
            sbom_path.write_bytes(await sbom.read())
            if fw_path.stat().st_size == 0:
                raise HTTPException(400, "firmware file is empty")
            try:
                json.loads(sbom_path.read_bytes())
            except ValueError as exc:
                raise HTTPException(400, "SBOM must be a CycloneDX JSON document") from exc
            result = await _run_cli(
                "verigate-publish",
                [
                    "release",
                    "--fw",
                    str(fw_path),
                    "--sbom",
                    str(sbom_path),
                    "--version",
                    version,
                    "--model",
                    device_model,
                    "--expiry",
                    when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                ],
            )
        if "error" in result:
            raise HTTPException(400, str(result["error"]))
        await _after_publish(_release_id(str(result["releaseId"])))
        return result

    async def _after_publish(rid: bytes) -> None:
        with contextlib.suppress(VerigateError):
            await service.note_release(rid)
        task = asyncio.create_task(_verify_quietly(rid))
        background.add(task)
        task.add_done_callback(background.discard)

    async def _verify_quietly(rid: bytes) -> None:
        with contextlib.suppress(Exception):  # the listener re-verifies on its own schedule
            await service.verify(rid)

    @app.post("/publisher/releases/{release_id}/withdraw")
    async def publisher_withdraw(release_id: str) -> dict[str, Any]:
        """Withdraw (revoke) one of the portal publisher's own releases."""
        rid = _release_id(release_id)
        record = await asyncio.to_thread(service.chain.get_release, rid)
        if not record.exists:
            raise HTTPException(404, "unknown release")
        if record.publisher_id != publisher_id(service.settings.publisher_did):
            raise HTTPException(403, "this release belongs to another publisher")
        result = await _run_cli("verigate-publish", ["revoke", "0x" + rid.hex()])
        if "error" in result:
            raise HTTPException(400, str(result["error"]))
        with contextlib.suppress(VerigateError):
            await service.refresh_releases()
        return result

    # ------------------------------------------------------------ guided demonstration

    @app.post("/story/publish")
    async def story_publish(fixture: str = Query(default="v2.0.0")) -> dict[str, Any]:
        """Publish one of the bundled real-firmware fixtures as the portal publisher (demo page).

        Same path as the publisher portal — signing CLI as a subprocess, verification in the
        background — with the files taken from the repository's fixtures and the version chosen
        as the next patch after the publisher's last release for ``demo-device``.
        """
        if fixture not in STORY_FIXTURES:
            raise HTTPException(400, f"unknown fixture; choose one of {sorted(STORY_FIXTURES)}")
        root = next((d for d in FIXTURE_DIRS if (d / fixture).is_dir()), None)
        if root is None:
            raise HTTPException(500, "release fixtures are not available on this gateway")
        pid = publisher_id(service.settings.publisher_did)
        packed = int(
            await asyncio.to_thread(
                service.chain.call,
                service.chain.firmware.functions.lastVersion(pid, device_model_id("demo-device")),
            )
        )
        major, minor, patch = packed >> 64, (packed >> 32) & 0xFFFFFFFF, packed & 0xFFFFFFFF
        version = f"{major}.{minor}.{patch + 1}" if packed else "1.0.0"
        result = await _run_cli(
            "verigate-publish",
            [
                "release",
                "--fw",
                str(root / fixture / "firmware.bin"),
                "--sbom",
                str(root / fixture / "sbom.json"),
                "--version",
                version,
                "--model",
                "demo-device",
                "--expiry",
                "2030-01-01T00:00:00Z",
            ],
        )
        if "error" in result:
            raise HTTPException(400, str(result["error"]))
        await _after_publish(_release_id(str(result["releaseId"])))
        return {**result, "fixture": fixture}

    @app.post("/simulate/device")
    async def simulate_device() -> dict[str, Any]:
        """One emulated device polls once: verify, install, receipt (demo page, step 7)."""
        own_url = f"http://127.0.0.1:{service.settings.gateway_port}"
        state = service.state_dir / "story-device"
        return await _run_cli(
            "verigate-fleet",
            [
                "run",
                "--count",
                "1",
                "--rounds",
                "1",
                "--interval",
                "0.1",
                "--prefix",
                "panel",
                "--state-dir",
                str(state),
                "--gateway",
                own_url,
            ],
        )

    @app.get("/attacks")
    async def attacks() -> dict[str, Any]:
        """Available attack scenarios (from ``verigate-attack list``)."""
        return await _run_attack_cli(["list"])

    @app.post("/attacks/{name}")
    async def run_attack(name: str) -> dict[str, Any]:
        """Run one scenario against this gateway (dashboard attack buttons). Synchronous."""
        if not re.fullmatch(r"[a-z\-]+", name):
            raise HTTPException(400, "bad attack name")
        own_url = f"http://127.0.0.1:{service.settings.gateway_port}"
        report = await _run_attack_cli(["run", name, "--gateway", own_url])
        if "error" in report:
            raise HTTPException(400, str(report["error"]))
        return report

    @app.websocket("/logs")
    async def logs(websocket: WebSocket) -> None:
        """Stream structured log events as JSON lines."""
        await websocket.accept()
        try:
            async for event in hub.subscribe():
                await websocket.send_text(json.dumps(event, default=str))
        except (WebSocketDisconnect, RuntimeError):
            return

    return app


async def _run_attack_cli(args: list[str]) -> dict[str, Any]:
    """Spawn ``verigate-attack`` (keeps the gateway free of fleet/attack imports) and parse JSON."""
    return await _run_cli("verigate-attack", args)


async def _run_cli(name: str, args: list[str]) -> dict[str, Any]:
    """Spawn one of the project's CLIs from the same environment and parse its JSON output."""
    exe = shutil.which(name) or str(Path(sys.executable).with_name(name))
    proc = await asyncio.create_subprocess_exec(
        exe, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await asyncio.wait_for(proc.communicate(), timeout=180)
    text = out.decode()
    if not text.strip():
        raise HTTPException(500, f"{name} produced no output: " + err.decode()[-500:])
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(text.lstrip())
    if not isinstance(obj, dict):
        raise HTTPException(500, f"unexpected {name} output")
    return obj


def build_service(settings: Settings) -> GatewayService:
    """Real clients from settings (used by ``run`` and by the attack CLI)."""
    service = GatewayService(
        settings=settings,
        chain=ChainClient(settings),
        ipfs=make_backend(settings),
        state_dir=settings.state_dir,
    )
    service.scorer = build_scorer(settings)
    service.explainer = build_explainer(settings, service.ipfs)
    return service


def run() -> None:
    """``verigate-gateway`` entry point."""
    settings = get_settings()
    configure_logging(settings, extra_processors=[hub.processor])
    app = create_app(build_service(settings))
    uvicorn.run(app, host=settings.gateway_host, port=settings.gateway_port, log_level="warning")


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazily build ``app`` for ``uvicorn …:app`` (``make gateway``) with no import side effects."""
    if name == "app":
        settings = get_settings()
        configure_logging(settings, extra_processors=[hub.processor])
        return create_app(build_service(settings))
    raise AttributeError(name)
