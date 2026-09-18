"""Shared plumbing for experiments on the live dev stack (hardhat + IPFS, optionally the gateway).

Every live experiment publishes the fixture releases under its *own* fresh publisher, so runs are
independent of the demo publisher's version lineage and reputation, and records the chain /
IPFS / model configuration it ran against in ``env.json``.
"""

from __future__ import annotations

import hashlib
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from common import ROOT

from verigate.attacks.common import AttackContext
from verigate.common.manifest import SemVer
from verigate.common.settings import Settings, get_settings
from verigate.gateway.api.main import build_service
from verigate.gateway.service import GatewayService
from verigate.gateway.stage1.inputs import DeviceView

FIXTURES = ROOT / "tests" / "fixtures" / "releases"
FIXTURE_VERSIONS = ("1.0.0", "1.1.0", "2.0.0")


def eval_settings(**overrides: Any) -> Settings:
    """``.env`` settings with the explainer off and a throw-away state directory.

    Timing experiments must not be perturbed by a CPU-bound language model; the explainer's own
    cost is measured separately (``latency_stage2``, ``llm`` section).
    """
    base = get_settings()
    state = Path(tempfile.mkdtemp(prefix="verigate-eval-"))
    return base.model_copy(update={"llm_enabled": False, "state_dir": state, **overrides})


def publish_fixtures(ctx: AttackContext, prefix: str) -> tuple[str, dict[str, str]]:
    """Publish the three fixture releases under a fresh publisher; returns (did, {version: rid})."""
    did, key, account = ctx.new_publisher(prefix)
    rids: dict[str, str] = {}
    for version in FIXTURE_VERSIONS:
        manifest = ctx.build_manifest(
            ctx.fixture(version, "firmware.bin"),
            ctx.fixture(version, "sbom.json"),
            SemVer.parse(version),
            did=did,
        )
        rids[version] = ctx.publish(manifest.sign(key), account)
    return did, rids


async def in_process_gateway(settings: Settings) -> GatewayService:
    """A ``GatewayService`` on the real clients (no HTTP, no listener) with releases loaded."""
    service = build_service(settings)
    await service.refresh_releases()
    return service


def device_view(i: int, installed: str = "0.1.0") -> DeviceView:
    """The i-th emulated device of an experiment fleet."""
    return DeviceView(f"eval-dev-{i:03d}", "demo-device", SemVer.parse(installed))


@contextmanager
def stopwatch() -> Iterator[dict[str, float]]:
    """``with stopwatch() as t: ...; t["ms"]``."""
    box: dict[str, float] = {}
    start = time.perf_counter()
    try:
        yield box
    finally:
        box["ms"] = (time.perf_counter() - start) * 1000.0


def stack_info(settings: Settings, ctx: AttackContext) -> dict[str, Any]:
    """What ``env.json`` records about the stack every live experiment ran against."""
    models = {
        p.relative_to(ROOT / "models").as_posix(): "0x" + hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((ROOT / "models").rglob("*.onnx"))
    }
    return {
        "rpc_url": settings.rpc_url,
        "chain_id": settings.chain_id,
        "contracts": ctx.chain.addresses.__dict__,
        "ipfs_backend": settings.ipfs_backend,
        "stage2_model_hashes": settings.stage2_model_hashes,
        "models": models,
        "vulndb_snapshot_date": settings.stage2_epss_date,
        "vuln_cache_only": settings.vuln_cache_only,
        "llm_enabled": settings.llm_enabled,
    }
