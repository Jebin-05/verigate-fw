"""P3-09: Stage 1 through the real GatewayService against deployed contracts + IPFS backend."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient
from verigate.common.crypto import KeyPair
from verigate.common.ipfs import IpfsBackend
from verigate.common.manifest import SemVer
from verigate.common.settings import Settings
from verigate.gateway.service import GatewayService
from verigate.gateway.stage1.inputs import DeviceView
from verigate.publisher.release import publish_release, revoke_release

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "releases"


@pytest.fixture
def service(
    live_settings: Settings, chain: ChainClient, ipfs: IpfsBackend, tmp_path: Path
) -> GatewayService:
    return GatewayService(
        settings=live_settings, chain=chain, ipfs=ipfs, state_dir=tmp_path / "state"
    )


async def test_stage1_against_live_contracts(
    service: GatewayService, chain: ChainClient, ipfs: IpfsBackend, funded_account: LocalAccount
) -> None:
    did = f"did:verigate:s1-{secrets.token_hex(4)}"
    key = KeyPair.generate()
    result = publish_release(
        chain=chain,
        ipfs=ipfs,
        account=funded_account,
        key=key,
        did=did,
        firmware_path=FIXTURES / "v1.0.0" / "firmware.bin",
        sbom_path=FIXTURES / "v1.0.0" / "sbom.json",
        version="1.0.0",
        device_model="demo-device",
        expiry=datetime(2030, 1, 1, tzinfo=UTC),
    )
    rid = bytes.fromhex(result.releaseId[2:])

    approved = await service.verify(rid)
    assert approved.verdict.value == "APPROVE", approved.to_dict()
    assert approved.stage1 is not None and [c.ok for c in approved.stage1.results] == [True] * 8

    rolled_back = await service.verify(rid, DeviceView("dev-live", "demo-device", SemVer(1, 0, 0)))
    assert rolled_back.stage1 is not None and rolled_back.stage1.failed == "version_monotonic"

    wrong_model = await service.verify(rid, DeviceView("dev-live", "acme-lock", SemVer(0, 0, 0)))
    assert wrong_model.stage1 is not None and wrong_model.stage1.failed == "version_monotonic"

    revoke_release(chain, funded_account, rid)
    revoked = await service.verify(rid)
    assert revoked.verdict.value == "REJECT" and revoked.stage1 is not None
    assert revoked.stage1.failed == "registry_record"
    assert "revoked" in (revoked.reason or "")

    unknown = await service.verify(b"\x42" * 32)
    assert unknown.verdict.value == "REJECT"

    assert await service.refresh_releases() >= 1
    assert any(r.release_id == rid and r.revoked for r in service.known_releases())
    assert [v["verdict"] for v in service.verdicts.recent(5)] == [
        "APPROVE",
        "REJECT",
        "REJECT",
        "REJECT",
        "REJECT",
    ]
