"""P4-02 live: batched verdicts verify on-chain with VeriGate VerdictRegistry.verifyLeaf."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient, publisher_id
from verigate.common.crypto import KeyPair
from verigate.common.ipfs import IpfsBackend
from verigate.common.settings import Settings
from verigate.gateway.service import GatewayService
from verigate.gateway.verdicts.record import VerdictRecord
from verigate.publisher.release import publish_release

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "releases"


async def test_batch_commit_and_on_chain_proof(
    live_settings: Settings,
    chain: ChainClient,
    ipfs: IpfsBackend,
    funded_account: LocalAccount,
    tmp_path: Path,
) -> None:
    did = f"did:verigate:b-{secrets.token_hex(4)}"
    key = KeyPair.generate()
    published = publish_release(
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
    rid = bytes.fromhex(published.releaseId[2:])
    service = GatewayService(
        settings=live_settings.model_copy(update={"batch_max_size": 3}),
        chain=chain,
        ipfs=ipfs,
        state_dir=tmp_path / "state",
    )
    assert service.batcher is not None and service.gateway_account is not None
    results = [await service.verify(rid) for _ in range(3)]
    assert all(r.verdict.value == "APPROVE" for r in results)
    assert service.batcher.commits == 1 and service.batcher.pending == 0

    proof = service.batcher.proof(results[1].verdict_id or "")
    assert proof is not None and proof["status"] == "committed"
    batch = chain.get_batch(proof["batchId"])
    assert batch.count == 3 and "0x" + batch.root.hex() == proof["root"]
    assert batch.gateway == service.gateway_account.address
    ok = chain.call(
        chain.verdicts.functions.verifyLeaf(
            proof["batchId"],
            bytes.fromhex(proof["verdictId"][2:]),
            [bytes.fromhex(p[2:]) for p in proof["proof"]],
        )
    )
    assert ok is True
    wrong = chain.call(
        chain.verdicts.functions.verifyLeaf(
            proof["batchId"], b"\x01" * 32, [bytes.fromhex(p[2:]) for p in proof["proof"]]
        )
    )
    assert wrong is False
    record = VerdictRecord.model_validate(proof["record"])
    assert record.signer() == service.gateway_account.address

    # reputation: a release-level reject lowers the publisher's on-chain score
    before = chain.get_publisher(publisher_id(did)).reputation_bp
    from verigate.publisher.release import revoke_release  # noqa: PLC0415

    revoke_release(chain, funded_account, rid)
    rejected = await service.verify(rid)
    assert rejected.verdict.value == "REJECT"
    assert chain.get_publisher(publisher_id(did)).reputation_bp < before
