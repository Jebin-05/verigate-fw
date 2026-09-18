"""P2-05: the full publish flow against hardhat + the configured IPFS backend."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient, publisher_id
from verigate.common.crypto import KeyPair
from verigate.common.errors import VerificationError
from verigate.common.ipfs import IpfsBackend
from verigate.common.manifest import SignedManifest
from verigate.publisher.release import publish_release, revoke_release

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "releases"
EXPIRY = datetime(2030, 1, 1, tzinfo=UTC)


def _publish(
    chain: ChainClient,
    ipfs: IpfsBackend,
    account: LocalAccount,
    key: KeyPair,
    did: str,
    version: str,
):  # noqa: ANN202
    return publish_release(
        chain=chain,
        ipfs=ipfs,
        account=account,
        key=key,
        did=did,
        firmware_path=FIXTURES / f"v{version}" / "firmware.bin",
        sbom_path=FIXTURES / f"v{version}" / "sbom.json",
        version=version,
        device_model="demo-device",
        expiry=EXPIRY,
    )


def test_full_publish_flow(
    chain: ChainClient, ipfs: IpfsBackend, funded_account: LocalAccount
) -> None:
    did = f"did:verigate:flow-{secrets.token_hex(4)}"
    key = KeyPair.generate()

    v1 = _publish(chain, ipfs, funded_account, key, did, "1.0.0")
    assert v1.status == "registered" and v1.txHash is not None
    assert v1.cids["firmware"].startswith("bafybei")  # > 256 KiB → chunked dag-pb root

    # on-chain record matches the manifest fetched from IPFS, and the signature verifies under
    # the key that the publisher registered on-chain
    release_id = bytes.fromhex(v1.releaseId[2:])
    record = chain.get_release(release_id)
    assert record.exists and not record.revoked
    assert record.publisher_id == publisher_id(did)
    assert record.version == (1, 0, 0)
    assert record.manifest_cid == v1.cids["manifest"]
    signed = SignedManifest.model_validate_json(ipfs.get(record.manifest_cid))
    assert signed.manifest_hash() == record.manifest_hash == release_id
    assert signed.verify(chain.get_publisher(publisher_id(did)).pub_key)
    assert record.firmware_hash.hex() == signed.firmwareHash.removeprefix("sha256:")
    assert ipfs.get(signed.cids.firmware) == (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()

    # idempotent
    assert _publish(chain, ipfs, funded_account, key, did, "1.0.0").status == "unchanged"

    # newer version accepted, older rejected on-chain
    v11 = _publish(chain, ipfs, funded_account, key, did, "1.1.0")
    assert v11.status == "registered" and v11.releaseId != v1.releaseId
    with pytest.raises(VerificationError, match="VersionNotMonotonic"):
        publish_release(
            chain=chain,
            ipfs=ipfs,
            account=funded_account,
            key=key,
            did=did,
            firmware_path=FIXTURES / "v2.0.0" / "firmware.bin",
            sbom_path=FIXTURES / "v2.0.0" / "sbom.json",
            version="0.9.0",
            device_model="demo-device",
            expiry=EXPIRY,
        )

    # revoke
    assert revoke_release(chain, funded_account, release_id)["status"] == "revoked"
    assert chain.get_release(release_id).revoked is True
    assert revoke_release(chain, funded_account, release_id)["status"] == "unchanged"
