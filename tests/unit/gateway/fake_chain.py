"""In-memory ChainClient stand-in for gateway/listener tests (no node, no web3)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verigate.common.chain import (
    STATUS_ACTIVE,
    STATUS_NONE,
    ModelRecord,
    PolicyRecord,
    PublisherRecord,
    ReleaseRecord,
    device_model_id,
    publisher_id,
)
from verigate.common.crypto import KeyPair, parse_hash, parse_signature, sha256_hex
from verigate.common.errors import ChainError
from verigate.common.ipfs import IpfsBackend
from verigate.common.manifest import Cids, Manifest, SemVer, SignedManifest

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"


class FakeAccount:
    """LocalAccount look-alike (address derived from the key text)."""

    def __init__(self, key: str) -> None:
        self.key = key
        self.address = "0x" + hashlib.sha256(key.encode()).hexdigest()[:40]


class _Call:
    def __init__(self, name: str, args: tuple[Any, ...]) -> None:
        self.name = name
        self.args = args


class _Functions:
    def __getattr__(self, name: str) -> Any:
        return lambda *args: _Call(name, args)


class _EventQuery:
    def __init__(self, chain: FakeChain, kind: str) -> None:
        self._chain = chain
        self._kind = kind

    def get_logs(self, from_block: int = 0, to_block: int | None = None) -> list[dict[str, Any]]:
        self._chain.raise_if_down()
        if self._kind == "NewRelease":
            hi = to_block if to_block is not None else 10**9
            return [
                {"args": {"releaseId": rid}, "blockNumber": block}
                for rid, block in self._chain.events
                if from_block <= block <= hi
            ]
        if self._kind == "PublisherRegistered":
            return [{"args": {"publisherId": pid}} for pid in self._chain.publisher_records]
        if self._kind == "ModelRegistered":
            return [{"args": {"modelHash": h}} for h in self._chain.model_records]
        return []

    def process_receipt(self, receipt: dict[str, Any], **_: Any) -> list[dict[str, Any]]:
        return [{"args": {"batchId": receipt["batchId"]}}]


class _Events:
    def __init__(self, chain: FakeChain) -> None:
        self._chain = chain

    def __getattr__(self, name: str) -> Any:
        return lambda: _EventQuery(self._chain, name)


class _Contract:
    def __init__(self, chain: FakeChain) -> None:
        self.functions = _Functions()
        self.events = _Events(chain)


@dataclass
class FakeChain:
    """Publishers, releases, models and NewRelease events, all in memory."""

    publisher_records: dict[bytes, PublisherRecord] = field(default_factory=dict)
    releases: dict[bytes, ReleaseRecord] = field(default_factory=dict)
    model_records: dict[bytes, ModelRecord] = field(default_factory=dict)
    events: list[tuple[bytes, int]] = field(default_factory=list)
    committed: list[dict[str, Any]] = field(default_factory=list)
    reputations: list[tuple[bytes, int]] = field(default_factory=list)
    block: int = 100
    down: bool = False
    policy_record: PolicyRecord = PolicyRecord(4000, 4000, 2000, 4500, 7000, 1, "0x" + "0" * 40, 1)

    def __post_init__(self) -> None:
        from verigate.common.chain import ContractAddresses  # noqa: PLC0415

        self.addresses = ContractAddresses(
            *["0x" + f"{i:040x}" for i in range(1, 6)], chain_id=31337
        )
        self.firmware = _Contract(self)
        self.publishers = _Contract(self)
        self.models = _Contract(self)
        self.verdicts = _Contract(self)
        self.policy = _Contract(self)

    # --- fault injection
    def raise_if_down(self) -> None:
        if self.down:
            raise ChainError("rpc failure: connection refused")

    def is_connected(self) -> bool:
        return not self.down

    def block_number(self) -> int:
        self.raise_if_down()
        return self.block

    def account(self, key: str) -> FakeAccount:
        return FakeAccount(key)

    # --- reads used by the gateway
    def get_publisher(self, pid: bytes) -> PublisherRecord:
        self.raise_if_down()
        return self.publisher_records.get(
            pid, PublisherRecord(pid, "", "0x" + "0" * 40, b"\x00" * 32, STATUS_NONE, 0, 0, 0, 0)
        )

    def get_release(self, rid: bytes) -> ReleaseRecord:
        self.raise_if_down()
        return self.releases.get(rid, _empty_release(rid))

    def get_model(self, h: bytes) -> ModelRecord:
        self.raise_if_down()
        return self.model_records.get(h, ModelRecord(h, "", STATUS_NONE, b"\x00" * 32, 0, 0))

    def get_policy(self) -> PolicyRecord:
        self.raise_if_down()
        return self.policy_record

    def release_count(self) -> int:
        self.raise_if_down()
        return len(self.releases)

    def release_ids(self, start: int = 0, limit: int = 100) -> list[bytes]:
        self.raise_if_down()
        ordered = sorted(self.releases.values(), key=lambda r: r.registered_at)
        return [r.release_id for r in ordered[start : start + limit]]

    # --- writes used by the gateway (batcher, reputation)
    def send(self, call: _Call, account: FakeAccount) -> dict[str, Any]:
        self.raise_if_down()
        self.block += 1
        if call.name == "commitBatch":
            root, count, hashes = call.args
            batch_id = len(self.committed)
            self.committed.append(
                {
                    "root": root,
                    "count": count,
                    "modelHashes": hashes,
                    "block": self.block,
                    "gateway": account.address,
                }
            )
            return {
                "transactionHash": b"\xbb" * 32,
                "blockNumber": self.block,
                "status": 1,
                "batchId": batch_id,
            }
        if call.name == "setReputation":
            pid, bp = call.args
            r = self.publisher_records[pid]
            self.publisher_records[pid] = PublisherRecord(
                pid, r.did, r.owner, r.pub_key, r.status, bp, r.key_version, r.registered_at, 0
            )
            self.reputations.append((pid, bp))
            return {"transactionHash": b"\xcc" * 32, "blockNumber": self.block, "status": 1}
        raise AssertionError(f"unexpected call {call.name}")

    # --- state setup helpers (what deploy/publish would have done)
    def add_publisher(self, did: str, key: KeyPair, status: int = STATUS_ACTIVE) -> bytes:
        pid = publisher_id(did)
        self.publisher_records[pid] = PublisherRecord(
            pid, did, "0x" + "ab" * 20, key.public, status, 5000, 0, 1, 0
        )
        return pid

    def set_publisher_status(self, pid: bytes, status: int) -> None:
        r = self.publisher_records[pid]
        self.publisher_records[pid] = PublisherRecord(
            pid,
            r.did,
            r.owner,
            r.pub_key,
            status,
            r.reputation_bp,
            r.key_version,
            r.registered_at,
            self.block,
        )

    def add_model(self, h: bytes, status: int = STATUS_ACTIVE) -> None:
        self.model_records[h] = ModelRecord(h, "m", status, b"\x00" * 32, 1, 0)

    def add_release(
        self, signed: SignedManifest, manifest_cid: str, revoked: bool = False
    ) -> bytes:
        rid = signed.manifest_hash()
        self.block += 1
        self.releases[rid] = ReleaseRecord(
            release_id=rid,
            publisher_id=publisher_id(signed.publisherDid),
            device_model_id=device_model_id(signed.deviceModel),
            major=signed.version.major,
            minor=signed.version.minor,
            patch=signed.version.patch,
            manifest_hash=rid,
            firmware_hash=parse_hash(signed.firmwareHash),
            sbom_hash=parse_hash(signed.sbomHash),
            expiry=int(signed.expiry.timestamp()),
            registered_at=self.block,
            revoked=revoked,
            device_model=signed.deviceModel,
            manifest_cid=manifest_cid,
            firmware_cid=signed.cids.firmware,
            sbom_cid=signed.cids.sbom,
            signature=parse_signature(signed.signature),
        )
        self.events.append((rid, self.block))
        return rid

    def revoke_release(self, rid: bytes) -> None:
        r = self.releases[rid]
        self.releases[rid] = ReleaseRecord(**{**r.__dict__, "revoked": True})


def _empty_release(rid: bytes) -> ReleaseRecord:
    zero = b"\x00" * 32
    return ReleaseRecord(
        rid, zero, zero, 0, 0, 0, zero, zero, zero, 0, 0, False, "", "", "", "", b""
    )


def publish(
    chain: FakeChain,
    ipfs: IpfsBackend,
    key: KeyPair,
    did: str,
    version: str,
    firmware: bytes,
    sbom: bytes = b'{"bomFormat":"CycloneDX"}',
    model: str = "demo-device",
    expiry: datetime | None = None,
    firmware_cid: str | None = None,
    sbom_cid: str | None = None,
    revoked: bool = False,
) -> tuple[bytes, SignedManifest]:
    """What `verigate-publish release` does, against the fakes (with optional CID overrides)."""
    fw_cid = ipfs.put(firmware)
    sb_cid = ipfs.put(sbom)
    signed = Manifest(
        firmwareHash=sha256_hex(firmware),
        sbomHash=sha256_hex(sbom),
        version=SemVer.parse(version),
        deviceModel=model,
        expiry=expiry or datetime(2030, 1, 1, tzinfo=UTC),
        cids=Cids(firmware=firmware_cid or fw_cid, sbom=sbom_cid or sb_cid),
        publisherDid=did,
    ).sign(key)
    manifest_cid = ipfs.put(signed.model_dump_json().encode())
    return chain.add_release(signed, manifest_cid, revoked=revoked), signed
