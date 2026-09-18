"""In-memory ChainClient stand-in for gateway/listener tests (no node, no web3)."""

from __future__ import annotations

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


class _Event:
    def __init__(self, chain: FakeChain) -> None:
        self._chain = chain

    def get_logs(self, from_block: int, to_block: int) -> list[dict[str, Any]]:
        self._chain.raise_if_down()
        return [
            {"args": {"releaseId": rid}, "blockNumber": block}
            for rid, block in self._chain.events
            if from_block <= block <= to_block
        ]


class _Events:
    def __init__(self, chain: FakeChain) -> None:
        self._chain = chain

    def NewRelease(self) -> _Event:  # noqa: N802 — mirrors web3's API
        return _Event(self._chain)


class _Firmware:
    def __init__(self, chain: FakeChain) -> None:
        self.events = _Events(chain)


@dataclass
class FakeChain:
    """Publishers, releases, models and NewRelease events, all in memory."""

    publishers: dict[bytes, PublisherRecord] = field(default_factory=dict)
    releases: dict[bytes, ReleaseRecord] = field(default_factory=dict)
    models: dict[bytes, ModelRecord] = field(default_factory=dict)
    events: list[tuple[bytes, int]] = field(default_factory=list)
    block: int = 100
    down: bool = False
    policy: PolicyRecord = PolicyRecord(4000, 4000, 2000, 3000, 6000, 1, "0x" + "0" * 40, 1)

    def __post_init__(self) -> None:
        self.firmware = _Firmware(self)

    # --- fault injection
    def raise_if_down(self) -> None:
        if self.down:
            raise ChainError("rpc failure: connection refused")

    def is_connected(self) -> bool:
        return not self.down

    def block_number(self) -> int:
        self.raise_if_down()
        return self.block

    # --- reads used by the gateway
    def get_publisher(self, pid: bytes) -> PublisherRecord:
        self.raise_if_down()
        return self.publishers.get(
            pid, PublisherRecord(pid, "", "0x" + "0" * 40, b"\x00" * 32, STATUS_NONE, 0, 0, 0, 0)
        )

    def get_release(self, rid: bytes) -> ReleaseRecord:
        self.raise_if_down()
        return self.releases.get(
            rid,
            ReleaseRecord(
                rid,
                b"\x00" * 32,
                b"\x00" * 32,
                0,
                0,
                0,
                b"\x00" * 32,
                b"\x00" * 32,
                b"\x00" * 32,
                0,
                0,
                False,
                "",
                "",
                "",
                "",
                b"",
            ),
        )

    def get_model(self, h: bytes) -> ModelRecord:
        self.raise_if_down()
        return self.models.get(h, ModelRecord(h, "", STATUS_NONE, b"\x00" * 32, 0, 0))

    def get_policy(self) -> PolicyRecord:
        self.raise_if_down()
        return self.policy

    def release_count(self) -> int:
        self.raise_if_down()
        return len(self.releases)

    def release_ids(self, start: int = 0, limit: int = 100) -> list[bytes]:
        self.raise_if_down()
        ordered = sorted(self.releases.values(), key=lambda r: r.registered_at)
        return [r.release_id for r in ordered[start : start + limit]]

    # --- state setup helpers (what deploy/publish would have done)
    def add_publisher(self, did: str, key: KeyPair, status: int = STATUS_ACTIVE) -> bytes:
        pid = publisher_id(did)
        self.publishers[pid] = PublisherRecord(
            pid, did, "0x" + "ab" * 20, key.public, status, 5000, 0, 1, 0
        )
        return pid

    def set_publisher_status(self, pid: bytes, status: int) -> None:
        r = self.publishers[pid]
        self.publishers[pid] = PublisherRecord(
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
        self.models[h] = ModelRecord(h, "m", status, b"\x00" * 32, 1, 0)

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


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"
