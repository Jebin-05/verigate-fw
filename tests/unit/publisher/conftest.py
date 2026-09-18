"""An in-memory stand-in for ChainClient so publisher logic is unit-testable without a node."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from hexbytes import HexBytes

from verigate.common.chain import (
    STATUS_ACTIVE,
    STATUS_NONE,
    STATUS_REVOKED,
    ContractRevertError,
    PublisherRecord,
    ReleaseRecord,
    publisher_id,
)


@dataclass
class FakeAccount:
    address: str
    key: bytes = b"\x11" * 32


@dataclass
class _Call:
    contract: str
    name: str
    args: tuple[Any, ...]


class _Functions:
    def __init__(self, contract: str) -> None:
        self._contract = contract

    def __getattr__(self, name: str) -> Any:
        return lambda *args: _Call(self._contract, name, args)


class _Contract:
    def __init__(self, name: str) -> None:
        self.functions = _Functions(name)


@dataclass
class FakeChain:
    """Enough of ChainClient for release.py: publishers/releases state + a `send` interpreter."""

    publishers_state: dict[bytes, PublisherRecord] = field(default_factory=dict)
    releases: dict[bytes, ReleaseRecord] = field(default_factory=dict)
    sent: list[_Call] = field(default_factory=list)
    revert_next: str | None = None
    block: int = 10

    def __post_init__(self) -> None:
        self.publishers = _Contract("publishers")
        self.firmware = _Contract("firmware")

    def account(self, key: str) -> FakeAccount:
        return FakeAccount("0x" + key[-40:])

    def get_publisher(self, pid: bytes) -> PublisherRecord:
        return self.publishers_state.get(
            pid, PublisherRecord(pid, "", "0x" + "0" * 40, b"\x00" * 32, STATUS_NONE, 0, 0, 0, 0)
        )

    def get_release(self, rid: bytes) -> ReleaseRecord:
        return self.releases.get(rid, _empty_release(rid))

    def revoke_publisher(self, pid: bytes) -> None:
        r = self.publishers_state[pid]
        self.publishers_state[pid] = PublisherRecord(
            pid,
            r.did,
            r.owner,
            r.pub_key,
            STATUS_REVOKED,
            r.reputation_bp,
            r.key_version,
            r.registered_at,
            5,
        )

    def send(self, call: _Call, account: FakeAccount) -> dict[str, Any]:
        if self.revert_next:
            name, self.revert_next = self.revert_next, None
            raise ContractRevertError(name, None)
        self.sent.append(call)
        self.block += 1
        if call.name == "register" and call.contract == "publishers":
            did, pub = call.args
            pid = publisher_id(did)
            self.publishers_state[pid] = PublisherRecord(
                pid, did, account.address, pub, STATUS_ACTIVE, 5000, 0, self.block, 0
            )
        elif call.name == "rotateKey":
            pid = next(p for p, r in self.publishers_state.items() if r.owner == account.address)
            r = self.publishers_state[pid]
            self.publishers_state[pid] = PublisherRecord(
                pid,
                r.did,
                r.owner,
                call.args[0],
                r.status,
                r.reputation_bp,
                r.key_version + 1,
                r.registered_at,
                0,
            )
        elif call.name == "register" and call.contract == "firmware":
            rec = call.args[0]
            rid = rec["manifestHash"]
            self.releases[rid] = ReleaseRecord(
                rid,
                b"\x01" * 32,
                b"\x02" * 32,
                rec["major"],
                rec["minor"],
                rec["patch"],
                rid,
                rec["firmwareHash"],
                rec["sbomHash"],
                rec["expiry"],
                self.block,
                False,
                rec["deviceModel"],
                rec["manifestCid"],
                rec["firmwareCid"],
                rec["sbomCid"],
                rec["signature"],
            )
        elif call.name == "revoke":
            r = self.releases[call.args[0]]
            self.releases[call.args[0]] = ReleaseRecord(**{**r.__dict__, "revoked": True})
        return {
            "transactionHash": HexBytes(bytes([len(self.sent)]) * 32),
            "status": 1,
            "blockNumber": self.block,
        }


def _empty_release(rid: bytes) -> ReleaseRecord:
    return ReleaseRecord(
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
    )


@pytest.fixture
def fake_chain() -> FakeChain:
    return FakeChain()
