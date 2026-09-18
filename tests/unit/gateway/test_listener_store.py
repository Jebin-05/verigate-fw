"""Listener (resumable, backoff, never skips) and the JSON stores under STATE_DIR."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fake_chain import FIXTURES, FakeChain, publish

from verigate.common.crypto import KeyPair
from verigate.common.errors import ChainError
from verigate.common.ipfs import LocalCidBackend
from verigate.gateway.listener import MAX_RANGE, NewReleaseListener
from verigate.gateway.store import Cursor, DeviceRecord, DeviceStore, VerdictLog

FW = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()


@pytest.fixture
def chain(tmp_path: Path) -> FakeChain:
    c = FakeChain()
    key = KeyPair.generate()
    c.add_publisher("did:verigate:l", key)
    ipfs = LocalCidBackend(tmp_path / "ipfs")
    publish(c, ipfs, key, "did:verigate:l", "1.0.0", FW)
    publish(c, ipfs, key, "did:verigate:l", "1.1.0", FW + b"1")
    return c


async def test_poll_once_handles_events_and_advances_cursor(
    chain: FakeChain, tmp_path: Path
) -> None:
    seen: list[tuple[bytes, int]] = []

    async def on_release(rid: bytes, block: int) -> None:
        seen.append((rid, block))

    cursor = Cursor(tmp_path / "listener.json")
    listener = NewReleaseListener(chain, cursor, on_release)  # type: ignore[arg-type]
    assert await listener.poll_once() == 2
    assert [b for _, b in seen] == [101, 102]
    assert cursor.last_block == chain.block
    assert await listener.poll_once() == 0  # nothing new
    assert Cursor(tmp_path / "listener.json").last_block == chain.block  # persisted


async def test_resumes_from_cursor_and_chunks_ranges(chain: FakeChain, tmp_path: Path) -> None:
    seen: list[int] = []

    async def on_release(_rid: bytes, block: int) -> None:
        seen.append(block)

    cursor = Cursor(tmp_path / "listener.json")
    cursor.advance(101)  # first event already handled in a previous life
    chain.block = 101 + MAX_RANGE * 2 + 5  # force several get_logs windows
    listener = NewReleaseListener(chain, cursor, on_release)  # type: ignore[arg-type]
    assert await listener.poll_once() == 1
    assert seen == [102]
    assert cursor.last_block == chain.block


async def test_rpc_error_leaves_cursor_untouched_and_backs_off(
    chain: FakeChain, tmp_path: Path
) -> None:
    async def on_release(_rid: bytes, _block: int) -> None:
        pass

    cursor = Cursor(tmp_path / "listener.json")
    listener = NewReleaseListener(
        chain, cursor, on_release, poll_interval_s=0.01, max_backoff_s=0.04
    )  # type: ignore[arg-type]
    chain.down = True
    with pytest.raises(ChainError):
        await listener.poll_once()
    assert cursor.last_block == -1
    stop = asyncio.Event()
    task = asyncio.create_task(listener.run(stop))
    await asyncio.sleep(0.15)
    assert listener.errors >= 2
    assert listener.backoff_s == 0.04  # capped
    chain.down = False
    await asyncio.sleep(0.15)
    assert listener.events == 2 and cursor.last_block == chain.block
    assert listener.backoff_s == 0.01  # reset after success
    stop.set()
    await task


async def test_cursor_ahead_of_chain_rewinds(chain: FakeChain, tmp_path: Path) -> None:
    seen: list[int] = []

    async def on_release(_rid: bytes, block: int) -> None:
        seen.append(block)

    cursor = Cursor(tmp_path / "listener.json")
    cursor.advance(5_000)  # persisted from a previous chain instance
    listener = NewReleaseListener(chain, cursor, on_release)  # type: ignore[arg-type]
    assert await listener.poll_once() == 2
    assert seen == [101, 102] and cursor.last_block == chain.block


async def test_get_logs_failure_is_a_chain_error(chain: FakeChain, tmp_path: Path) -> None:
    async def on_release(_rid: bytes, _block: int) -> None:
        pass

    listener = NewReleaseListener(chain, Cursor(tmp_path / "c.json"), on_release)  # type: ignore[arg-type]

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("socket closed")

    chain.firmware.events.NewRelease().get_logs = boom  # type: ignore[method-assign]
    chain.firmware.events.NewRelease = lambda: type("E", (), {"get_logs": staticmethod(boom)})()  # type: ignore[method-assign]
    with pytest.raises(ChainError, match="get_logs failed"):
        await listener.poll_once()


def test_device_store_round_trip(tmp_path: Path) -> None:
    store = DeviceStore(tmp_path / "devices.json")
    assert store.get("x") is None and store.all() == []
    rec = DeviceRecord("dev-2", "demo-device", "ed25519:00", "1.0.0", 3, 10)
    store.put(rec)
    store.put(DeviceRecord("dev-1", "demo-device", "ed25519:01", "0.0.0", 1, 11, "0xabc", 2))
    reloaded = DeviceStore(tmp_path / "devices.json")
    assert reloaded.get("dev-2") == rec
    assert [d.device_id for d in reloaded.all()] == ["dev-1", "dev-2"]
    assert reloaded.get("dev-1") is not None and reloaded.get("dev-1").receipts == 2


def test_verdict_log_round_trip_and_tail(tmp_path: Path) -> None:
    log = VerdictLog(tmp_path / "v.jsonl", keep_in_memory=3)
    for i in range(5):
        log.append({"i": i})
    assert [e["i"] for e in log.recent(10)] == [2, 3, 4]
    assert [e["i"] for e in log] == [2, 3, 4]
    assert [e["i"] for e in log.recent(2)] == [3, 4]
    reloaded = VerdictLog(tmp_path / "v.jsonl", keep_in_memory=3)
    assert [e["i"] for e in reloaded.recent(10)] == [2, 3, 4]
    assert len((tmp_path / "v.jsonl").read_text().splitlines()) == 5


def test_cursor_persistence(tmp_path: Path) -> None:
    assert Cursor(tmp_path / "c.json").last_block == -1
    Cursor(tmp_path / "c.json").advance(42)
    assert Cursor(tmp_path / "c.json").last_block == 42
