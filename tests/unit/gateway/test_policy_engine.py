"""Policy engine: every branch of decide(), per-block caching, DEFER on outage."""

from __future__ import annotations

import pytest
from fake_chain import FakeChain
from hypothesis import given
from hypothesis import strategies as st

from verigate.common.chain import PolicyRecord
from verigate.gateway.policy.engine import BASIS, PolicyEngine, decide
from verigate.gateway.verdicts.types import Verdict

POLICY = PolicyRecord(4000, 4000, 2000, 3000, 6000, 7, "0x" + "0" * 40, 1)


@pytest.mark.parametrize(
    ("r_sbom", "r_img", "rep", "expected_r", "verdict"),
    [
        (0, 0, 10_000, 0, Verdict.APPROVE),
        (0, 0, 5000, 1000, Verdict.APPROVE),
        (0, 0, 0, 2000, Verdict.APPROVE),
        (2500, 2500, 5000, 3000, Verdict.DEFER),  # exactly tau_approve → not below → DEFER
        (2499, 2500, 5000, 3000, Verdict.DEFER),  # 2999.6 rounds to 3000
        (2498, 2500, 5000, 2999, Verdict.APPROVE),
        (5000, 5000, 5000, 5000, Verdict.DEFER),
        (7500, 7500, 5000, 7000, Verdict.REJECT),
        (6250, 6250, 5000, 6000, Verdict.REJECT),  # exactly tau_reject → REJECT
        (10_000, 10_000, 0, 10_000, Verdict.REJECT),
    ],
)
def test_decide_table(r_sbom: int, r_img: int, rep: int, expected_r: int, verdict: Verdict) -> None:
    d = decide(POLICY, r_sbom, r_img, rep)
    assert d.r_bp == expected_r
    assert d.verdict is verdict
    assert d.policy_version == 7
    assert "R=" in d.reason


def test_decide_defers_on_missing_inputs() -> None:
    assert decide(None, 0, 0, 0).verdict is Verdict.DEFER
    assert decide(None, 0, 0, 0).reason == "policy unavailable"
    d = decide(POLICY, None, 0, None)
    assert d.verdict is Verdict.DEFER and d.reason == "missing r_sbom, reputation"
    assert d.r_bp == BASIS


@pytest.mark.parametrize("bad", [-1, 10_001])
def test_decide_defers_on_out_of_range(bad: int) -> None:
    assert decide(POLICY, bad, 0, 0).verdict is Verdict.DEFER
    assert decide(POLICY, 0, bad, 0).reason == f"r_img out of range: {bad}"
    assert decide(POLICY, 0, 0, bad).verdict is Verdict.DEFER


bp = st.integers(min_value=0, max_value=BASIS)


@given(bp, bp, bp)
def test_decide_matches_float_formula(r_sbom: int, r_img: int, rep: int) -> None:
    d = decide(POLICY, r_sbom, r_img, rep)
    expected = 0.4 * r_sbom + 0.4 * r_img + 0.2 * (BASIS - rep)
    assert abs(d.r_bp - expected) <= 1
    assert d.verdict is (
        Verdict.APPROVE if d.r_bp < 3000 else Verdict.REJECT if d.r_bp >= 6000 else Verdict.DEFER
    )


def test_decide_is_deterministic() -> None:
    assert decide(POLICY, 1234, 4321, 777) == decide(POLICY, 1234, 4321, 777)


async def test_engine_caches_per_block_and_defers_on_outage() -> None:
    chain = FakeChain()
    engine = PolicyEngine(chain)  # type: ignore[arg-type]
    first = await engine.decide(0, 0, 5000)
    assert first.verdict is Verdict.APPROVE and first.policy_version == 1
    chain.policy_record = PolicyRecord(4000, 4000, 2000, 500, 600, 2, "0x" + "0" * 40, 2)
    assert (await engine.decide(0, 0, 5000)).policy_version == 1  # same block → cached
    chain.block += 1
    assert (await engine.decide(0, 0, 5000)).policy_version == 2  # new block → re-read
    chain.down = True
    outage = await engine.decide(0, 0, 5000)
    assert outage.verdict is Verdict.DEFER and outage.reason == "policy unavailable"
    assert engine.policy() is None
