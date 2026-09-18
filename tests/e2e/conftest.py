"""End-to-end fixtures: a running gateway (GATEWAY_URL, default :8000) plus hardhat + IPFS.

Run locally with ``make infra-up && make contracts-deploy-local && make gateway`` in another
shell, or against the full compose stack (``make up``). Skipped when the gateway is unreachable.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pytest

from verigate.attacks.common import AttackContext, AttackReport
from verigate.common.errors import ChainError, VerigateError
from verigate.common.settings import Settings


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Run the happy path first: the attack scenarios burn the demo publisher's reputation
    (ADR-0006), after which its genuine releases are — correctly — deferred, not approved."""
    items.sort(key=lambda item: 0 if "test_full_stack" in item.nodeid else 1)


@pytest.fixture(scope="session")
def gateway_url() -> str:
    url = os.environ.get("GATEWAY_URL", f"http://127.0.0.1:{Settings().gateway_port}")
    try:
        if httpx.get(f"{url}/health", timeout=5).json().get("status") != "ok":
            pytest.skip("gateway not healthy")
    except (httpx.HTTPError, ValueError):
        pytest.skip(f"no gateway at {url}")
    return url


@pytest.fixture(scope="session")
def ctx(gateway_url: str) -> AttackContext:
    try:
        context = AttackContext.from_settings(Settings(), gateway_url)
    except (ChainError, VerigateError) as exc:
        pytest.skip(f"attack context unavailable: {exc}")
    if not context.chain.is_connected():
        pytest.skip("no chain")
    return context


def verdict_log_entry(gateway_url: str, report: AttackReport) -> dict[str, Any]:
    """The dashboard-visible line: the verdict-log entry for the attacked release."""
    entries = httpx.get(f"{gateway_url}/verdicts?limit=1000", timeout=30).json()
    matches = [e for e in entries if e.get("releaseId") == report.release_id and "verdict" in e]
    assert matches, f"no verdict logged for {report.release_id}"
    return matches[-1]
