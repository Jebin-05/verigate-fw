"""Fixtures for tests that need `make infra-up` + `make contracts-deploy-local`.

CI runs them with ``IPFS_BACKEND=local LLM_ENABLED=false`` and a freshly deployed hardhat node.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

import pytest
from eth_account.signers.local import LocalAccount

from verigate.common.chain import ChainClient
from verigate.common.errors import ChainError
from verigate.common.ipfs import IpfsBackend, KuboBackend, make_backend
from verigate.common.settings import Settings


@pytest.fixture(scope="session")
def live_settings() -> Settings:
    """The real ``.env`` (plus environment overrides), as the services would see it."""
    return Settings()


@pytest.fixture(scope="session")
def chain(live_settings: Settings) -> ChainClient:
    """Client bound to the deployed contracts; skips when no node is reachable."""
    try:
        client = ChainClient(live_settings)
    except ChainError as exc:
        pytest.skip(f"contracts not deployed: {exc}")
    if not client.is_connected():
        pytest.skip(f"no hardhat node at {live_settings.rpc_url}")
    return client


@pytest.fixture(scope="session")
def deployer(chain: ChainClient, live_settings: Settings) -> LocalAccount:
    """Hardhat account #0 — admin of every registry."""
    return chain.account(live_settings.deployer_private_key)


@pytest.fixture(scope="session")
def gateway_account(chain: ChainClient, live_settings: Settings) -> LocalAccount:
    """Hardhat account #1 — holds GATEWAY_ROLE."""
    return chain.account(live_settings.gateway_private_key)


@pytest.fixture
def funded_account(chain: ChainClient, deployer: LocalAccount) -> LocalAccount:
    """A brand-new account with 1 ETH from the deployer (re-runnable against a persistent node)."""
    account = chain.account("0x" + secrets.token_hex(32))
    tx = {
        "from": deployer.address,
        "to": account.address,
        "value": chain.w3.to_wei(1, "ether"),
        "nonce": chain.w3.eth.get_transaction_count(deployer.address),
        "chainId": chain.settings.chain_id,
        "gas": 21_000,
        "gasPrice": chain.w3.eth.gas_price,
    }
    signed = chain.w3.eth.account.sign_transaction(tx, deployer.key)
    chain.w3.eth.wait_for_transaction_receipt(
        chain.w3.eth.send_raw_transaction(signed.raw_transaction)
    )
    return account


@pytest.fixture(scope="session")
def ipfs(live_settings: Settings) -> IpfsBackend:
    """The configured backend (local in CI, Kubo on a dev laptop with ``make infra-up``)."""
    backend = make_backend(live_settings)
    if isinstance(backend, KuboBackend) and not backend.is_available():
        pytest.skip(f"no Kubo daemon at {live_settings.ipfs_api}")
    return backend


@pytest.fixture(scope="session")
def kubo(live_settings: Settings) -> Iterator[KuboBackend]:
    """A Kubo backend regardless of ``IPFS_BACKEND``; skipped when the daemon is absent."""
    backend = KuboBackend(live_settings.ipfs_api, timeout=10)
    if not backend.is_available():
        pytest.skip(f"no Kubo daemon at {live_settings.ipfs_api}")
    yield backend
