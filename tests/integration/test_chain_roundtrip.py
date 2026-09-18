"""P1-13: deploy → register → read, plus revert decoding, against a live hardhat node."""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from eth_account.signers.local import LocalAccount
from web3.logs import DISCARD

from verigate.common.chain import (
    GATEWAY_ROLE,
    STATUS_ACTIVE,
    STATUS_NONE,
    ChainClient,
    ContractRevertError,
    publisher_id,
)
from verigate.common.crypto import KeyPair

pytestmark = pytest.mark.integration


def test_addresses_come_from_deployment_file(chain: ChainClient) -> None:
    assert chain.addresses.source.endswith("addresses.json")
    assert chain.addresses.gateway is not None
    assert chain.block_number() > 0


def test_gateway_holds_gateway_role(chain: ChainClient, gateway_account: LocalAccount) -> None:
    assert chain.call(chain.publishers.functions.hasRole(GATEWAY_ROLE, gateway_account.address))
    assert chain.call(chain.verdicts.functions.hasRole(GATEWAY_ROLE, gateway_account.address))


def test_policy_is_readable(chain: ChainClient) -> None:
    policy = chain.get_policy()
    assert policy.w_sbom + policy.w_img + policy.w_rep == 10_000
    assert policy.tau_approve < policy.tau_reject <= 10_000
    assert policy.version >= 1


def test_register_publisher_and_read_back(chain: ChainClient, funded_account: LocalAccount) -> None:
    did = f"did:verigate:test-{secrets.token_hex(4)}"
    key = KeyPair.generate()
    pid = publisher_id(did)
    assert chain.get_publisher(pid).status == STATUS_NONE

    receipt = chain.send(chain.publishers.functions.register(did, key.public), funded_account)
    assert receipt["status"] == 1

    record = chain.get_publisher(pid)
    assert record.exists and record.is_active
    assert record.status == STATUS_ACTIVE
    assert record.did == did
    assert record.owner == funded_account.address
    assert record.pub_key == key.public
    assert record.reputation_bp == 5000
    assert record.registered_at == receipt["blockNumber"]

    events: list[Any] = chain.publishers.events.PublisherRegistered().process_receipt(
        receipt, errors=DISCARD
    )
    assert events[0]["args"]["publisherId"] == pid


def test_revert_is_decoded(chain: ChainClient, funded_account: LocalAccount) -> None:
    did = f"did:verigate:test-{secrets.token_hex(4)}"
    chain.send(chain.publishers.functions.register(did, KeyPair.generate().public), funded_account)
    with pytest.raises(ContractRevertError) as exc:
        chain.send(
            chain.publishers.functions.register(did, KeyPair.generate().public), funded_account
        )
    assert exc.value.name in {"PublisherExists", "AddressAlreadyPublisher"}
    with pytest.raises(ContractRevertError) as exc2:
        chain.get_batch(10**9)
    assert exc2.value.name == "UnknownBatch"


def test_release_enumeration_is_consistent(chain: ChainClient) -> None:
    total = chain.release_count()
    ids = chain.release_ids(0, 5)
    assert len(ids) == min(total, 5)
    for rid in ids:
        assert chain.get_release(rid).exists
