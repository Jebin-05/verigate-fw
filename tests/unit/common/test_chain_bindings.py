"""Chain bindings without a node: address resolution, ABI packaging, error translation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from web3.exceptions import ContractCustomError, ContractLogicError

from verigate.common.chain import (
    ADMIN_ROLE,
    CONTRACT_NAMES,
    ChainClient,
    ContractAddresses,
    ContractRevertError,
    _revert_data,
    device_model_id,
    load_abi,
    load_addresses,
    publisher_id,
)
from verigate.common.errors import ChainError
from verigate.common.settings import Settings

ADDR = ["0x" + f"{i:040x}" for i in range(1, 7)]
ARTIFACTS = Path(__file__).resolve().parents[3] / "contracts" / "artifacts" / "contracts"


def write_addresses(path: Path, chain_id: int = 31337, **extra: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "chainId": chain_id,
                "gateway": ADDR[5],
                "contracts": dict(zip(CONTRACT_NAMES, ADDR, strict=False)),
                **extra,
            }
        )
    )


def test_load_abi_has_every_contract() -> None:
    for name in CONTRACT_NAMES:
        abi = load_abi(name)
        assert any(item.get("type") == "function" for item in abi)
        assert any(item.get("type") == "error" for item in abi)


@pytest.mark.skipif(not ARTIFACTS.is_dir(), reason="contracts not compiled (npx hardhat compile)")
def test_packaged_abis_match_compiled_artifacts() -> None:
    for name in CONTRACT_NAMES:
        artifact = json.loads((ARTIFACTS / f"{name}.sol" / f"{name}.json").read_text())
        assert load_abi(name) == artifact["abi"], f"{name}: run scripts/sync_abi.py"


def test_addresses_from_json_take_precedence(settings: Settings) -> None:
    write_addresses(settings.addresses_file)
    s = settings.model_copy(update={"publisher_registry_addr": ADDR[5]})
    got = load_addresses(s)
    assert got.publisher_registry.lower() == ADDR[0]
    assert got.gateway is not None and got.gateway.lower() == ADDR[5]
    assert got.source == str(settings.addresses_file)
    assert got.chain_id == 31337


def test_addresses_fall_back_to_env_when_json_is_for_another_chain(settings: Settings) -> None:
    write_addresses(settings.addresses_file, chain_id=1)
    s = Settings(
        _env_file=None,
        deployments_dir=settings.deployments_dir,
        publisher_registry_addr=ADDR[0],
        model_registry_addr=ADDR[1],
        firmware_registry_addr=ADDR[2],
        policy_contract_addr=ADDR[3],
        verdict_registry_addr=ADDR[4],
    )
    got = load_addresses(s)
    assert got.source == "env"
    assert got.gateway is None
    assert got.verdict_registry.lower() == ADDR[4]


def test_addresses_missing_everywhere(settings: Settings) -> None:
    with pytest.raises(ChainError, match="no contract addresses"):
        load_addresses(settings)


def test_addresses_malformed_json(settings: Settings) -> None:
    settings.addresses_file.parent.mkdir(parents=True)
    settings.addresses_file.write_text('{"chainId": 31337, "contracts": {}}')
    with pytest.raises(ChainError, match="malformed"):
        load_addresses(settings)


def test_addresses_invalid_env_value(settings: Settings) -> None:
    s = settings.model_copy(
        update={
            "publisher_registry_addr": "0xnothex",
            "model_registry_addr": ADDR[1],
            "firmware_registry_addr": ADDR[2],
            "policy_contract_addr": ADDR[3],
            "verdict_registry_addr": ADDR[4],
        }
    )
    with pytest.raises(ChainError, match="invalid contract address"):
        load_addresses(s)


@pytest.fixture
def offline_client(settings: Settings) -> ChainClient:
    addresses = ContractAddresses(*ADDR[:5], chain_id=31337, gateway=ADDR[5])
    return ChainClient(settings.model_copy(update={"rpc_url": "http://127.0.0.1:1"}), addresses)


def test_dependency_down_is_a_chain_error(offline_client: ChainClient) -> None:
    assert offline_client.is_connected() is False
    with pytest.raises(ChainError, match="eth_blockNumber"):
        offline_client.block_number()
    with pytest.raises(ChainError, match="rpc failure"):
        offline_client.get_policy()
    with pytest.raises(ChainError, match="rpc failure"):
        offline_client.send(
            offline_client.models.functions.register(b"\x01" * 32, "x"),
            offline_client.account("0x" + "11" * 32),
        )


def test_custom_error_decoding(offline_client: ChainClient) -> None:
    selector = next(
        k
        for k, v in offline_client._errors.items()
        if v == "VersionNotMonotonic"  # noqa: SLF001
    )
    data = "0x" + selector.hex() + "00" * 64
    assert offline_client.decode_error(data) == "VersionNotMonotonic"
    assert offline_client.decode_error(bytes.fromhex(data[2:])) == "VersionNotMonotonic"
    assert offline_client.decode_error("0xdeadbeef") is None
    assert offline_client.decode_error(None) is None

    wrapped = offline_client._wrap(ContractCustomError("boom", data=data))  # noqa: SLF001
    assert isinstance(wrapped, ContractRevertError)
    assert wrapped.name == "VersionNotMonotonic"
    nested = offline_client._wrap(ContractLogicError("x", data={"message": "m", "data": data}))  # noqa: SLF001
    assert isinstance(nested, ContractRevertError) and nested.name == "VersionNotMonotonic"
    plain = offline_client._wrap(ContractLogicError("execution reverted"))  # noqa: SLF001
    assert isinstance(plain, ContractRevertError) and plain.name is None
    assert "unknown reason" in str(plain)
    other = offline_client._wrap(RuntimeError("socket"))  # noqa: SLF001
    assert type(other) is ChainError


def test_ids_and_roles() -> None:
    assert (
        publisher_id("did:verigate:acme").hex()
        == "3ea6aeb12f62d5dc8db2369d2d48fcfe2686855542b050640e84dfc8bbaa17d1"
    )
    assert len(device_model_id("demo-device")) == 32
    assert ADMIN_ROLE.hex() == "a49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775"


def test_revert_data_is_found_in_rpc_error_payloads(offline_client: ChainClient) -> None:
    from web3.exceptions import Web3RPCError  # noqa: PLC0415

    selector = next(k for k, v in offline_client._errors.items() if v == "InvalidExpiry")  # noqa: SLF001
    data = "0x" + selector.hex() + "00" * 64
    hardhat_style = Web3RPCError(
        {
            "code": -32603,
            "message": "reverted with custom error 'InvalidExpiry(1, 2)'",
            "data": {"message": "m", "data": data},
        }
    )
    wrapped = offline_client._wrap(hardhat_style)  # noqa: SLF001
    assert isinstance(wrapped, ContractRevertError) and wrapped.name == "InvalidExpiry"
    assert _revert_data({"a": [1, {"data": data}]}) == data
    assert _revert_data("0x12") is None and _revert_data(None) is None and _revert_data(5) is None
    assert _revert_data({"x": {"y": {"z": {"w": {"v": {"u": {"t": data}}}}}}}) is None  # depth cap
    plain = offline_client._wrap(Web3RPCError({"code": -32000, "message": "insufficient funds"}))  # noqa: SLF001
    assert type(plain) is ChainError
