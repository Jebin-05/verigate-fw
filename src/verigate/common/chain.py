"""web3 client and typed bindings for the five registries.

Addresses come from ``contracts/deployments/<net>/addresses.json`` (written by ``deploy.ts``) and
fall back to the ``*_ADDR`` settings, so the same code works on the host, in compose and on a fresh
machine. ABIs ship inside the package (``verigate/common/abi/*.json``, synced by
``scripts/sync_abi.py``).

Every RPC failure surfaces as :class:`ChainError` (→ DEFER); a contract revert surfaces as
:class:`ContractRevertError` with the decoded custom-error name (→ REJECT or a CLI error). Reads
used by Stage 1 return frozen records so the checks stay pure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any, cast

from eth_account.signers.local import LocalAccount
from eth_typing import ABIError
from eth_utils.abi import function_abi_to_4byte_selector
from eth_utils.crypto import keccak
from web3 import Web3
from web3.contract import Contract
from web3.contract.contract import ContractFunction
from web3.exceptions import ContractLogicError
from web3.types import TxReceipt

from verigate.common.errors import ChainError
from verigate.common.settings import Settings

CONTRACT_NAMES = (
    "PublisherRegistry",
    "ModelRegistry",
    "FirmwareRegistry",
    "PolicyContract",
    "VerdictRegistry",
)

# Role ids: keccak256 of the role name, as in contracts/access/Roles.sol.
ADMIN_ROLE = keccak(b"ADMIN_ROLE")
PUBLISHER_ROLE = keccak(b"PUBLISHER_ROLE")
GATEWAY_ROLE = keccak(b"GATEWAY_ROLE")

STATUS_NONE, STATUS_ACTIVE, STATUS_REVOKED = 0, 1, 2


class ContractRevertError(ChainError):
    """A transaction or call reverted. ``name`` is the decoded custom error when known."""

    def __init__(self, name: str | None, data: str | None) -> None:
        self.name = name
        self.data = data
        super().__init__(f"contract reverted: {name or data or 'unknown reason'}")


@dataclass(frozen=True)
class ContractAddresses:
    """Checksummed addresses of the deployed registries plus the gateway account."""

    publisher_registry: str
    model_registry: str
    firmware_registry: str
    policy_contract: str
    verdict_registry: str
    chain_id: int
    gateway: str | None = None
    source: str = "env"


@dataclass(frozen=True)
class PublisherRecord:
    """Mirror of ``IPublisherRegistry.Publisher``."""

    publisher_id: bytes
    did: str
    owner: str
    pub_key: bytes
    status: int
    reputation_bp: int
    key_version: int
    registered_at: int
    revoked_at: int

    @property
    def exists(self) -> bool:
        """False for an id the registry has never seen."""
        return self.status != STATUS_NONE

    @property
    def is_active(self) -> bool:
        """True iff status == ACTIVE."""
        return self.status == STATUS_ACTIVE


@dataclass(frozen=True)
class ReleaseRecord:
    """Mirror of ``IFirmwareRegistry.Release``; ``registered_at == 0`` means unknown."""

    release_id: bytes
    publisher_id: bytes
    device_model_id: bytes
    major: int
    minor: int
    patch: int
    manifest_hash: bytes
    firmware_hash: bytes
    sbom_hash: bytes
    expiry: int
    registered_at: int
    revoked: bool
    device_model: str
    manifest_cid: str
    firmware_cid: str
    sbom_cid: str
    signature: bytes

    @property
    def exists(self) -> bool:
        """False for an id the registry has never seen."""
        return self.registered_at != 0

    @property
    def version(self) -> tuple[int, int, int]:
        """``(major, minor, patch)``."""
        return (self.major, self.minor, self.patch)


@dataclass(frozen=True)
class ModelRecord:
    """Mirror of ``IModelRegistry.Model``."""

    model_hash: bytes
    name: str
    status: int
    successor: bytes
    registered_at: int
    revoked_at: int

    @property
    def is_active(self) -> bool:
        """True iff status == ACTIVE."""
        return self.status == STATUS_ACTIVE


@dataclass(frozen=True)
class PolicyRecord:
    """Mirror of ``IPolicyContract.Policy`` (basis points)."""

    w_sbom: int
    w_img: int
    w_rep: int
    tau_approve: int
    tau_reject: int
    version: int
    changed_by: str
    changed_at: int


@dataclass(frozen=True)
class BatchRecord:
    """Mirror of ``IVerdictRegistry.Batch``."""

    batch_id: int
    root: bytes
    count: int
    block_number: int
    gateway: str
    model_hashes: tuple[bytes, ...]


def load_abi(name: str) -> list[dict[str, Any]]:
    """Load the packaged ABI of contract ``name``."""
    text = resources.files("verigate.common.abi").joinpath(f"{name}.json").read_text()
    abi: list[dict[str, Any]] = json.loads(text)
    return abi


def load_addresses(settings: Settings) -> ContractAddresses:
    """Resolve addresses: ``addresses.json`` for this chain first, then the ``*_ADDR`` settings.

    Raises:
        ChainError: If neither source provides all five addresses.
    """
    path = settings.addresses_file
    if path.is_file():
        try:
            data = json.loads(path.read_text())
            contracts = data["contracts"]
            if int(data["chainId"]) == settings.chain_id:
                return ContractAddresses(
                    publisher_registry=Web3.to_checksum_address(contracts["PublisherRegistry"]),
                    model_registry=Web3.to_checksum_address(contracts["ModelRegistry"]),
                    firmware_registry=Web3.to_checksum_address(contracts["FirmwareRegistry"]),
                    policy_contract=Web3.to_checksum_address(contracts["PolicyContract"]),
                    verdict_registry=Web3.to_checksum_address(contracts["VerdictRegistry"]),
                    chain_id=settings.chain_id,
                    gateway=Web3.to_checksum_address(data["gateway"])
                    if data.get("gateway")
                    else None,
                    source=str(path),
                )
        except (KeyError, ValueError, TypeError) as exc:
            raise ChainError(f"malformed {path}: {exc}") from exc
    env = (
        settings.publisher_registry_addr,
        settings.model_registry_addr,
        settings.firmware_registry_addr,
        settings.policy_contract_addr,
        settings.verdict_registry_addr,
    )
    if not all(env):
        raise ChainError(
            f"no contract addresses: {path} missing and *_ADDR unset (make contracts-deploy-local)"
        )
    try:
        pub, mdl, fw, pol, ver = (Web3.to_checksum_address(a) for a in env if a is not None)
    except ValueError as exc:
        raise ChainError(f"invalid contract address in settings: {exc}") from exc
    return ContractAddresses(pub, mdl, fw, pol, ver, chain_id=settings.chain_id, source="env")


class ChainClient:
    """Synchronous web3 client bound to the five registries.

    Sync on purpose: the async gateway calls it via ``asyncio.to_thread`` (Manual §4.1).
    """

    def __init__(self, settings: Settings, addresses: ContractAddresses | None = None) -> None:
        self.settings = settings
        self.w3 = Web3(Web3.HTTPProvider(settings.rpc_url, request_kwargs={"timeout": 10}))
        self.addresses = addresses or load_addresses(settings)
        self.publishers = self._bind("PublisherRegistry", self.addresses.publisher_registry)
        self.models = self._bind("ModelRegistry", self.addresses.model_registry)
        self.firmware = self._bind("FirmwareRegistry", self.addresses.firmware_registry)
        self.policy = self._bind("PolicyContract", self.addresses.policy_contract)
        self.verdicts = self._bind("VerdictRegistry", self.addresses.verdict_registry)
        self._errors: dict[bytes, str] = {}
        for name in CONTRACT_NAMES:
            for item in load_abi(name):
                if item.get("type") == "error":
                    selector = function_abi_to_4byte_selector(cast("ABIError", item))
                    self._errors[selector] = str(item["name"])

    def _bind(self, name: str, address: str) -> Contract:
        return self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=load_abi(name))

    # ------------------------------------------------------------------ connection

    def is_connected(self) -> bool:
        """True iff the RPC answers and reports the configured chain id."""
        try:
            return bool(self.w3.is_connected()) and self.w3.eth.chain_id == self.settings.chain_id
        except Exception:  # noqa: BLE001 — any transport failure means "not connected"
            return False

    def block_number(self) -> int:
        """Latest block number.

        Raises:
            ChainError: On any RPC failure.
        """
        try:
            return int(self.w3.eth.block_number)
        except Exception as exc:
            raise ChainError(f"eth_blockNumber failed: {exc}") from exc

    def account(self, private_key: str) -> LocalAccount:
        """Local signing account for ``private_key`` (hex)."""
        account: LocalAccount = self.w3.eth.account.from_key(private_key)
        return account

    # ------------------------------------------------------------------ errors

    def decode_error(self, data: str | bytes | None) -> str | None:
        """Map revert data to a custom error name declared in any of the five ABIs."""
        if not data:
            return None
        raw = bytes.fromhex(data[2:]) if isinstance(data, str) else data
        return self._errors.get(raw[:4])

    def _wrap(self, exc: Exception) -> ChainError:
        data = _revert_data(exc)
        if isinstance(exc, ContractLogicError) or data is not None:
            return ContractRevertError(self.decode_error(data), data)
        return ChainError(f"rpc failure: {exc}")

    # ------------------------------------------------------------------ calls

    def call(self, fn: ContractFunction) -> Any:  # noqa: ANN401 — mirrors web3's untyped return
        """``eth_call`` with error translation."""
        try:
            return fn.call()
        except Exception as exc:
            raise self._wrap(exc) from exc

    def send(self, fn: ContractFunction, account: LocalAccount) -> TxReceipt:
        """Build, sign, send and await a transaction from ``account``.

        Raises:
            ContractRevertError: If the transaction reverts (decoded custom error name when known).
            ChainError: On any other failure (including a receipt with ``status == 0``).
        """
        try:
            tx = fn.build_transaction(
                {
                    "from": account.address,
                    "nonce": self.w3.eth.get_transaction_count(account.address),
                    "chainId": self.settings.chain_id,
                }
            )
            signed = self.w3.eth.account.sign_transaction(tx, account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        except Exception as exc:
            raise self._wrap(exc) from exc
        if receipt["status"] != 1:
            raise ChainError(f"transaction {tx_hash.hex()} failed (status 0)")
        return receipt

    # ------------------------------------------------------------------ typed reads

    def get_publisher(self, publisher_id: bytes) -> PublisherRecord:
        """Read a publisher record."""
        r = self.call(self.publishers.functions.get(publisher_id))
        return PublisherRecord(publisher_id, r[0], r[1], bytes(r[2]), r[3], r[4], r[5], r[6], r[7])

    def get_release(self, release_id: bytes) -> ReleaseRecord:
        """Read a release record."""
        r = self.call(self.firmware.functions.get(release_id))
        return ReleaseRecord(
            release_id=release_id,
            publisher_id=bytes(r[0]),
            device_model_id=bytes(r[1]),
            major=r[2],
            minor=r[3],
            patch=r[4],
            manifest_hash=bytes(r[5]),
            firmware_hash=bytes(r[6]),
            sbom_hash=bytes(r[7]),
            expiry=r[8],
            registered_at=r[9],
            revoked=r[10],
            device_model=r[11],
            manifest_cid=r[12],
            firmware_cid=r[13],
            sbom_cid=r[14],
            signature=bytes(r[15]),
        )

    def get_model(self, model_hash: bytes) -> ModelRecord:
        """Read a model record."""
        r = self.call(self.models.functions.get(model_hash))
        return ModelRecord(model_hash, r[0], r[1], bytes(r[2]), r[3], r[4])

    def get_policy(self) -> PolicyRecord:
        """Read the policy in force."""
        r = self.call(self.policy.functions.current())
        return PolicyRecord(*r)

    def get_batch(self, batch_id: int) -> BatchRecord:
        """Read a verdict batch."""
        r = self.call(self.verdicts.functions.getBatch(batch_id))
        return BatchRecord(batch_id, bytes(r[0]), r[1], r[2], r[3], tuple(bytes(h) for h in r[4]))

    def release_count(self) -> int:
        """Number of releases registered so far."""
        return int(self.call(self.firmware.functions.count()))

    def release_ids(self, start: int = 0, limit: int = 100) -> list[bytes]:
        """Release ids ``[start, start+limit)`` in registration order."""
        total = self.release_count()
        end = min(total, start + limit)
        return [bytes(self.call(self.firmware.functions.releaseIdAt(i))) for i in range(start, end)]


def _revert_data(obj: object, depth: int = 0) -> str | None:
    """Find ``0x``-prefixed revert data anywhere in an exception payload (web3/Hardhat nest it)."""
    if depth > 6:
        return None
    if isinstance(obj, str):
        return obj if obj.startswith("0x") and len(obj) >= 10 else None
    if isinstance(obj, dict):
        found = _revert_data(obj.get("data"), depth + 1)
        return found or next(
            (r for r in (_revert_data(v, depth + 1) for v in obj.values()) if r), None
        )
    if isinstance(obj, list | tuple):
        return next((r for r in (_revert_data(v, depth + 1) for v in obj) if r), None)
    if isinstance(obj, BaseException):
        data = getattr(obj, "data", None)
        response = getattr(obj, "rpc_response", None)
        return (
            _revert_data(data, depth + 1)
            or _revert_data(response, depth + 1)
            or _revert_data(obj.args, depth + 1)
        )
    return None


def publisher_id(did: str) -> bytes:
    """``keccak256(did)`` — the on-chain publisher identifier."""
    return keccak(did.encode("utf-8"))


def device_model_id(device_model: str) -> bytes:
    """``keccak256(deviceModel)`` — the on-chain device-model identifier."""
    return keccak(device_model.encode("utf-8"))
