"""``verigate-admin`` — operator commands that are on-chain transactions (ADMIN_ROLE).

register-model / revoke-model (ModelRegistry), set-policy (PolicyContract), revoke-publisher
(PublisherRegistry), grant-gateway (GATEWAY_ROLE on both registries). Every command prints one
JSON object; the admin account is ``DEPLOYER_PRIVATE_KEY``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from verigate.common.chain import GATEWAY_ROLE, ChainClient, publisher_id
from verigate.common.errors import VerigateError
from verigate.common.logging import configure_logging
from verigate.common.settings import Settings, get_settings

app = typer.Typer(help="Admin transactions.", add_completion=False, pretty_exceptions_enable=False)


@app.callback()
def main() -> None:
    """Operator transactions (``verigate-admin register-model --file models/sbom_risk.onnx``)."""


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _fail(exc: Exception) -> None:
    _emit({"error": str(exc), "type": type(exc).__name__})
    raise typer.Exit(code=1)


def _chain(settings: Settings) -> ChainClient:
    if not settings.deployer_private_key:
        raise VerigateError("DEPLOYER_PRIVATE_KEY is not set")
    return ChainClient(settings)


def _hash32(text: str) -> bytes:
    try:
        raw = bytes.fromhex(text.removeprefix("0x"))
    except ValueError as exc:
        raise VerigateError(f"not a hex hash: {text!r}") from exc
    if len(raw) != 32:
        raise VerigateError("expected a 32-byte hex hash")
    return raw


@app.command("register-model")
def register_model(
    file: Annotated[
        Path | None, typer.Option("--file", exists=True, help="ONNX file (hash = SHA-256)")
    ] = None,
    model_hash: Annotated[
        str | None, typer.Option("--hash", help="0x… hash instead of --file")
    ] = None,
    name: Annotated[str | None, typer.Option("--name", help="Human-readable name")] = None,
) -> None:
    """ModelRegistry.register(modelHash, name); idempotent (already registered → unchanged)."""
    settings = get_settings()
    configure_logging(settings)
    try:
        if file is not None:
            digest = hashlib.sha256(file.read_bytes()).digest()
            name = name or file.stem
        elif model_hash is not None:
            digest = _hash32(model_hash)
            name = name or "model"
        else:
            raise VerigateError("give --file or --hash")
        chain = _chain(settings)
        record = chain.get_model(digest)
        if record.status != 0:
            _emit({"modelHash": "0x" + digest.hex(), "name": record.name, "status": "unchanged"})
            return
        receipt = chain.send(
            chain.models.functions.register(digest, name),
            chain.account(settings.deployer_private_key),
        )
    except (OSError, VerigateError) as exc:
        _fail(exc)
        return
    _emit(
        {
            "modelHash": "0x" + digest.hex(),
            "name": name,
            "status": "registered",
            "txHash": "0x" + bytes(receipt["transactionHash"]).hex(),
        }
    )


@app.command("register-models")
def register_models(
    manifest: Annotated[
        Path, typer.Option("--manifest", exists=True, help="models/MANIFEST.sha256")
    ] = Path("models/MANIFEST.sha256"),
) -> None:
    """Register every hash in ``MANIFEST.sha256`` (idempotent; the one-shot for a fresh stack)."""
    settings = get_settings()
    configure_logging(settings)
    results: list[dict[str, Any]] = []
    try:
        chain = _chain(settings)
        account = chain.account(settings.deployer_private_key)
        for line in manifest.read_text().splitlines():
            if not line.strip():
                continue
            digest_hex, _, name = line.partition("  ")
            digest = _hash32(digest_hex.strip())
            record = chain.get_model(digest)
            if record.status != 0:
                results.append({"modelHash": "0x" + digest.hex(), "status": "unchanged"})
                continue
            receipt = chain.send(chain.models.functions.register(digest, name.strip()), account)
            results.append(
                {
                    "modelHash": "0x" + digest.hex(),
                    "name": name.strip(),
                    "status": "registered",
                    "txHash": "0x" + bytes(receipt["transactionHash"]).hex(),
                }
            )
    except (OSError, VerigateError) as exc:
        _fail(exc)
        return
    _emit({"models": results})


@app.command("revoke-model")
def revoke_model(
    model_hash: Annotated[str, typer.Argument(help="0x… hash of the model to revoke")],
    successor: Annotated[
        str | None, typer.Option("--successor", help="0x… hash of the replacement")
    ] = None,
) -> None:
    """ModelRegistry.revoke(modelHash, successor): every batch that used it becomes STALE."""
    settings = get_settings()
    configure_logging(settings)
    try:
        chain = _chain(settings)
        digest = _hash32(model_hash)
        succ = _hash32(successor) if successor else b"\x00" * 32
        receipt = chain.send(
            chain.models.functions.revoke(digest, succ),
            chain.account(settings.deployer_private_key),
        )
    except VerigateError as exc:
        _fail(exc)
        return
    _emit(
        {
            "modelHash": "0x" + digest.hex(),
            "successor": "0x" + succ.hex(),
            "status": "revoked",
            "txHash": "0x" + bytes(receipt["transactionHash"]).hex(),
        }
    )


@app.command("set-policy")
def set_policy(
    w_sbom: Annotated[int, typer.Option("--w-sbom", min=0, max=10_000)],
    w_img: Annotated[int, typer.Option("--w-img", min=0, max=10_000)],
    w_rep: Annotated[int, typer.Option("--w-rep", min=0, max=10_000)],
    tau_approve: Annotated[int, typer.Option("--tau-approve", min=0, max=10_000)],
    tau_reject: Annotated[int, typer.Option("--tau-reject", min=0, max=10_000)],
) -> None:
    """PolicyContract.setPolicy — weights (bp, sum 10 000) and thresholds (bp)."""
    settings = get_settings()
    configure_logging(settings)
    try:
        chain = _chain(settings)
        receipt = chain.send(
            chain.policy.functions.setPolicy(w_sbom, w_img, w_rep, tau_approve, tau_reject),
            chain.account(settings.deployer_private_key),
        )
        policy = chain.get_policy()
    except VerigateError as exc:
        _fail(exc)
        return
    _emit({"policy": policy.__dict__, "txHash": "0x" + bytes(receipt["transactionHash"]).hex()})


@app.command("revoke-publisher")
def revoke_publisher(did: Annotated[str, typer.Argument(help="Publisher DID")]) -> None:
    """PublisherRegistry.revoke(publisherId) — the stolen-key response."""
    settings = get_settings()
    configure_logging(settings)
    try:
        chain = _chain(settings)
        receipt = chain.send(
            chain.publishers.functions.revoke(publisher_id(did)),
            chain.account(settings.deployer_private_key),
        )
    except VerigateError as exc:
        _fail(exc)
        return
    _emit(
        {"did": did, "status": "revoked", "txHash": "0x" + bytes(receipt["transactionHash"]).hex()}
    )


@app.command("grant-gateway")
def grant_gateway(address: Annotated[str, typer.Argument(help="Gateway account address")]) -> None:
    """Grant GATEWAY_ROLE on PublisherRegistry and VerdictRegistry."""
    settings = get_settings()
    configure_logging(settings)
    try:
        chain = _chain(settings)
        admin = chain.account(settings.deployer_private_key)
        txs = [
            "0x"
            + bytes(
                chain.send(c.functions.grantRole(GATEWAY_ROLE, address), admin)["transactionHash"]
            ).hex()
            for c in (chain.publishers, chain.verdicts)
        ]
    except VerigateError as exc:
        _fail(exc)
        return
    _emit({"address": address, "role": "GATEWAY_ROLE", "txHashes": txs})


if __name__ == "__main__":
    app()
