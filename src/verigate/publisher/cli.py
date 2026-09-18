"""``verigate-publish`` — the firmware publisher's command line (Typer).

Every command prints exactly one JSON object on stdout (``--json`` is accepted for readability
and is the default behaviour) and exits non-zero with ``{"error": ...}`` on failure, so the demo
script and the tests can parse results without scraping logs.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from verigate.common.chain import ChainClient
from verigate.common.errors import VerigateError
from verigate.common.ipfs import make_backend
from verigate.common.logging import configure_logging
from verigate.common.settings import Settings, get_settings
from verigate.publisher.release import (
    ensure_key,
    ensure_registered,
    publish_release,
    revoke_release,
)

app = typer.Typer(
    help="Build, sign, upload and register firmware releases.",
    add_completion=False,
    pretty_exceptions_enable=False,
)

JsonFlag = Annotated[bool, typer.Option("--json", help="Print a JSON result (always on).")]
DidOpt = Annotated[
    str | None, typer.Option("--did", help="Publisher DID (default: PUBLISHER_DID).")
]


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _fail(exc: Exception) -> None:
    _emit({"error": str(exc), "type": type(exc).__name__})
    raise typer.Exit(code=1)


def _settings() -> Settings:
    settings = get_settings()
    configure_logging(settings)
    return settings


def _key_name(did: str) -> str:
    return did.replace(":", "_")


def _parse_expiry(text: str) -> datetime:
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise VerigateError("expiry must include a timezone, e.g. 2030-01-01T00:00:00Z")
    return value


def _account_key(settings: Settings) -> str:
    if not settings.publisher_private_key:
        raise VerigateError("PUBLISHER_PRIVATE_KEY is not set")
    return settings.publisher_private_key


@app.command()
def keygen(did: DidOpt = None, json_out: JsonFlag = True) -> None:  # noqa: ARG001
    """Create (or reuse) the Ed25519 signing key for the publisher DID under KEYS_DIR."""
    settings = _settings()
    did = did or settings.publisher_did
    try:
        key = ensure_key(settings.keys_dir, _key_name(did))
    except (OSError, VerigateError) as exc:
        _fail(exc)
        return
    _emit(
        {
            "did": did,
            "publicKey": key.public_encoded,
            "privateKeyFile": str(settings.keys_dir / f"{_key_name(did)}.key"),
        }
    )


@app.command()
def register(did: DidOpt = None, json_out: JsonFlag = True) -> None:  # noqa: ARG001
    """Register the DID + public key in PublisherRegistry (idempotent; rotates on key change)."""
    settings = _settings()
    did = did or settings.publisher_did
    try:
        key = ensure_key(settings.keys_dir, _key_name(did))
        chain = ChainClient(settings)
        result = ensure_registered(chain, chain.account(_account_key(settings)), did, key)
    except (OSError, VerigateError) as exc:
        _fail(exc)
        return
    _emit(
        {
            "did": result.did,
            "publisherId": "0x" + result.publisher_id,
            "owner": result.owner,
            "publicKey": result.public_key,
            "status": result.status,
            "txHash": result.tx_hash,
        }
    )


@app.command()
def release(
    fw: Annotated[Path, typer.Option("--fw", exists=True, dir_okay=False, help="firmware.bin")],
    sbom: Annotated[
        Path, typer.Option("--sbom", exists=True, dir_okay=False, help="CycloneDX JSON")
    ],
    version: Annotated[str, typer.Option("--version", help="Strict SemVer, e.g. 1.2.0")],
    model: Annotated[str, typer.Option("--model", help="Device model, e.g. demo-device")],
    expiry: Annotated[
        str, typer.Option("--expiry", help="ISO-8601 UTC, e.g. 2030-01-01T00:00:00Z")
    ],
    did: DidOpt = None,
    json_out: JsonFlag = True,  # noqa: ARG001
) -> None:
    """Hash → IPFS → manifest → sign → IPFS → FirmwareRegistry.register. Idempotent."""
    settings = _settings()
    did = did or settings.publisher_did
    try:
        key = ensure_key(settings.keys_dir, _key_name(did))
        chain = ChainClient(settings)
        result = publish_release(
            chain=chain,
            ipfs=make_backend(settings),
            account=chain.account(_account_key(settings)),
            key=key,
            did=did,
            firmware_path=fw,
            sbom_path=sbom,
            version=version,
            device_model=model,
            expiry=_parse_expiry(expiry),
        )
    except (OSError, ValueError, VerigateError) as exc:
        _fail(exc)
        return
    _emit(result.to_dict())


@app.command()
def revoke(
    release_id: Annotated[str, typer.Argument(help="0x-prefixed releaseId (= manifest hash)")],
    json_out: JsonFlag = True,  # noqa: ARG001
) -> None:
    """Withdraw a release (publisher owner or admin). Idempotent."""
    settings = _settings()
    try:
        raw = bytes.fromhex(release_id.removeprefix("0x"))
        if len(raw) != 32:
            raise VerigateError("releaseId must be 32 bytes")
        chain = ChainClient(settings)
        result = revoke_release(chain, chain.account(_account_key(settings)), raw)
    except (ValueError, VerigateError) as exc:
        _fail(exc)
        return
    _emit(result)


if __name__ == "__main__":
    app()
