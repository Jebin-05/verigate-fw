"""The eight deterministic, fail-closed checks of the cryptographic gate (Guide §5).

Every check is a pure function of :class:`~verigate.gateway.stage1.inputs.Stage1Input`: no I/O,
no clock, no environment. A missing input is a failure, never a pass. The runner
(``stage1/runner.py``) calls them in order and stops at the first failure.
"""

from __future__ import annotations

from dataclasses import dataclass

from verigate.common.chain import STATUS_ACTIVE, STATUS_NONE, STATUS_REVOKED, publisher_id
from verigate.common.crypto import parse_hash, sha256
from verigate.gateway.stage1.inputs import Stage1Input


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check; ``reason`` is human-readable and shown on the dashboard."""

    name: str
    ok: bool
    reason: str | None = None


def check_firmware_hash(inp: Stage1Input) -> CheckResult:
    """#1 ``SHA-256(firmware.bin) == manifest.firmwareHash`` (and == the on-chain record).

    Stops tampering in transit or on IPFS.
    """
    name = "firmware_hash"
    if inp.manifest is None:
        return CheckResult(name, False, "manifest unavailable")
    if inp.firmware is None:
        return CheckResult(name, False, "firmware unavailable")
    expected = parse_hash(inp.manifest.firmwareHash)
    actual = sha256(inp.firmware)
    if actual != expected:
        return CheckResult(
            name, False, f"sha256 {actual.hex()[:16]}… != manifest {expected.hex()[:16]}…"
        )
    if inp.release is not None and inp.release.firmware_hash != expected:
        return CheckResult(name, False, "manifest firmwareHash != on-chain record")
    return CheckResult(name, True)


def check_signature(inp: Stage1Input) -> CheckResult:
    """#2 Manifest signature verifies under the key registered for ``manifest.publisherDid``.

    Stops forgery / impersonation: an attacker's key is not the one on-chain for that DID.
    """
    name = "signature"
    if inp.manifest is None:
        return CheckResult(name, False, "manifest unavailable")
    if inp.publisher is None or inp.publisher.status == STATUS_NONE:
        return CheckResult(name, False, f"publisher {inp.manifest.publisherDid} not registered")
    if inp.publisher.publisher_id != publisher_id(inp.manifest.publisherDid):
        return CheckResult(name, False, "publisher record does not belong to manifest.publisherDid")
    if not inp.manifest.verify(inp.publisher.pub_key):
        return CheckResult(name, False, "signature does not verify under the registered key")
    return CheckResult(name, True)


def check_publisher_active(inp: Stage1Input) -> CheckResult:
    """#3 Publisher status is ACTIVE in ``PublisherRegistry``. Stops stolen / retired keys."""
    name = "publisher_active"
    if inp.publisher is None or inp.publisher.status == STATUS_NONE:
        return CheckResult(name, False, "publisher unknown")
    if inp.publisher.status == STATUS_REVOKED:
        return CheckResult(name, False, f"publisher revoked at block {inp.publisher.revoked_at}")
    if inp.publisher.status != STATUS_ACTIVE:
        return CheckResult(name, False, f"publisher status {inp.publisher.status}")
    return CheckResult(name, True)


def check_version_monotonic(inp: Stage1Input) -> CheckResult:
    """#4 ``manifest.version > device.installedVersion`` and the model matches. Stops rollback."""
    name = "version_monotonic"
    if inp.manifest is None:
        return CheckResult(name, False, "manifest unavailable")
    if inp.manifest.deviceModel != inp.device.device_model:
        return CheckResult(
            name,
            False,
            f"release is for {inp.manifest.deviceModel}, device is {inp.device.device_model}",
        )
    if inp.manifest.version <= inp.device.installed_version:
        return CheckResult(
            name, False, f"{inp.manifest.version} <= installed {inp.device.installed_version}"
        )
    return CheckResult(name, True)


def check_expiry(inp: Stage1Input) -> CheckResult:
    """#5 ``manifest.expiry > now``. A stale manifest means a freeze attack → DEFER + alert."""
    name = "expiry"
    if inp.manifest is None:
        return CheckResult(name, False, "manifest unavailable")
    if inp.now.tzinfo is None:
        return CheckResult(name, False, "clock has no timezone")
    if inp.manifest.expiry <= inp.now:
        return CheckResult(name, False, f"expired at {inp.manifest.expiry.isoformat()}")
    return CheckResult(name, True)


def check_sbom_hash(inp: Stage1Input) -> CheckResult:
    """#6 ``SHA-256(sbom.json) == manifest.sbomHash``. Stops SBOM substitution before Stage 2."""
    name = "sbom_hash"
    if inp.manifest is None:
        return CheckResult(name, False, "manifest unavailable")
    if inp.sbom is None:
        return CheckResult(name, False, "sbom unavailable")
    expected = parse_hash(inp.manifest.sbomHash)
    actual = sha256(inp.sbom)
    if actual != expected:
        return CheckResult(
            name, False, f"sha256 {actual.hex()[:16]}… != manifest {expected.hex()[:16]}…"
        )
    if inp.release is not None and inp.release.sbom_hash != expected:
        return CheckResult(name, False, "manifest sbomHash != on-chain record")
    return CheckResult(name, True)


def check_registry_record(inp: Stage1Input) -> CheckResult:
    """#7 The release exists on-chain, binds to this manifest and publisher, and is not revoked."""
    name = "registry_record"
    if inp.manifest is None:
        return CheckResult(name, False, "manifest unavailable")
    if inp.release is None or not inp.release.exists:
        return CheckResult(name, False, "release not found in FirmwareRegistry")
    if inp.release.manifest_hash != inp.manifest.manifest_hash():
        return CheckResult(name, False, "on-chain manifestHash != keccak(manifest)")
    if inp.release.publisher_id != publisher_id(inp.manifest.publisherDid):
        return CheckResult(name, False, "on-chain publisher != manifest.publisherDid")
    if inp.release.version != inp.manifest.version.as_tuple():
        return CheckResult(name, False, "on-chain version != manifest.version")
    if inp.release.revoked:
        return CheckResult(name, False, "release revoked in FirmwareRegistry")
    return CheckResult(name, True)


def check_models_active(inp: Stage1Input) -> CheckResult:
    """#8 Every AI model the gate will use is ACTIVE in ``ModelRegistry`` (none is fine)."""
    name = "model_active"
    for model in inp.models:
        if model is None:
            return CheckResult(name, False, "model status unavailable")
        if model.status == STATUS_REVOKED:
            return CheckResult(name, False, f"model {model.model_hash.hex()[:16]}… revoked")
        if model.status != STATUS_ACTIVE:
            return CheckResult(name, False, f"model {model.model_hash.hex()[:16]}… not registered")
    return CheckResult(name, True)


CHECKS = (
    check_firmware_hash,
    check_signature,
    check_publisher_active,
    check_version_monotonic,
    check_expiry,
    check_sbom_hash,
    check_registry_record,
    check_models_active,
)
"""The eight checks in the order the runner applies them (Guide §5 numbering)."""

DEFER_CHECKS = frozenset({"expiry"})
"""Checks whose failure means "genuine but stale" → DEFER + alert rather than REJECT."""
