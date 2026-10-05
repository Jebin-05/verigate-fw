"""Table-driven tests: one parametrised test per check with valid / missing / malformed /
boundary / dependency-unavailable rows (Manual §6)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

import pytest
from stage1_fixture_helpers import (
    EXPIRY,
    FIXTURES,
    NOW,
    model_record,
    publisher_record,
    release_record,
)

from verigate.common.chain import STATUS_NONE, STATUS_REVOKED
from verigate.common.crypto import KeyPair
from verigate.common.manifest import SemVer, SignedManifest
from verigate.gateway.stage1 import checks
from verigate.gateway.stage1.inputs import DeviceView, Stage1Input
from verigate.ml.data.mutate import CATALOGUE

Mutation = Any  # callable(valid_input) -> Stage1Input


def resign(inp: Stage1Input, **fields: Any) -> SignedManifest:
    """A manifest with ``fields`` changed but the *old* signature kept (tampered)."""
    assert inp.manifest is not None
    return inp.manifest.model_copy(update=fields)


ROWS: dict[str, list[tuple[str, Mutation, bool, str | None]]] = {
    "firmware_hash": [
        ("valid", lambda i: i, True, None),
        ("firmware missing", lambda i: replace(i, firmware=None), False, "firmware unavailable"),
        ("manifest missing", lambda i: replace(i, manifest=None), False, "manifest unavailable"),
        (
            "one byte flipped",
            lambda i: replace(i, firmware=i.firmware[:-1] + bytes([i.firmware[-1] ^ 0xFF])),
            False,
            "!= manifest",
        ),
        ("empty firmware", lambda i: replace(i, firmware=b""), False, "!= manifest"),
        (
            "on-chain record disagrees",
            lambda i: replace(i, release=release_record(i.manifest, firmware_hash=b"\x01" * 32)),
            False,
            "on-chain record",
        ),
        (
            "record unavailable still passes hash check",
            lambda i: replace(i, release=None),
            True,
            None,
        ),
    ],
    "signature": [
        ("valid", lambda i: i, True, None),
        ("manifest missing", lambda i: replace(i, manifest=None), False, "manifest unavailable"),
        ("publisher unavailable", lambda i: replace(i, publisher=None), False, "not registered"),
        (
            "publisher unknown on-chain",
            lambda i: replace(
                i, publisher=publisher_record(KeyPair.generate(), status=STATUS_NONE)
            ),
            False,
            "not registered",
        ),
        (
            "signed by another key",
            lambda i: replace(i, publisher=publisher_record(KeyPair.generate())),
            False,
            "does not verify",
        ),
        (
            "field changed after signing",
            lambda i: replace(i, manifest=resign(i, deviceModel="other")),
            False,
            "does not verify",
        ),
        (
            "record for a different DID",
            lambda i: replace(
                i, publisher=publisher_record(KeyPair.generate(), did="did:verigate:other")
            ),
            False,
            "does not belong",
        ),
    ],
    "publisher_active": [
        ("valid", lambda i: i, True, None),
        ("publisher unavailable", lambda i: replace(i, publisher=None), False, "unknown"),
        (
            "status NONE",
            lambda i: replace(i, publisher=publisher_record(KeyPair.generate(), STATUS_NONE)),
            False,
            "unknown",
        ),
        (
            "revoked",
            lambda i: replace(
                i,
                publisher=replace(
                    publisher_record(KeyPair.generate(), STATUS_REVOKED), revoked_at=99
                ),
            ),
            False,
            "revoked at block 99",
        ),
        (
            "unknown status value",
            lambda i: replace(i, publisher=publisher_record(KeyPair.generate(), 7)),
            False,
            "status 7",
        ),
    ],
    "version_monotonic": [
        ("valid (1.1.0 > 1.0.0)", lambda i: i, True, None),
        ("manifest missing", lambda i: replace(i, manifest=None), False, "manifest unavailable"),
        (
            "equal version",
            lambda i: replace(i, device=DeviceView("d", "demo-device", SemVer(1, 1, 0))),
            False,
            "1.1.0 <= installed 1.1.0",
        ),
        (
            "older version (rollback)",
            lambda i: replace(i, device=DeviceView("d", "demo-device", SemVer(2, 0, 0))),
            False,
            "<= installed 2.0.0",
        ),
        (
            "patch boundary",
            lambda i: replace(i, device=DeviceView("d", "demo-device", SemVer(1, 0, 99))),
            True,
            None,
        ),
        (
            "wrong device model",
            lambda i: replace(i, device=DeviceView("d", "acme-lock", SemVer(0, 0, 1))),
            False,
            "device is acme-lock",
        ),
        (
            "fresh device 0.0.0",
            lambda i: replace(i, device=DeviceView("d", "demo-device", SemVer(0, 0, 0))),
            True,
            None,
        ),
    ],
    "expiry": [
        ("valid", lambda i: i, True, None),
        ("manifest missing", lambda i: replace(i, manifest=None), False, "manifest unavailable"),
        ("expiry == now", lambda i: replace(i, now=EXPIRY), False, "expired at"),
        (
            "one second after expiry",
            lambda i: replace(i, now=EXPIRY + timedelta(seconds=1)),
            False,
            "expired at",
        ),
        (
            "one second before expiry",
            lambda i: replace(i, now=EXPIRY - timedelta(seconds=1)),
            True,
            None,
        ),
        ("naive clock", lambda i: replace(i, now=datetime(2026, 1, 1)), False, "timezone"),  # noqa: DTZ001
    ],
    "sbom_hash": [
        ("valid", lambda i: i, True, None),
        ("manifest missing", lambda i: replace(i, manifest=None), False, "manifest unavailable"),
        ("sbom missing", lambda i: replace(i, sbom=None), False, "sbom unavailable"),
        (
            "sbom swapped",
            lambda i: replace(i, sbom=b'{"bomFormat":"CycloneDX","components":[]}'),
            False,
            "!= manifest",
        ),
        (
            "on-chain record disagrees",
            lambda i: replace(i, release=release_record(i.manifest, sbom_hash=b"\x02" * 32)),
            False,
            "on-chain record",
        ),
    ],
    "registry_record": [
        ("valid", lambda i: i, True, None),
        ("manifest missing", lambda i: replace(i, manifest=None), False, "manifest unavailable"),
        ("record unavailable", lambda i: replace(i, release=None), False, "not found"),
        (
            "record empty",
            lambda i: replace(i, release=release_record(i.manifest, registered_at=0)),
            False,
            "not found",
        ),
        (
            "manifest hash mismatch",
            lambda i: replace(i, release=release_record(i.manifest, manifest_hash=b"\x03" * 32)),
            False,
            "manifestHash",
        ),
        (
            "publisher mismatch",
            lambda i: replace(i, release=release_record(i.manifest, publisher_id=b"\x04" * 32)),
            False,
            "publisher",
        ),
        (
            "version mismatch",
            lambda i: replace(i, release=release_record(i.manifest, patch=9)),
            False,
            "version",
        ),
        (
            "revoked",
            lambda i: replace(i, release=release_record(i.manifest, revoked=True)),
            False,
            "revoked",
        ),
    ],
    "model_active": [
        ("valid", lambda i: i, True, None),
        ("no models configured", lambda i: replace(i, models=()), True, None),
        (
            "model status unavailable",
            lambda i: replace(i, models=(model_record(), None)),
            False,
            "unavailable",
        ),
        (
            "model revoked",
            lambda i: replace(i, models=(model_record(STATUS_REVOKED),)),
            False,
            "revoked",
        ),
        (
            "model unregistered",
            lambda i: replace(i, models=(model_record(STATUS_NONE),)),
            False,
            "not registered",
        ),
    ],
    "release_delta": [
        ("valid: no earlier release", lambda i: i, True, None),
        ("identical re-release", lambda i: replace(i, trusted_firmware=i.firmware), True, None),
        (
            "rebuild of a different version",
            lambda i: replace(
                i, trusted_firmware=(FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()
            ),
            True,
            None,
        ),
        (
            "trusted image with 256 bytes overwritten",
            lambda i: replace(i, trusted_firmware=CATALOGUE["byte-patch"].apply(i.firmware, 7)),
            False,
            "blocks changed",
        ),
        (
            "trusted image with two regions swapped",
            lambda i: replace(i, trusted_firmware=CATALOGUE["section-swap"].apply(i.firmware, 7)),
            False,
            "moved",
        ),
        (
            "trusted image unavailable",
            lambda i: replace(i, trusted_unavailable=True),
            False,
            "unavailable",
        ),
        (
            "firmware missing",
            lambda i: replace(i, firmware=None, trusted_firmware=b"x" * 128),
            False,
            "firmware unavailable",
        ),
    ],
}


def _probe() -> Stage1Input:
    """An all-missing input: every check fails on it but still reports its name."""
    return Stage1Input(None, None, None, None, None, DeviceView("d", "m", SemVer(0, 0, 0)), (), NOW)


CHECK_BY_NAME = {check(_probe()).name: check for check in checks.CHECKS}

CASES = [(name, row) for name, rows in ROWS.items() for row in rows]


@pytest.mark.parametrize(("check_name", "row"), CASES, ids=[f"{n}:{r[0]}" for n, r in CASES])
def test_check_table(
    valid_input: Stage1Input, check_name: str, row: tuple[str, Mutation, bool, str | None]
) -> None:
    _, mutate, expected_ok, expected_reason = row
    result = CHECK_BY_NAME[check_name](mutate(valid_input))
    assert result.name == check_name
    assert result.ok is expected_ok, result.reason
    if expected_reason is None:
        assert result.reason is None
    else:
        assert result.reason is not None and expected_reason in result.reason


def test_every_check_is_covered_by_the_table() -> None:
    assert set(ROWS) == set(CHECK_BY_NAME)
