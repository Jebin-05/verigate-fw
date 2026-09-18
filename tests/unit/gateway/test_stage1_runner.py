"""Runner: fail-closed order, first failure short-circuits, expiry → DEFER, logs name the check."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

import pytest
import structlog
from stage1_fixture_helpers import EXPIRY

from verigate.common.logging import configure_logging
from verigate.common.settings import Settings
from verigate.gateway.stage1.checks import CHECKS
from verigate.gateway.stage1.inputs import Stage1Input
from verigate.gateway.stage1.runner import run_stage1
from verigate.gateway.verdicts.types import Verdict


def test_all_pass(valid_input: Stage1Input) -> None:
    result = run_stage1(valid_input, "rid")
    assert result.ok and result.failed is None and result.outcome is None
    assert [r.name for r in result.results] == [c(valid_input).name for c in CHECKS]
    assert all(r.ok for r in result.results)
    assert result.to_dict()["outcome"] is None
    assert len(result.to_dict()["checks"]) == 8


def test_first_failure_short_circuits(valid_input: Stage1Input) -> None:
    result = run_stage1(replace(valid_input, firmware=b"tampered", sbom=None), "rid")
    assert not result.ok
    assert result.failed == "firmware_hash"
    assert result.outcome is Verdict.REJECT
    assert len(result.results) == 1  # sbom_hash never ran


def test_expiry_defers_not_rejects(valid_input: Stage1Input) -> None:
    result = run_stage1(replace(valid_input, now=EXPIRY + timedelta(days=1)), "rid")
    assert result.failed == "expiry"
    assert result.outcome is Verdict.DEFER
    assert len(result.results) == 5


def test_everything_missing_fails_closed(valid_input: Stage1Input) -> None:
    empty = replace(
        valid_input, manifest=None, firmware=None, sbom=None, release=None, publisher=None
    )
    result = run_stage1(empty)
    assert result.outcome is Verdict.REJECT and result.failed == "firmware_hash"
    assert result.reason == "manifest unavailable"


def test_deterministic(valid_input: Stage1Input) -> None:
    assert run_stage1(valid_input) == run_stage1(valid_input)


def test_structured_log_names_the_check(
    valid_input: Stage1Input, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(Settings(_env_file=None, verigate_env="ci"))
    run_stage1(replace(valid_input, release=replace(valid_input.release, revoked=True)), "rid-1")  # type: ignore[arg-type]
    lines = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines()]
    failed = [line for line in lines if line["event"] == "stage1.failed"]
    assert failed == [
        {
            **failed[0],
            "check": "registry_record",
            "outcome": "REJECT",
            "release_id": "rid-1",
            "device_id": "dev-01",
            "level": "warning",
        }
    ]
    assert [line["check"] for line in lines if line["event"] == "stage1.check"][
        -1
    ] == "registry_record"
    structlog.reset_defaults()
