"""``verigate-attack`` — run one attack scenario (or all) against the running gateway."""

from __future__ import annotations

import json
import sys
from types import ModuleType
from typing import Annotated

import typer

from verigate.attacks import (
    bad_history,
    forge,
    freeze,
    hidden_payload,
    poisoned_model,
    policy_tamper,
    rollback,
    sbom_swap,
    stolen_key,
    tamper,
    vulnerable_genuine,
)
from verigate.attacks.common import AttackContext
from verigate.common.errors import VerigateError
from verigate.common.logging import configure_logging
from verigate.common.settings import get_settings

ATTACKS: dict[str, ModuleType] = {
    m.NAME: m
    for m in (
        tamper,
        forge,
        stolen_key,
        rollback,
        freeze,
        sbom_swap,
        vulnerable_genuine,
        hidden_payload,
        bad_history,
        poisoned_model,
        policy_tamper,
    )
}
"""Registry of scenarios in demo order (Guide §9 rows 1–6 Stage 1, 7–11 the AI gate)."""

app = typer.Typer(help="Attack scenarios.", add_completion=False, pretty_exceptions_enable=False)


@app.callback()
def main() -> None:
    """Attack scenarios against the local emulated fleet (``verigate-attack run <name>``)."""


@app.command("list")
def list_attacks() -> None:
    """Print the available scenarios with their expected verdict."""
    sys.stdout.write(
        json.dumps({name: {"expected": m.EXPECTED} for name, m in ATTACKS.items()}, indent=2) + "\n"
    )


@app.command()
def run(
    name: Annotated[str, typer.Argument(help="Scenario name or 'all'")],
    gateway: Annotated[str | None, typer.Option("--gateway", help="Gateway base URL")] = None,
) -> None:
    """Run a scenario; prints one JSON report per scenario; exit 1 if any observed != expected."""
    settings = get_settings()
    configure_logging(settings)
    names = list(ATTACKS) if name == "all" else [name]
    unknown = [n for n in names if n not in ATTACKS]
    if unknown:
        sys.stdout.write(json.dumps({"error": f"unknown attack {unknown[0]}"}) + "\n")
        raise typer.Exit(code=2)
    try:
        ctx = AttackContext.from_settings(settings, gateway)
    except VerigateError as exc:
        sys.stdout.write(json.dumps({"error": str(exc)}) + "\n")
        raise typer.Exit(code=1) from exc
    failed = False
    for n in names:
        report = ATTACKS[n].run(ctx)
        failed |= not report.passed
        sys.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    raise typer.Exit(code=1 if failed else 0)


if __name__ == "__main__":
    app()
