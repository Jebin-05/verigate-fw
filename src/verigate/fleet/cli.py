"""``verigate-fleet`` — run N emulated devices against a gateway."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from verigate.common.chain import ChainClient
from verigate.common.logging import configure_logging
from verigate.common.settings import get_settings
from verigate.fleet.runner import run_fleet

app = typer.Typer(
    help="Emulated device fleet.", add_completion=False, pretty_exceptions_enable=False
)


@app.callback()
def main() -> None:
    """Emulated device fleet (``verigate-fleet run --count N``)."""


@app.command()
def run(
    count: Annotated[int, typer.Option("--count", "-n", min=1, help="Number of devices")] = 20,
    gateway: Annotated[str | None, typer.Option("--gateway", help="Gateway base URL")] = None,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Per-device state")] = Path(
        ".verigate/fleet"
    ),
    model: Annotated[str, typer.Option("--model", help="Device model")] = "demo-device",
    interval: Annotated[float, typer.Option("--interval", min=0.1, help="Poll interval s")] = 5.0,
    rounds: Annotated[
        int | None, typer.Option("--rounds", min=1, help="Stop after N polls")
    ] = None,
    prefix: Annotated[str, typer.Option("--prefix", help="Device id prefix")] = "dev",
    chain_check: Annotated[
        bool,
        typer.Option(
            "--chain-check/--no-chain-check",
            help="Devices read the publisher key and release record from the chain themselves",
        ),
    ] = True,
) -> None:
    """Start the fleet; prints a JSON stats object when it stops (Ctrl-C or --rounds)."""
    settings = get_settings()
    configure_logging(settings)
    url = gateway or f"http://127.0.0.1:{settings.gateway_port}"
    chain = ChainClient(settings) if chain_check else None
    try:
        stats = asyncio.run(
            run_fleet(url, state_dir, count, model, interval, rounds, prefix, chain)
        )
    except KeyboardInterrupt:
        return
    sys.stdout.write(json.dumps(stats.to_dict(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    app()
