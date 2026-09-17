"""Package-level sanity: the installed version matches pyproject.toml."""

import tomllib
from pathlib import Path

import verigate


def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    with pyproject.open("rb") as fh:
        declared = tomllib.load(fh)["project"]["version"]
    assert verigate.__version__ == declared
