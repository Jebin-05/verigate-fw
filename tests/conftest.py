"""Shared pytest fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from verigate.common.settings import Settings

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Root of ``tests/fixtures``."""
    return FIXTURES


@pytest.fixture(scope="session")
def load_fixture() -> Any:  # noqa: ANN401 — returns a loader callable
    """Return ``loader(relative_path) -> parsed JSON``."""

    def _load(relative: str) -> Any:  # noqa: ANN401
        return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))

    return _load


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings that ignore the developer's ``.env`` and write nothing outside ``tmp_path``."""
    return Settings(
        _env_file=None,
        verigate_env="ci",
        ipfs_backend="local",
        local_ipfs_dir=tmp_path / "ipfs-local",
        deployments_dir=tmp_path / "deployments",
        llm_enabled=False,
        vuln_cache_only=True,
    )
