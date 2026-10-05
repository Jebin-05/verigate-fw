"""Frozen inputs to the Stage-1 checks. Anything that could not be fetched is ``None``."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from verigate.common.chain import ModelRecord, PublisherRecord, ReleaseRecord
from verigate.common.manifest import SemVer, SignedManifest


@dataclass(frozen=True)
class DeviceView:
    """What the gateway knows about the target device when it verifies a release for it."""

    device_id: str
    device_model: str
    installed_version: SemVer


@dataclass(frozen=True)
class Stage1Input:
    """Everything the nine checks look at. ``None`` means "could not be obtained" → fail closed.

    ``trusted_firmware`` is the image of the last non-revoked release of the same publisher and
    device model; ``None`` with ``trusted_unavailable=False`` means there is no such release.
    """

    manifest: SignedManifest | None
    firmware: bytes | None
    sbom: bytes | None
    release: ReleaseRecord | None
    publisher: PublisherRecord | None
    device: DeviceView
    models: tuple[ModelRecord | None, ...]
    now: datetime
    trusted_firmware: bytes | None = None
    trusted_unavailable: bool = False
