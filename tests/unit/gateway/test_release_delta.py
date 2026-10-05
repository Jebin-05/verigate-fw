"""Release delta (Stage-1 check #9): block matching, patch / reorder detection, change regions."""

from __future__ import annotations

import numpy as np
import pytest
from stage1_fixture_helpers import FIXTURES

from verigate.gateway.stage1.delta import BLOCK, PATCH_LIMIT_BLOCKS, release_delta
from verigate.ml.data.mutate import CATALOGUE


@pytest.fixture(scope="module")
def image() -> bytes:
    return (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()


def test_identical_is_not_patched(image: bytes) -> None:
    d = release_delta(image, image)
    assert d.identical and not d.patched and d.regions == ()


def test_shifted_code_still_matches(image: bytes) -> None:
    d = release_delta(b"\0" * 4 + image, image)  # every block moved by 4 bytes
    assert d.changed_blocks <= 2 and not d.reordered


def test_byte_patch_is_patched_and_located(image: bytes) -> None:
    patched = bytearray(image)
    patched[BLOCK * 10 : BLOCK * 10 + 16] = b"\xff" * 16
    d = release_delta(bytes(patched), image)
    assert d.patched and d.changed_blocks == 1
    assert d.regions == ((BLOCK * 10, BLOCK),)


def test_catalogue_patch_and_relabel_are_patched(image: bytes) -> None:
    other = (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()
    assert release_delta(CATALOGUE["byte-patch"].apply(image, 1), image).patched
    relabel = CATALOGUE["downgrade-relabel"].apply(other, 1, old_image=image)
    assert release_delta(relabel, image).patched


def test_section_swap_is_reordered(image: bytes) -> None:
    d = release_delta(CATALOGUE["section-swap"].apply(image, 5), image)
    assert d.patched and d.reordered >= 1 and d.changed_blocks <= 1


def test_rebuild_and_append_are_not_patched(image: bytes) -> None:
    other = (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()
    assert release_delta(other, image).changed_blocks > PATCH_LIMIT_BLOCKS
    assert not release_delta(other, image).patched
    assert not release_delta(CATALOGUE["append"].apply(image, 1), image).patched


def test_tail_region_length_is_exact(image: bytes) -> None:
    rng = np.random.default_rng(0)
    d = release_delta(image + rng.integers(0, 256, 10, dtype=np.uint8).tobytes(), image)
    start, length = d.regions[-1]
    assert start + length == len(image) + 10


def test_deterministic(image: bytes) -> None:
    patched = CATALOGUE["byte-patch"].apply(image, 9)
    assert release_delta(patched, image) == release_delta(patched, image)


def test_moved_repeated_content_is_reordered() -> None:
    rng = np.random.default_rng(1)
    code = rng.integers(0, 256, 64 * 64, dtype=np.uint8).tobytes()
    trusted = code[:2048] + b"\0" * 1024 + code[2048:] + b"\xff" * 1024
    moved = code[:2048] + b"\xff" * 1024 + code[2048:] + b"\0" * 1024  # the two fills swapped
    d = release_delta(moved, trusted)
    assert d.changed_blocks == 0 and d.reordered >= 1 and d.patched
