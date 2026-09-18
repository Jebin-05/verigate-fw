"""Mutation catalogue (seeded, documented) and image features (pure, ELF-aware)."""

from __future__ import annotations

import struct
from pathlib import Path

import numpy as np
import pytest

from verigate.ml.data.mutate import CATALOGUE, ELF_HEADER_LEN, catalogue_markdown
from verigate.ml.features.image_features import (
    CHUNK,
    FEATURE_NAMES,
    as_vector,
    chunk_entropies,
    image_features,
    parse_elf,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "releases"
FW1 = (FIXTURES / "v1.0.0" / "firmware.bin").read_bytes()
FW2 = (FIXTURES / "v1.1.0" / "firmware.bin").read_bytes()


def elf64_with_sections(body: bytes, n_sections: int = 3, nobits: bool = True) -> bytes:
    """A minimal ELF64 image: header, body, then a section table describing the body."""
    sh_len = 64
    shoff = 64 + len(body)
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header += struct.pack(
        "<HHIQQQIHHHHHH", 2, 0xB7, 1, 0x1000, 0, shoff, 0, 64, 0, 0, sh_len, n_sections, 0
    )
    table = b""
    per = len(body) // n_sections
    for i in range(n_sections):
        sh_type = 8 if (nobits and i == n_sections - 1) else 1
        table += struct.pack("<IIQQQQIIQQ", i, sh_type, 0, 0, 64 + i * per, per, 0, 0, 1, 0)
    return header + body + table


@pytest.mark.parametrize("name", list(CATALOGUE))
def test_mutations_are_deterministic_and_change_the_image(name: str) -> None:
    m = CATALOGUE[name]
    extra = {"old_image": FW1} if name == "downgrade-relabel" else {}
    a = m.apply(FW2, 42, **extra)
    b = m.apply(FW2, 42, **extra)
    c = m.apply(FW2, 43, **extra)
    assert a == b
    assert a != FW2
    assert a[:ELF_HEADER_LEN] == FW2[:ELF_HEADER_LEN]  # the header is never touched
    if name != "downgrade-relabel":
        assert c != a  # seed matters (except for the seedless relabel)
    if name == "append":
        assert len(a) == len(FW2) + m.params["size"]
    elif name == "downgrade-relabel":
        assert len(a) == len(FW1)  # the old body under the new label
    else:
        assert len(a) == len(FW2)


def test_mutation_edge_cases() -> None:
    tiny = b"\x7fELF" + b"\x00" * 100
    assert CATALOGUE["byte-patch"].apply(tiny, 1) == tiny  # too small to patch safely
    assert CATALOGUE["section-swap"].apply(tiny, 1) == tiny
    assert CATALOGUE["downgrade-relabel"].apply(FW2, 1) == FW2  # no old image given
    incompressible = bytes(np.random.default_rng(0).integers(0, 256, 4096, dtype=np.uint8))
    assert CATALOGUE["pack"].apply(incompressible, 1) == incompressible
    md = catalogue_markdown()
    assert md.count("\n") == len(CATALOGUE) + 2 and "`append`" in md


def test_parse_elf_and_appended_bytes() -> None:
    body = bytes(range(256)) * 12
    image = elf64_with_sections(body)
    info = parse_elf(image)
    assert info.valid and info.n_sections == 3 and info.declared_end == len(image)
    appended = image + b"\xff" * 2048
    assert parse_elf(appended).declared_end == len(image)
    assert image_features(appended)["appended_kb"] == 2
    assert image_features(image)["appended_kb"] == 0
    assert parse_elf(b"not an elf at all").valid is False
    assert parse_elf(b"\x7fELF" + bytes([9, 1])).valid is False
    truncated = image[:70]
    assert parse_elf(truncated).n_sections == 0
    stripped = parse_elf(FW1)  # real stripped binary: no section table, but PT_LOAD segments
    assert stripped.valid and stripped.n_sections == 0 and stripped.n_segments == 9
    assert stripped.declared_end == len(FW1)


def test_chunk_entropies_bounds() -> None:
    zeros = b"\x00" * (3 * CHUNK + 5)
    e = chunk_entropies(zeros)
    assert e.shape == (4,) and e.max() == 0.0
    rnd = bytes(np.random.default_rng(1).integers(0, 256, 8 * CHUNK, dtype=np.uint8))
    assert chunk_entropies(rnd).min() > 7.5
    assert chunk_entropies(b"").size == 0


def test_image_features_shape_and_deltas() -> None:
    f = image_features(FW2, FW1)
    assert list(f) == list(FEATURE_NAMES)
    assert all(isinstance(v, int) for v in f.values())
    assert f["size_delta_kb"] == round((len(FW2) - len(FW1)) / 1024)
    assert 0 <= f["changed_chunks_pct"] <= 100
    assert as_vector(f) == [float(f[n]) for n in FEATURE_NAMES]
    g = image_features(FW2 + b"\x00" * 4096, FW2)
    assert g["size_delta_kb"] == 4 and g["entropy_delta_x1000"] < 0
    assert image_features(b"") == {**dict.fromkeys(FEATURE_NAMES, 0)}
    assert image_features(FW1) == image_features(FW1)
