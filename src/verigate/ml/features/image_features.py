"""Firmware image features (P6-02): pure, deterministic, integer-quantised.

Structural signals only (Guide §6.2 scope statement): chunk entropy statistics, printable ratio,
ELF header sanity and section sizes (when the image is a well-formed ELF), appended bytes after
the declared end, and deltas versus the previous version. No execution, no disassembly.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

CHUNK = 1024
FEATURE_NAMES: tuple[str, ...] = (
    "size_kb",
    "entropy_mean_x1000",
    "entropy_std_x1000",
    "entropy_max_x1000",
    "high_entropy_chunks_pct",
    "printable_ratio_x1000",
    "header_valid",
    "n_sections",
    "n_segments",
    "declared_size_kb",
    "appended_kb",
    "size_delta_kb",
    "entropy_delta_x1000",
    "changed_chunks_pct",
)
"""Column order of the model input vector; changing it is a new model version (Manual §11)."""


@dataclass(frozen=True)
class ElfInfo:
    """What the header parser could establish."""

    valid: bool
    n_sections: int
    declared_end: int  # highest byte covered by a section/segment, or len(image) if unknown
    n_segments: int = 0


def parse_elf(image: bytes) -> ElfInfo:
    """Minimal ELF32/ELF64 header, program-header and section-table parse (never raises).

    The declared end is the highest file byte covered by a PT_LOAD segment or a section (whichever
    is larger); stripped firmware binaries have no section table but always have segments.
    """
    if (
        len(image) < 52
        or image[:4] != b"\x7fELF"
        or image[4] not in (1, 2)
        or image[5] not in (1, 2)
    ):
        return ElfInfo(False, 0, len(image))
    order = "<" if image[5] == 1 else ">"
    is32 = image[4] == 1
    try:
        if is32:
            fields = struct.unpack(order + "HHIIIIIHHHHHH", image[16:52])
            sh_fmt, sh_len, ph_fmt, ph_len = order + "IIIIIIIIII", 40, order + "IIIIIIII", 32
        else:
            fields = struct.unpack(order + "HHIQQQIHHHHHH", image[16:64])
            sh_fmt, sh_len, ph_fmt, ph_len = order + "IIQQQQIIQQ", 64, order + "IIQQQQQQ", 56
    except struct.error:
        return ElfInfo(False, 0, len(image))
    (
        e_type,
        e_machine,
        e_version,
        _,
        phoff,
        shoff,
        _,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        _,
    ) = fields
    valid = e_version == 1 and e_type in (1, 2, 3, 4) and e_machine != 0 and ehsize in (52, 64)
    end = 0
    n_segments = 0
    if phoff and phnum and phentsize == ph_len and phoff + phnum * ph_len <= len(image):
        for i in range(phnum):
            ph = struct.unpack(ph_fmt, image[phoff + i * ph_len : phoff + (i + 1) * ph_len])
            p_type, p_offset, p_filesz = (ph[0], ph[1], ph[4]) if is32 else (ph[0], ph[2], ph[5])
            n_segments += 1
            if p_type == 1:  # PT_LOAD
                end = max(end, p_offset + p_filesz)
    n_sections = 0
    if shoff and shnum and shentsize == sh_len and shoff + shnum * sh_len <= len(image):
        n_sections = shnum
        for i in range(shnum):
            sh = struct.unpack(sh_fmt, image[shoff + i * sh_len : shoff + (i + 1) * sh_len])
            if sh[1] != 8:  # SHT_NOBITS occupies no file space
                end = max(end, sh[4] + sh[5])
        end = max(end, shoff + shnum * sh_len)
    declared = min(end, len(image)) if end else len(image)
    return ElfInfo(valid, n_sections, declared, n_segments)


def chunk_entropies(image: bytes, chunk: int = CHUNK) -> np.ndarray:
    """Shannon entropy (bits/byte) of every ``chunk``-byte window."""
    data = np.frombuffer(image, dtype=np.uint8)
    if data.size == 0:
        return np.zeros(0)
    n = math.ceil(data.size / chunk)
    padded = np.zeros(n * chunk, dtype=np.uint8)
    padded[: data.size] = data
    windows = padded.reshape(n, chunk).astype(np.int64)
    flat = (np.arange(n, dtype=np.int64)[:, None] * 256 + windows).ravel()
    counts = np.bincount(flat, minlength=n * 256).reshape(n, 256).astype(float)
    lengths = np.full(n, chunk, dtype=float)
    lengths[-1] = data.size - (n - 1) * chunk
    counts[-1, 0] -= chunk - lengths[-1]  # the zero padding of the last window is not data
    probs = counts / lengths[:, None]
    with np.errstate(divide="ignore", invalid="ignore"):
        logs = np.where(probs > 0, np.log2(probs), 0.0)
    entropy: np.ndarray = -(probs * logs).sum(axis=1)
    return entropy


def image_features(image: bytes, previous: bytes | None = None) -> dict[str, int]:
    """Quantised feature vector for ``image`` (and deltas versus ``previous`` when given)."""
    ent = chunk_entropies(image)
    printable = sum(1 for b in image if 32 <= b < 127) / len(image) if image else 0.0
    elf = parse_elf(image)
    size = len(image)
    delta_size = size - len(previous) if previous is not None else 0
    prev_ent = chunk_entropies(previous) if previous is not None else np.zeros(0)
    ent_delta = float(ent.mean() - prev_ent.mean()) if ent.size and prev_ent.size else 0.0
    if previous is not None and ent.size and prev_ent.size:
        n = min(ent.size, prev_ent.size)
        a = (
            np.frombuffer(image[: n * CHUNK], dtype=np.uint8).reshape(-1, CHUNK)
            if n * CHUNK <= len(image)
            else None
        )
        b = (
            np.frombuffer(previous[: n * CHUNK], dtype=np.uint8).reshape(-1, CHUNK)
            if n * CHUNK <= len(previous)
            else None
        )
        changed = (
            float(np.mean(np.any(a != b, axis=1))) if a is not None and b is not None and n else 1.0
        )
    else:
        changed = 0.0
    return {
        "size_kb": round(size / 1024),
        "entropy_mean_x1000": round(float(ent.mean()) * 1000) if ent.size else 0,
        "entropy_std_x1000": round(float(ent.std()) * 1000) if ent.size else 0,
        "entropy_max_x1000": round(float(ent.max()) * 1000) if ent.size else 0,
        "high_entropy_chunks_pct": round(float(np.mean(ent > 7.5)) * 100) if ent.size else 0,
        "printable_ratio_x1000": round(printable * 1000),
        "header_valid": int(elf.valid),
        "n_sections": elf.n_sections,
        "n_segments": elf.n_segments,
        "declared_size_kb": round(elf.declared_end / 1024),
        "appended_kb": round(max(0, size - elf.declared_end) / 1024),
        "size_delta_kb": round(delta_size / 1024),
        "entropy_delta_x1000": round(ent_delta * 1000),
        "changed_chunks_pct": round(changed * 100),
    }


def as_vector(features: dict[str, int], names: Sequence[str] = FEATURE_NAMES) -> list[float]:
    """Feature dict → model input row."""
    return [float(features[n]) for n in names]
