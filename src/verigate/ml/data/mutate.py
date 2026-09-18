"""Mutation catalogue for the synthetic tampered set (P6-01) — part of the paper's reproducibility.

Every mutation is a pure function ``(image, seed, **params) -> bytes`` driven by
``numpy.random.default_rng(seed)``; the catalogue records name, description and parameters so the
exact tampered set can be regenerated. The set is *synthetic structural tampering*, not
real-world malware (Guide §6.2, §11) — say so wherever it is used.
"""

from __future__ import annotations

import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np

ELF_HEADER_LEN = 64  # never mutate the header itself: header sanity is a separate feature


@dataclass(frozen=True)
class Mutation:
    """One catalogue entry."""

    name: str
    description: str
    params: dict[str, Any]
    fn: Callable[..., bytes] = field(repr=False, compare=False)

    def apply(self, image: bytes, seed: int, **overrides: Any) -> bytes:  # noqa: ANN401
        """Apply with the catalogue parameters (optionally overridden)."""
        return self.fn(image, seed, **{**self.params, **overrides})


def byte_patch(image: bytes, seed: int, n_patches: int = 4, patch_len: int = 64) -> bytes:
    """Overwrite ``n_patches`` random regions of ``patch_len`` bytes with random bytes."""
    rng = np.random.default_rng(seed)
    out = bytearray(image)
    body = len(out) - ELF_HEADER_LEN - patch_len
    if body <= 0:
        return bytes(out)
    for _ in range(n_patches):
        offset = ELF_HEADER_LEN + int(rng.integers(0, body))
        out[offset : offset + patch_len] = rng.integers(
            0, 256, size=patch_len, dtype=np.uint8
        ).tobytes()
    return bytes(out)


def append(image: bytes, seed: int, size: int = 200 * 1024) -> bytes:
    """Append ``size`` bytes of high-entropy payload after the declared image end."""
    rng = np.random.default_rng(seed)
    return image + rng.integers(0, 256, size=size, dtype=np.uint8).tobytes()


def section_swap(image: bytes, seed: int, chunk_size: int = 16 * 1024) -> bytes:
    """Swap two random ``chunk_size`` regions of the body (content preserved, layout broken)."""
    rng = np.random.default_rng(seed)
    out = bytearray(image)
    n_chunks = (len(out) - ELF_HEADER_LEN) // chunk_size
    if n_chunks < 2:
        return bytes(out)
    a, b = rng.choice(n_chunks, size=2, replace=False)
    sa, sb = ELF_HEADER_LEN + int(a) * chunk_size, ELF_HEADER_LEN + int(b) * chunk_size
    out[sa : sa + chunk_size], out[sb : sb + chunk_size] = (
        out[sb : sb + chunk_size],
        out[sa : sa + chunk_size],
    )
    return bytes(out)


def pack(image: bytes, seed: int, level: int = 9) -> bytes:
    """Compress the body (header kept) and pad with random bytes to the original length.

    This is the profile of a packed / encrypted payload.
    """
    rng = np.random.default_rng(seed)
    header, body = image[:ELF_HEADER_LEN], image[ELF_HEADER_LEN:]
    packed = zlib.compress(body, level)
    if len(packed) >= len(body):
        return image
    pad = rng.integers(0, 256, size=len(body) - len(packed), dtype=np.uint8).tobytes()
    return header + packed + pad


def downgrade_relabel(
    image: bytes,
    seed: int,  # noqa: ARG001 — deterministic by construction; kept for the uniform signature
    old_image: bytes = b"",
    label_len: int = 64,
) -> bytes:
    """Ship the *old* image body under the new image's header and version strings.

    ``old_image`` is the previous release; the first ``label_len`` bytes after the header (where
    the version string lives in the fixtures) are copied from the new image.
    """
    if not old_image:
        return image
    cut = ELF_HEADER_LEN + label_len
    return image[:cut] + old_image[cut:]


CATALOGUE: dict[str, Mutation] = {
    "byte-patch": Mutation(
        "byte-patch",
        "overwrite random regions with random bytes (backdoor-style patch)",
        {"n_patches": 4, "patch_len": 64},
        byte_patch,
    ),
    "append": Mutation(
        "append",
        "append a high-entropy payload after the declared image end",
        {"size": 200 * 1024},
        append,
    ),
    "section-swap": Mutation(
        "section-swap",
        "swap two body regions (layout tampering, content preserved)",
        {"chunk_size": 16 * 1024},
        section_swap,
    ),
    "pack": Mutation(
        "pack",
        "compress the body and pad randomly (packed / encrypted payload profile)",
        {"level": 9},
        pack,
    ),
    "downgrade-relabel": Mutation(
        "downgrade-relabel",
        "old image body under the new header and version label",
        {"label_len": 64},
        downgrade_relabel,
    ),
}
"""The mutation catalogue (name → Mutation), in the order used by the paper's table."""


def catalogue_markdown() -> str:
    """Table for docs/paper: name, description, parameters."""
    lines = ["| mutation | description | parameters |", "|---|---|---|"]
    lines += [f"| `{m.name}` | {m.description} | `{m.params}` |" for m in CATALOGUE.values()]
    return "\n".join(lines) + "\n"
