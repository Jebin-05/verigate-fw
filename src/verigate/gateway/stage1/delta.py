"""Release delta: how a new image differs from the last trusted image of the same device model.

Vendors ship rebuilt images; a rebuild of an OpenWrt package changes at least 76 of its 64-byte
blocks in the corpus (``evaluation/results/release_delta``). An image that *is* the trusted image
with a handful of blocks overwritten, or with its blocks reordered, is the footprint of a
post-build modification (an insider patch, a relabelled old build). Check #9 sends such a release
to human review; it never rejects, because a vendor binary hot-patch looks the same.

Pure and deterministic: no I/O, no model. Blocks of the new image are looked up among the trusted
image's 64-byte windows at every 4-byte offset, so code that merely moved still matches.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

BLOCK = 64
STRIDE = 4
PATCH_LIMIT_BLOCKS = 32
"""At most this many changed blocks (2 KiB) on top of the trusted image counts as a patch."""
REORDER_GAP = 4096
"""A matched block that lands more than this many bytes *before* its predecessor is reordered."""


@dataclass(frozen=True)
class ReleaseDelta:
    """What changed between the trusted image and the new one."""

    blocks: int
    changed_blocks: int
    reordered: int
    regions: tuple[tuple[int, int], ...]  # (offset, length) of each changed run in the new image

    @property
    def identical(self) -> bool:
        """Byte-for-byte reuse of the trusted image (a re-release)."""
        return self.changed_blocks == 0 and self.reordered == 0

    @property
    def patched(self) -> bool:
        """The trusted image with a few blocks overwritten or moved: route to review."""
        return not self.identical and self.changed_blocks <= PATCH_LIMIT_BLOCKS


@lru_cache(maxsize=64)
def release_delta(new: bytes, trusted: bytes) -> ReleaseDelta:
    """Compare ``new`` with ``trusted`` block by block (see the module docstring).

    Pure, so cached: a fleet verifies the same (release, reference) pair once per device.
    """
    first: dict[bytes, int] = {}
    repeated: set[bytes] = set()
    for off in range(0, len(trusted) - BLOCK + 1, STRIDE):
        window = trusted[off : off + BLOCK]
        if window in first:
            repeated.add(window)
        else:
            first[window] = off
    changed: list[int] = []
    positions: list[int] = []
    displaced_runs = 0
    cursor: int | None = None  # where the trusted image continues if nothing moved
    in_run = False
    n_full = len(new) // BLOCK
    for i in range(n_full):
        block = new[i * BLOCK : (i + 1) * BLOCK]
        pos = first.get(block)
        displaced = False
        if pos is None:
            changed.append(i)
        elif block not in repeated:
            positions.append(pos)
            cursor = pos
        elif cursor is not None and cursor + BLOCK <= len(trusted):
            # a repeated block (padding, tables) has no unique position: it must sit where the
            # trusted image continues, otherwise it was moved here
            displaced = trusted[cursor : cursor + BLOCK] != block
        displaced_runs += displaced and not in_run
        in_run = displaced
        cursor = None if cursor is None else cursor + BLOCK
    tail = new[n_full * BLOCK :]
    if tail and tail not in trusted:
        changed.append(n_full)
    jumps_back = sum(
        1 for a, b in zip(positions, positions[1:], strict=False) if b < a - REORDER_GAP
    )
    reordered = jumps_back + displaced_runs
    regions: list[tuple[int, int]] = []
    for i in changed:
        if regions and regions[-1][0] + regions[-1][1] == i * BLOCK:
            regions[-1] = (regions[-1][0], regions[-1][1] + BLOCK)
        else:
            regions.append((i * BLOCK, BLOCK))
    if regions and changed[-1] == n_full:
        start, length = regions[-1]
        regions[-1] = (start, length - BLOCK + len(tail))
    return ReleaseDelta(n_full + (1 if tail else 0), len(changed), reordered, tuple(regions))
