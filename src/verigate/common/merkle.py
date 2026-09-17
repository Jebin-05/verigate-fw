"""SHA-256 Merkle tree with domain-separated leaves (mirrored by ``MerkleLeaf.sol``).

Construction (must stay byte-identical to the Solidity library):

* ``leaf  = sha256(0x00 ‖ domain ‖ data)`` — the ``0x00`` tag and the domain string make a leaf
  hash unforgeable as an inner node and unique per record type;
* ``node  = sha256(0x01 ‖ min(a, b) ‖ max(a, b))`` — sorted pairs, so a proof is just the list of
  sibling hashes (no position bits);
* an odd node at any level is *promoted* unchanged to the next level (no duplication);
* a single leaf is its own root; an empty tree has no root (batches need ``count >= 1``).

Golden vectors: ``tests/fixtures/merkle/*.json`` (leaves, root, one proof per leaf), asserted by
pytest and by the Hardhat test of ``MerkleLeaf``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"
VERDICT_DOMAIN = b"VERIGATE-VERDICT-V1"


def leaf_hash(domain: bytes, data: bytes) -> bytes:
    """Hash ``data`` into a 32-byte leaf under ``domain``."""
    return hashlib.sha256(LEAF_TAG + domain + data).digest()


def node_hash(a: bytes, b: bytes) -> bytes:
    """Hash two child digests into a parent (order-independent)."""
    lo, hi = (a, b) if a <= b else (b, a)
    return hashlib.sha256(NODE_TAG + lo + hi).digest()


def verify_proof(root: bytes, leaf: bytes, proof: Sequence[bytes]) -> bool:
    """Return ``True`` iff ``leaf`` combined with ``proof`` siblings reproduces ``root``."""
    node = leaf
    for sibling in proof:
        node = node_hash(node, sibling)
    return node == root


@dataclass(frozen=True)
class MerkleTree:
    """An immutable tree built from already-hashed leaves (see :func:`leaf_hash`)."""

    levels: tuple[tuple[bytes, ...], ...]

    @classmethod
    def from_leaves(cls, leaves: Sequence[bytes]) -> MerkleTree:
        """Build the tree bottom-up.

        Raises:
            ValueError: If ``leaves`` is empty or any leaf is not 32 bytes.
        """
        if not leaves:
            raise ValueError("a Merkle tree needs at least one leaf")
        if any(len(leaf) != 32 for leaf in leaves):
            raise ValueError("every leaf must be a 32-byte digest")
        levels: list[tuple[bytes, ...]] = [tuple(leaves)]
        while len(levels[-1]) > 1:
            current = levels[-1]
            parents = [node_hash(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)]
            if len(current) % 2 == 1:
                parents.append(current[-1])  # promote the odd node unchanged
            levels.append(tuple(parents))
        return cls(tuple(levels))

    @property
    def root(self) -> bytes:
        """The 32-byte root digest."""
        return self.levels[-1][0]

    @property
    def leaves(self) -> tuple[bytes, ...]:
        """The leaves in insertion order."""
        return self.levels[0]

    def proof(self, index: int) -> list[bytes]:
        """Sibling hashes from leaf ``index`` up to (but excluding) the root."""
        if not 0 <= index < len(self.leaves):
            raise IndexError(f"leaf index {index} out of range")
        siblings: list[bytes] = []
        for level in self.levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                siblings.append(level[sibling])
            index //= 2
        return siblings
