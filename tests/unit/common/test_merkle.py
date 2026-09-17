"""Merkle tree: golden vectors (shared with Solidity), proof soundness, error branches."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from verigate.common.merkle import (
    VERDICT_DOMAIN,
    MerkleTree,
    leaf_hash,
    node_hash,
    verify_proof,
)

TREES = sorted((Path(__file__).resolve().parents[2] / "fixtures" / "merkle").glob("tree_*.json"))


def test_primitives(load_fixture: Any) -> None:
    vec = load_fixture("merkle/primitives.json")
    assert VERDICT_DOMAIN.hex() == vec["domain_hex"]
    leaf = vec["leaf"]
    assert leaf_hash(VERDICT_DOMAIN, bytes.fromhex(leaf["data_hex"])).hex() == leaf["leaf_hex"]
    assert (
        leaf_hash(VERDICT_DOMAIN, b"record-0")
        == hashlib.sha256(b"\x00" + VERDICT_DOMAIN + b"record-0").digest()
    )
    node = vec["node"]
    a, b = bytes.fromhex(node["a_hex"]), bytes.fromhex(node["b_hex"])
    assert node_hash(a, b).hex() == node["node_hex"]
    assert node_hash(b, a).hex() == node["node_swapped_hex"] == node["node_hex"]


@pytest.mark.parametrize("path", TREES, ids=[p.stem for p in TREES])
def test_golden_trees(path: Path) -> None:
    vec = json.loads(path.read_text())
    leaves = [bytes.fromhex(h) for h in vec["leaves_hex"]]
    tree = MerkleTree.from_leaves(leaves)
    assert tree.root.hex() == vec["root_hex"]
    assert tree.leaves == tuple(leaves)
    for i, proof_hex in enumerate(vec["proofs_hex"]):
        proof = [bytes.fromhex(h) for h in proof_hex]
        assert tree.proof(i) == proof
        assert verify_proof(tree.root, leaves[i], proof)


def test_single_leaf_is_root() -> None:
    leaf = leaf_hash(VERDICT_DOMAIN, b"only")
    tree = MerkleTree.from_leaves([leaf])
    assert tree.root == leaf
    assert tree.proof(0) == []


def test_errors() -> None:
    with pytest.raises(ValueError, match="at least one leaf"):
        MerkleTree.from_leaves([])
    with pytest.raises(ValueError, match="32-byte"):
        MerkleTree.from_leaves([b"short"])
    tree = MerkleTree.from_leaves(
        [leaf_hash(VERDICT_DOMAIN, b"a"), leaf_hash(VERDICT_DOMAIN, b"b")]
    )
    with pytest.raises(IndexError):
        tree.proof(2)
    with pytest.raises(IndexError):
        tree.proof(-1)


@given(st.lists(st.binary(min_size=1, max_size=40), min_size=1, max_size=40, unique=True))
def test_proofs_sound_and_foreign_leaf_rejected(records: list[bytes]) -> None:
    leaves = [leaf_hash(VERDICT_DOMAIN, r) for r in records]
    tree = MerkleTree.from_leaves(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.proof(i)
        assert verify_proof(tree.root, leaf, proof)
        foreign = leaf_hash(VERDICT_DOMAIN, b"not-in-tree:" + records[i])
        assert not verify_proof(tree.root, foreign, proof)
        if proof:
            assert not verify_proof(tree.root, leaf, proof[:-1])
