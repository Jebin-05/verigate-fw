// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title MerkleLeaf
/// @notice SHA-256 Merkle proofs with domain-separated leaves; byte-identical to
///         `verigate.common.merkle` in Python (golden vectors in `tests/fixtures/merkle/`).
/// @dev leaf = sha256(0x00 ‖ domain ‖ data); node = sha256(0x01 ‖ min(a,b) ‖ max(a,b)).
///      Odd nodes are promoted unchanged, so a proof is just the ordered list of siblings.
library MerkleLeaf {
    /// @notice Hash a record into a leaf under `domain`.
    /// @param domain Record-type tag, e.g. "VERIGATE-VERDICT-V1".
    /// @param data Canonical bytes of the record.
    function leaf(bytes memory domain, bytes memory data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x00), domain, data));
    }

    /// @notice Combine two child digests (order-independent).
    function parent(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        (bytes32 lo, bytes32 hi) = a < b ? (a, b) : (b, a);
        return sha256(abi.encodePacked(bytes1(0x01), lo, hi));
    }

    /// @notice True iff `leafHash` combined with `proof` reproduces `root`.
    /// @param root The committed batch root.
    /// @param leafHash A leaf produced by {leaf}.
    /// @param proof Sibling hashes from the leaf up to (excluding) the root.
    function verify(bytes32 root, bytes32 leafHash, bytes32[] memory proof) internal pure returns (bool) {
        bytes32 node = leafHash;
        uint256 len = proof.length;
        for (uint256 i = 0; i < len; ++i) {
            node = parent(node, proof[i]);
        }
        return node == root;
    }
}
