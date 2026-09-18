// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {MerkleLeaf} from "../libraries/MerkleLeaf.sol";

/// @title MerkleLeafHarness
/// @notice Test-only wrapper exposing the internal library functions to Hardhat tests.
contract MerkleLeafHarness {
    /// @notice See {MerkleLeaf.leaf}.
    function leaf(bytes calldata domain, bytes calldata data) external pure returns (bytes32) {
        return MerkleLeaf.leaf(domain, data);
    }

    /// @notice See {MerkleLeaf.parent}.
    function parent(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return MerkleLeaf.parent(a, b);
    }

    /// @notice See {MerkleLeaf.verify}.
    function verify(bytes32 root, bytes32 leafHash, bytes32[] calldata proof) external pure returns (bool) {
        return MerkleLeaf.verify(root, leafHash, proof);
    }
}
