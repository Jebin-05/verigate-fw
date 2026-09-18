// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IVerdictRegistry
/// @notice Merkle-batched, model-attributed verdict commitments (Guide §8, Novelty 1 + efficiency claim).
interface IVerdictRegistry {
    /// @notice One committed batch of verdict leaves.
    /// @param root Merkle root over `count` leaves (see MerkleLeaf).
    /// @param count Number of verdicts in the batch (≥ 1).
    /// @param blockNumber Block of commitment.
    /// @param gateway The gateway that committed it.
    /// @param modelHashes Every model hash used by verdicts in this batch (may be empty for Stage-1-only).
    struct Batch {
        bytes32 root;
        uint32 count;
        uint64 blockNumber;
        address gateway;
        bytes32[] modelHashes;
    }

    /// @notice Emitted per batch; the dashboard and evaluation runners index on it.
    event BatchCommitted(
        uint256 indexed batchId, bytes32 indexed root, uint32 count, address indexed gateway, bytes32[] modelHashes
    );

    error InvalidRoot();
    error EmptyBatch();
    error TooManyModels(uint256 n);
    error ModelNotActive(bytes32 modelHash);
    error UnknownBatch(uint256 batchId);

    /// @notice Gateway: commit a Merkle root over `count` verdicts produced with `modelHashes`.
    /// @return batchId Zero-based index of the new batch.
    function commitBatch(bytes32 root, uint32 count, bytes32[] calldata modelHashes) external returns (uint256 batchId);

    /// @notice True iff `leaf` is in batch `batchId` under `proof`.
    function verifyLeaf(uint256 batchId, bytes32 leaf, bytes32[] calldata proof) external view returns (bool);

    /// @notice Pure proof check against an arbitrary root (no storage read).
    function verifyRoot(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external pure returns (bool);

    /// @notice Batch ids that used `modelHash`, if and only if that model is now REVOKED; else empty.
    function staleByModel(bytes32 modelHash) external view returns (uint256[] memory);

    /// @notice All batch ids that used `modelHash`, regardless of status.
    function batchesByModel(bytes32 modelHash) external view returns (uint256[] memory);

    /// @notice Number of batches committed so far.
    function batchCount() external view returns (uint256);

    /// @notice Batch by id.
    function getBatch(uint256 batchId) external view returns (Batch memory);
}
