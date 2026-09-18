// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Roles} from "./access/Roles.sol";
import {IModelRegistry} from "./interfaces/IModelRegistry.sol";
import {IVerdictRegistry} from "./interfaces/IVerdictRegistry.sol";
import {MerkleLeaf} from "./libraries/MerkleLeaf.sol";

/// @title VerdictRegistry
/// @notice One transaction per batch of verdicts: a Merkle root plus the model hashes that produced them.
/// @dev Storage layout (append-only after v0.1.0):
///      slot 0..: AccessControl
///      models          : immutable (no slot)
///      _batches        : Batch[]
///      _batchesByModel : mapping(bytes32 modelHash => uint256[] batchIds)
///      `staleByModel` is a view over `_batchesByModel`; it is never called from a transaction, so the
///      unbounded loop rule (Manual §4.2) does not apply. Off-chain callers paginate via `batchesByModel`.
contract VerdictRegistry is AccessControl, IVerdictRegistry {
    /// @notice Registry consulted for model status at commit time and in `staleByModel`.
    IModelRegistry public immutable models;
    /// @notice Upper bound on model hashes per batch (a verdict uses at most a few models).
    uint256 public constant MAX_MODELS_PER_BATCH = 8;

    Batch[] private _batches;
    mapping(bytes32 modelHash => uint256[] batchIds) private _batchesByModel;

    /// @param admin Receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE; ADMIN_ROLE administers GATEWAY_ROLE.
    /// @param models_ The deployed ModelRegistry.
    constructor(address admin, IModelRegistry models_) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.ADMIN_ROLE, admin);
        _setRoleAdmin(Roles.GATEWAY_ROLE, Roles.ADMIN_ROLE);
        models = models_;
    }

    /// @inheritdoc IVerdictRegistry
    function commitBatch(bytes32 root, uint32 count, bytes32[] calldata modelHashes)
        external
        onlyRole(Roles.GATEWAY_ROLE)
        returns (uint256 batchId)
    {
        if (root == bytes32(0)) revert InvalidRoot();
        if (count == 0) revert EmptyBatch();
        uint256 n = modelHashes.length;
        if (n > MAX_MODELS_PER_BATCH) revert TooManyModels(n);
        for (uint256 i = 0; i < n; ++i) {
            if (!models.isActive(modelHashes[i])) revert ModelNotActive(modelHashes[i]);
        }

        batchId = _batches.length;
        _batches.push(
            Batch({
                root: root,
                count: count,
                blockNumber: uint64(block.number),
                gateway: msg.sender,
                modelHashes: modelHashes
            })
        );
        for (uint256 i = 0; i < n; ++i) {
            _batchesByModel[modelHashes[i]].push(batchId);
        }
        emit BatchCommitted(batchId, root, count, msg.sender, modelHashes);
    }

    /// @inheritdoc IVerdictRegistry
    function verifyLeaf(uint256 batchId, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        if (batchId >= _batches.length) revert UnknownBatch(batchId);
        return MerkleLeaf.verify(_batches[batchId].root, leaf, proof);
    }

    /// @inheritdoc IVerdictRegistry
    function verifyRoot(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external pure returns (bool) {
        return MerkleLeaf.verify(root, leaf, proof);
    }

    /// @inheritdoc IVerdictRegistry
    function staleByModel(bytes32 modelHash) external view returns (uint256[] memory) {
        if (models.statusOf(modelHash) != IModelRegistry.Status.REVOKED) return new uint256[](0);
        return _batchesByModel[modelHash];
    }

    /// @inheritdoc IVerdictRegistry
    function batchesByModel(bytes32 modelHash) external view returns (uint256[] memory) {
        return _batchesByModel[modelHash];
    }

    /// @inheritdoc IVerdictRegistry
    function batchCount() external view returns (uint256) {
        return _batches.length;
    }

    /// @inheritdoc IVerdictRegistry
    function getBatch(uint256 batchId) external view returns (Batch memory) {
        if (batchId >= _batches.length) revert UnknownBatch(batchId);
        return _batches[batchId];
    }
}
