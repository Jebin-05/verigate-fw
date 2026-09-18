// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Roles} from "./access/Roles.sol";
import {IModelRegistry} from "./interfaces/IModelRegistry.sol";

/// @title ModelRegistry
/// @notice The AI model is a supply-chain artefact: its hash is registered, may be revoked, and names a successor.
/// @dev Storage layout (append-only after v0.1.0):
///      slot 0..: AccessControl
///      _models : mapping(bytes32 modelHash => Model)
///      modelHash = SHA-256 of the ONNX file bytes (models/MANIFEST.sha256).
contract ModelRegistry is AccessControl, IModelRegistry {
    mapping(bytes32 modelHash => Model) private _models;

    /// @param admin Receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE.
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.ADMIN_ROLE, admin);
    }

    /// @inheritdoc IModelRegistry
    function register(bytes32 modelHash, string calldata name) external onlyRole(Roles.ADMIN_ROLE) {
        if (modelHash == bytes32(0)) revert InvalidModelHash();
        if (_models[modelHash].status != Status.NONE) revert ModelExists(modelHash);
        _models[modelHash] = Model({
            name: name,
            status: Status.ACTIVE,
            successor: bytes32(0),
            registeredAt: uint64(block.number),
            revokedAt: 0
        });
        emit ModelRegistered(modelHash, name, msg.sender);
    }

    /// @inheritdoc IModelRegistry
    function revoke(bytes32 modelHash, bytes32 successor) external onlyRole(Roles.ADMIN_ROLE) {
        Model storage m = _models[modelHash];
        if (m.status == Status.NONE) revert UnknownModel(modelHash);
        if (m.status != Status.ACTIVE) revert ModelNotActive(modelHash);
        if (successor != bytes32(0)) {
            if (successor == modelHash || _models[successor].status != Status.ACTIVE) {
                revert InvalidSuccessor(successor);
            }
        }
        m.status = Status.REVOKED;
        m.successor = successor;
        m.revokedAt = uint64(block.number);
        emit ModelRevoked(modelHash, successor, m.revokedAt, msg.sender);
    }

    /// @inheritdoc IModelRegistry
    function get(bytes32 modelHash) external view returns (Model memory) {
        return _models[modelHash];
    }

    /// @inheritdoc IModelRegistry
    function statusOf(bytes32 modelHash) external view returns (Status) {
        return _models[modelHash].status;
    }

    /// @inheritdoc IModelRegistry
    function isActive(bytes32 modelHash) external view returns (bool) {
        // slither-disable-next-line incorrect-equality -- enum comparison, not a balance check
        return _models[modelHash].status == Status.ACTIVE;
    }

    /// @inheritdoc IModelRegistry
    function revokedAt(bytes32 modelHash) external view returns (uint64) {
        return _models[modelHash].revokedAt;
    }

    /// @inheritdoc IModelRegistry
    function successorOf(bytes32 modelHash) external view returns (bytes32) {
        return _models[modelHash].successor;
    }
}
