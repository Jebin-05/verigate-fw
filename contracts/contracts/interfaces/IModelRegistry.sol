// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IModelRegistry
/// @notice AI model hash → status, successor, revocation block (Guide §8, Novelty 2).
interface IModelRegistry {
    /// @notice Lifecycle of a model hash.
    enum Status {
        NONE,
        ACTIVE,
        REVOKED
    }

    /// @notice One registered model version.
    /// @param name Human-readable name, e.g. "image_anomaly_v3".
    /// @param status ACTIVE or REVOKED.
    /// @param successor Model hash that replaces this one after revocation (0x0 if none).
    /// @param registeredAt Block number of registration.
    /// @param revokedAt Block number of revocation (0 if active).
    struct Model {
        string name;
        Status status;
        bytes32 successor;
        uint64 registeredAt;
        uint64 revokedAt;
    }

    /// @notice Emitted when the admin registers a model hash (SHA-256 of the ONNX bytes).
    event ModelRegistered(bytes32 indexed modelHash, string name, address indexed by);
    /// @notice Emitted on revocation; every verdict batch that used `modelHash` is now STALE.
    event ModelRevoked(bytes32 indexed modelHash, bytes32 indexed successor, uint64 revokedAt, address indexed by);

    error ModelExists(bytes32 modelHash);
    error UnknownModel(bytes32 modelHash);
    error ModelNotActive(bytes32 modelHash);
    error InvalidSuccessor(bytes32 successor);
    error InvalidModelHash();

    /// @notice Admin: register a new model hash.
    function register(bytes32 modelHash, string calldata name) external;

    /// @notice Admin: revoke a model and optionally name its ACTIVE successor.
    function revoke(bytes32 modelHash, bytes32 successor) external;

    /// @notice Full record; `status == NONE` if unknown.
    function get(bytes32 modelHash) external view returns (Model memory);

    /// @notice Status of a model hash.
    function statusOf(bytes32 modelHash) external view returns (Status);

    /// @notice True iff registered and not revoked.
    function isActive(bytes32 modelHash) external view returns (bool);

    /// @notice Block number of revocation, 0 if not revoked.
    function revokedAt(bytes32 modelHash) external view returns (uint64);

    /// @notice Successor hash, 0x0 if none.
    function successorOf(bytes32 modelHash) external view returns (bytes32);
}
