// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IPublisherRegistry
/// @notice Publisher DID → Ed25519 public key, status, key rotation and reputation.
interface IPublisherRegistry {
    /// @notice Lifecycle of a publisher record.
    enum Status {
        NONE,
        ACTIVE,
        REVOKED
    }

    /// @notice On-chain record of one firmware publisher.
    /// @param did The publisher DID string, e.g. "did:verigate:acme".
    /// @param owner The EOA allowed to register releases and rotate the key.
    /// @param pubKey Raw 32-byte Ed25519 public key that signs manifests.
    /// @param status ACTIVE or REVOKED.
    /// @param reputationBp Reputation in basis points (0–10 000), maintained by gateways.
    /// @param keyVersion Incremented on every rotation (0 = registration key).
    /// @param registeredAt Block number of registration.
    /// @param revokedAt Block number of revocation (0 if active).
    struct Publisher {
        string did;
        address owner;
        bytes32 pubKey;
        Status status;
        uint16 reputationBp;
        uint32 keyVersion;
        uint64 registeredAt;
        uint64 revokedAt;
    }

    /// @notice Emitted when a new publisher self-registers.
    event PublisherRegistered(bytes32 indexed publisherId, string did, address indexed owner, bytes32 pubKey);
    /// @notice Emitted on key rotation; verifiers must use `newKey` for releases after this block.
    event KeyRotated(bytes32 indexed publisherId, bytes32 oldKey, bytes32 newKey, uint32 keyVersion);
    /// @notice Emitted when the admin revokes a publisher (stolen / retired key).
    event PublisherRevoked(bytes32 indexed publisherId, address indexed by);
    /// @notice Emitted whenever a gateway updates the reputation score.
    event ReputationUpdated(bytes32 indexed publisherId, uint16 oldBp, uint16 newBp, address indexed by);

    error PublisherExists(bytes32 publisherId);
    error UnknownPublisher(bytes32 publisherId);
    error NotActivePublisher(bytes32 publisherId);
    error AddressAlreadyPublisher(address owner);
    error InvalidKey();
    error InvalidDid();
    error InvalidReputation(uint16 bp);

    /// @notice Register `msg.sender` as the owner of `did` with signing key `pubKey`.
    /// @return publisherId keccak256(bytes(did)).
    function register(string calldata did, bytes32 pubKey) external returns (bytes32 publisherId);

    /// @notice Replace the signing key of the caller's publisher.
    function rotateKey(bytes32 newKey) external;

    /// @notice Admin: mark a publisher REVOKED and strip its PUBLISHER_ROLE.
    function revoke(bytes32 publisherId) external;

    /// @notice Gateway: set the reputation score in basis points.
    function setReputation(bytes32 publisherId, uint16 bp) external;

    /// @notice Full record; `status == NONE` if unknown.
    function get(bytes32 publisherId) external view returns (Publisher memory);

    /// @notice True iff the publisher exists and is ACTIVE.
    function isActive(bytes32 publisherId) external view returns (bool);

    /// @notice Publisher id owned by `owner`, or 0x0.
    function idOf(address owner) external view returns (bytes32);

    /// @notice Owner address of `publisherId`, or address(0).
    function ownerOf(bytes32 publisherId) external view returns (address);

    /// @notice Current Ed25519 public key, or 0x0.
    function publicKeyOf(bytes32 publisherId) external view returns (bytes32);

    /// @notice Reputation in basis points.
    function reputationOf(bytes32 publisherId) external view returns (uint16);

    /// @notice OpenZeppelin AccessControl role check (used by FirmwareRegistry).
    function hasRole(bytes32 role, address account) external view returns (bool);
}
