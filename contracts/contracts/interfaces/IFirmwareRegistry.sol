// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IFirmwareRegistry
/// @notice releaseId → signed-manifest record; only ACTIVE publishers, monotonic versions per device model.
interface IFirmwareRegistry {
    /// @notice Everything the gateway cross-checks against the manifest fetched from IPFS.
    /// @dev `releaseId == manifestHash == keccak256(canonicalManifest)` (ADR-0001).
    struct Release {
        bytes32 publisherId;
        bytes32 deviceModelId;
        uint32 major;
        uint32 minor;
        uint32 patch;
        bytes32 manifestHash;
        bytes32 firmwareHash;
        bytes32 sbomHash;
        uint64 expiry;
        uint64 registeredAt;
        bool revoked;
        string deviceModel;
        string manifestCid;
        string firmwareCid;
        string sbomCid;
        bytes signature;
    }

    /// @notice Calldata bundle for {register}.
    struct RegisterInput {
        string deviceModel;
        uint32 major;
        uint32 minor;
        uint32 patch;
        bytes32 manifestHash;
        bytes32 firmwareHash;
        bytes32 sbomHash;
        uint64 expiry;
        string manifestCid;
        string firmwareCid;
        string sbomCid;
        bytes signature;
    }

    /// @notice Emitted for every accepted release; the gateway's event listener starts here.
    event NewRelease(
        bytes32 indexed releaseId,
        bytes32 indexed publisherId,
        bytes32 indexed deviceModelId,
        uint32 major,
        uint32 minor,
        uint32 patch,
        bytes32 manifestHash
    );
    /// @notice Emitted when a publisher (or the admin) withdraws a release.
    event ReleaseRevoked(bytes32 indexed releaseId, address indexed by);

    error NotActivePublisher(bytes32 publisherId);
    error NotPublisher(address caller);
    error ReleaseExists(bytes32 releaseId);
    error UnknownRelease(bytes32 releaseId);
    error AlreadyRevoked(bytes32 releaseId);
    error VersionNotMonotonic(uint96 packedVersion, uint96 lastPackedVersion);
    error InvalidSignatureLength(uint256 length);
    error InvalidManifestHash();
    error InvalidExpiry(uint64 expiry, uint64 nowTs);
    error NotAuthorised(address caller);

    /// @notice Register a release for the caller's ACTIVE publisher.
    /// @return releaseId The manifest hash.
    function register(RegisterInput calldata input) external returns (bytes32 releaseId);

    /// @notice Revoke a release (publisher owner or admin).
    function revoke(bytes32 releaseId) external;

    /// @notice Full record; `registeredAt == 0` if unknown.
    function get(bytes32 releaseId) external view returns (Release memory);

    /// @notice True iff the release exists and is revoked.
    function isRevoked(bytes32 releaseId) external view returns (bool);

    /// @notice Number of releases ever registered (for enumeration by the dashboard).
    function count() external view returns (uint256);

    /// @notice releaseId at index `i` in registration order.
    function releaseIdAt(uint256 i) external view returns (bytes32);

    /// @notice Highest packed version registered by a publisher for a device model.
    function lastVersion(bytes32 publisherId, bytes32 deviceModelId) external view returns (uint96);
}
