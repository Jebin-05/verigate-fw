// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Roles} from "./access/Roles.sol";
import {IFirmwareRegistry} from "./interfaces/IFirmwareRegistry.sol";
import {IPublisherRegistry} from "./interfaces/IPublisherRegistry.sol";

/// @title FirmwareRegistry
/// @notice Signed-manifest records per release; ACTIVE publishers only; strictly increasing versions per device model.
/// @dev Storage layout (append-only after v0.1.0):
///      slot 0..: AccessControl
///      publishers   : immutable (no slot)
///      _releases    : mapping(bytes32 releaseId => Release)
///      _lastVersion : mapping(bytes32 publisherId => mapping(bytes32 deviceModelId => uint96 packed))
///      _releaseIds  : bytes32[] (registration order, for enumeration)
///      Version is packed as (major << 64 | minor << 32 | patch) so a single uint96 compare is monotonic.
contract FirmwareRegistry is AccessControl, IFirmwareRegistry {
    /// @notice Registry consulted for ACTIVE status, ownership and PUBLISHER_ROLE.
    IPublisherRegistry public immutable publishers;
    /// @notice Ed25519 signatures are exactly 64 bytes.
    uint256 public constant SIGNATURE_LENGTH = 64;

    mapping(bytes32 releaseId => Release) private _releases;
    mapping(bytes32 publisherId => mapping(bytes32 deviceModelId => uint96 packed)) private _lastVersion;
    bytes32[] private _releaseIds;

    /// @param admin Receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE (may revoke any release).
    /// @param publishers_ The deployed PublisherRegistry.
    constructor(address admin, IPublisherRegistry publishers_) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.ADMIN_ROLE, admin);
        publishers = publishers_;
    }

    /// @inheritdoc IFirmwareRegistry
    function register(RegisterInput calldata input) external returns (bytes32 releaseId) {
        // --- checks
        bytes32 publisherId = publishers.idOf(msg.sender);
        if (publisherId == bytes32(0) || !publishers.hasRole(Roles.PUBLISHER_ROLE, msg.sender)) {
            revert NotPublisher(msg.sender);
        }
        if (!publishers.isActive(publisherId)) revert NotActivePublisher(publisherId);
        if (input.manifestHash == bytes32(0)) revert InvalidManifestHash();
        if (input.signature.length != SIGNATURE_LENGTH) revert InvalidSignatureLength(input.signature.length);
        if (input.expiry <= block.timestamp) revert InvalidExpiry(input.expiry, uint64(block.timestamp));

        releaseId = input.manifestHash;
        if (_releases[releaseId].registeredAt != 0) revert ReleaseExists(releaseId);

        bytes32 deviceModelId = keccak256(bytes(input.deviceModel));
        uint96 packed = packVersion(input.major, input.minor, input.patch);
        uint96 last = _lastVersion[publisherId][deviceModelId];
        if (packed <= last) revert VersionNotMonotonic(packed, last);

        // --- effects
        _lastVersion[publisherId][deviceModelId] = packed;
        _releases[releaseId] = Release({
            publisherId: publisherId,
            deviceModelId: deviceModelId,
            major: input.major,
            minor: input.minor,
            patch: input.patch,
            manifestHash: input.manifestHash,
            firmwareHash: input.firmwareHash,
            sbomHash: input.sbomHash,
            expiry: input.expiry,
            registeredAt: uint64(block.number),
            revoked: false,
            deviceModel: input.deviceModel,
            manifestCid: input.manifestCid,
            firmwareCid: input.firmwareCid,
            sbomCid: input.sbomCid,
            signature: input.signature
        });
        _releaseIds.push(releaseId);
        emit NewRelease(
            releaseId, publisherId, deviceModelId, input.major, input.minor, input.patch, input.manifestHash
        );
    }

    /// @inheritdoc IFirmwareRegistry
    function revoke(bytes32 releaseId) external {
        Release storage r = _releases[releaseId];
        if (r.registeredAt == 0) revert UnknownRelease(releaseId);
        if (r.revoked) revert AlreadyRevoked(releaseId);
        bool isOwner = publishers.ownerOf(r.publisherId) == msg.sender;
        if (!isOwner && !hasRole(Roles.ADMIN_ROLE, msg.sender)) revert NotAuthorised(msg.sender);
        r.revoked = true;
        emit ReleaseRevoked(releaseId, msg.sender);
    }

    /// @inheritdoc IFirmwareRegistry
    function get(bytes32 releaseId) external view returns (Release memory) {
        return _releases[releaseId];
    }

    /// @inheritdoc IFirmwareRegistry
    function isRevoked(bytes32 releaseId) external view returns (bool) {
        return _releases[releaseId].revoked;
    }

    /// @inheritdoc IFirmwareRegistry
    function count() external view returns (uint256) {
        return _releaseIds.length;
    }

    /// @inheritdoc IFirmwareRegistry
    function releaseIdAt(uint256 i) external view returns (bytes32) {
        return _releaseIds[i];
    }

    /// @inheritdoc IFirmwareRegistry
    function lastVersion(bytes32 publisherId, bytes32 deviceModelId) external view returns (uint96) {
        return _lastVersion[publisherId][deviceModelId];
    }

    /// @notice Pack a SemVer triple so that numeric comparison equals lexicographic comparison.
    function packVersion(uint32 major, uint32 minor, uint32 patch) public pure returns (uint96) {
        return (uint96(major) << 64) | (uint96(minor) << 32) | uint96(patch);
    }
}
