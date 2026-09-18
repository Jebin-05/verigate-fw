// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Roles} from "./access/Roles.sol";
import {IPublisherRegistry} from "./interfaces/IPublisherRegistry.sol";

/// @title PublisherRegistry
/// @notice Publisher DID → Ed25519 key, status, rotation history (events) and reputation.
/// @dev Storage layout (append-only after v0.1.0; see ADR for any change):
///      slot 0..: AccessControl (roles mapping)
///      _publishers : mapping(bytes32 publisherId => Publisher)
///      _idOf       : mapping(address owner => bytes32 publisherId)
///      Registration is open (a publisher registers itself, Guide §2.5); the admin can revoke.
contract PublisherRegistry is AccessControl, IPublisherRegistry {
    /// @notice A new publisher starts neutral: 0.5 (5000 bp). Gateways move it up on receipts, down on rejects.
    uint16 public constant INITIAL_REPUTATION_BP = 5000;
    /// @notice Basis-point scale (1.0 == 10 000).
    uint16 public constant BASIS = 10_000;

    mapping(bytes32 publisherId => Publisher) private _publishers;
    mapping(address owner => bytes32 publisherId) private _idOf;

    /// @param admin Receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE; ADMIN_ROLE administers the other roles.
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.ADMIN_ROLE, admin);
        _setRoleAdmin(Roles.PUBLISHER_ROLE, Roles.ADMIN_ROLE);
        _setRoleAdmin(Roles.GATEWAY_ROLE, Roles.ADMIN_ROLE);
    }

    /// @inheritdoc IPublisherRegistry
    function register(string calldata did, bytes32 pubKey) external returns (bytes32 publisherId) {
        if (bytes(did).length < 7) revert InvalidDid(); // "did:x:y" is the shortest legal DID
        if (pubKey == bytes32(0)) revert InvalidKey();
        publisherId = keccak256(bytes(did));
        if (_publishers[publisherId].status != Status.NONE) revert PublisherExists(publisherId);
        if (_idOf[msg.sender] != bytes32(0)) revert AddressAlreadyPublisher(msg.sender);

        _publishers[publisherId] = Publisher({
            did: did,
            owner: msg.sender,
            pubKey: pubKey,
            status: Status.ACTIVE,
            reputationBp: INITIAL_REPUTATION_BP,
            keyVersion: 0,
            registeredAt: uint64(block.number),
            revokedAt: 0
        });
        _idOf[msg.sender] = publisherId;
        _grantRole(Roles.PUBLISHER_ROLE, msg.sender);
        emit PublisherRegistered(publisherId, did, msg.sender, pubKey);
    }

    /// @inheritdoc IPublisherRegistry
    function rotateKey(bytes32 newKey) external {
        if (newKey == bytes32(0)) revert InvalidKey();
        bytes32 publisherId = _idOf[msg.sender];
        if (publisherId == bytes32(0)) revert UnknownPublisher(publisherId);
        Publisher storage p = _publishers[publisherId];
        if (p.status != Status.ACTIVE) revert NotActivePublisher(publisherId);
        bytes32 oldKey = p.pubKey;
        p.pubKey = newKey;
        p.keyVersion += 1;
        emit KeyRotated(publisherId, oldKey, newKey, p.keyVersion);
    }

    /// @inheritdoc IPublisherRegistry
    function revoke(bytes32 publisherId) external onlyRole(Roles.ADMIN_ROLE) {
        Publisher storage p = _publishers[publisherId];
        if (p.status == Status.NONE) revert UnknownPublisher(publisherId);
        if (p.status != Status.ACTIVE) revert NotActivePublisher(publisherId);
        p.status = Status.REVOKED;
        p.revokedAt = uint64(block.number);
        _revokeRole(Roles.PUBLISHER_ROLE, p.owner);
        emit PublisherRevoked(publisherId, msg.sender);
    }

    /// @inheritdoc IPublisherRegistry
    function setReputation(bytes32 publisherId, uint16 bp) external onlyRole(Roles.GATEWAY_ROLE) {
        if (bp > BASIS) revert InvalidReputation(bp);
        Publisher storage p = _publishers[publisherId];
        if (p.status == Status.NONE) revert UnknownPublisher(publisherId);
        uint16 old = p.reputationBp;
        p.reputationBp = bp;
        emit ReputationUpdated(publisherId, old, bp, msg.sender);
    }

    /// @inheritdoc IPublisherRegistry
    function get(bytes32 publisherId) external view returns (Publisher memory) {
        return _publishers[publisherId];
    }

    /// @inheritdoc IPublisherRegistry
    function isActive(bytes32 publisherId) external view returns (bool) {
        // slither-disable-next-line incorrect-equality -- enum comparison, not a balance check
        return _publishers[publisherId].status == Status.ACTIVE;
    }

    /// @inheritdoc IPublisherRegistry
    function idOf(address owner) external view returns (bytes32) {
        return _idOf[owner];
    }

    /// @inheritdoc IPublisherRegistry
    function ownerOf(bytes32 publisherId) external view returns (address) {
        return _publishers[publisherId].owner;
    }

    /// @inheritdoc IPublisherRegistry
    function publicKeyOf(bytes32 publisherId) external view returns (bytes32) {
        return _publishers[publisherId].pubKey;
    }

    /// @inheritdoc IPublisherRegistry
    function reputationOf(bytes32 publisherId) external view returns (uint16) {
        return _publishers[publisherId].reputationBp;
    }

    /// @inheritdoc IPublisherRegistry
    function hasRole(bytes32 role, address account)
        public
        view
        override(AccessControl, IPublisherRegistry)
        returns (bool)
    {
        return AccessControl.hasRole(role, account);
    }
}
