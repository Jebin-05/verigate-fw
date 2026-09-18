// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title Roles
/// @notice Role identifiers shared by every VeriGate-FW registry (OpenZeppelin AccessControl).
/// @dev `DEFAULT_ADMIN_ROLE` (0x00) administers all three; `ADMIN_ROLE` is the operational admin.
library Roles {
    /// @notice Operator of the gateways: registers/revokes models, sets policy, revokes publishers.
    bytes32 internal constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    /// @notice Granted to a publisher's address by `PublisherRegistry.register`; lost on revocation.
    bytes32 internal constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
    /// @notice A gateway verifier: commits verdict batches and updates publisher reputation.
    bytes32 internal constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");
}
