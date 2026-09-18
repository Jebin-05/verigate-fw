// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title IPolicyContract
/// @notice Weights and thresholds of the policy engine (Guide §7); every change is a transaction.
interface IPolicyContract {
    /// @notice R = wSbom·r_sbom + wImg·r_img + wRep·(1 − reputation); all values in basis points.
    /// @param wSbom Weight of the SBOM risk score.
    /// @param wImg Weight of the image anomaly score.
    /// @param wRep Weight of (1 − publisher reputation).
    /// @param tauApprove R below this → APPROVE.
    /// @param tauReject R at or above this → REJECT; in between → DEFER.
    /// @param version Incremented on every change (0 never exists).
    /// @param changedBy Address that set this policy.
    /// @param changedAt Block number of the change.
    struct Policy {
        uint16 wSbom;
        uint16 wImg;
        uint16 wRep;
        uint16 tauApprove;
        uint16 tauReject;
        uint32 version;
        address changedBy;
        uint64 changedAt;
    }

    /// @notice Emitted on every change with the full old and new policy (audit log).
    event PolicyChanged(uint32 indexed version, Policy oldPolicy, Policy newPolicy, address indexed changedBy);

    error WeightsMustSumToBasis(uint256 sum);
    error ThresholdsOutOfOrder(uint16 tauApprove, uint16 tauReject);
    error ThresholdOutOfRange(uint16 tau);

    /// @notice Admin: replace the whole policy atomically.
    function setPolicy(uint16 wSbom, uint16 wImg, uint16 wRep, uint16 tauApprove, uint16 tauReject) external;

    /// @notice The policy in force.
    function current() external view returns (Policy memory);

    /// @notice Current policy version.
    function version() external view returns (uint32);
}
