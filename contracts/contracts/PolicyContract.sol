// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Roles} from "./access/Roles.sol";
import {IPolicyContract} from "./interfaces/IPolicyContract.sol";

/// @title PolicyContract
/// @notice Policy on-chain, decision off-chain (Guide §8, Novelty 3): weights and thresholds in basis points.
/// @dev Storage layout (append-only after v0.1.0):
///      slot 0..: AccessControl
///      _policy : Policy (single struct; history is the PolicyChanged event stream)
contract PolicyContract is AccessControl, IPolicyContract {
    /// @notice Basis-point scale (1.0 == 10 000).
    uint16 public constant BASIS = 10_000;

    Policy private _policy;

    /// @param admin Receives DEFAULT_ADMIN_ROLE and ADMIN_ROLE.
    /// @param wSbom Initial SBOM weight (bp).
    /// @param wImg Initial image weight (bp).
    /// @param wRep Initial reputation weight (bp).
    /// @param tauApprove Initial approve threshold (bp).
    /// @param tauReject Initial reject threshold (bp).
    constructor(address admin, uint16 wSbom, uint16 wImg, uint16 wRep, uint16 tauApprove, uint16 tauReject) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(Roles.ADMIN_ROLE, admin);
        _set(wSbom, wImg, wRep, tauApprove, tauReject);
    }

    /// @inheritdoc IPolicyContract
    function setPolicy(uint16 wSbom, uint16 wImg, uint16 wRep, uint16 tauApprove, uint16 tauReject)
        external
        onlyRole(Roles.ADMIN_ROLE)
    {
        _set(wSbom, wImg, wRep, tauApprove, tauReject);
    }

    /// @inheritdoc IPolicyContract
    function current() external view returns (Policy memory) {
        return _policy;
    }

    /// @inheritdoc IPolicyContract
    function version() external view returns (uint32) {
        return _policy.version;
    }

    function _set(uint16 wSbom, uint16 wImg, uint16 wRep, uint16 tauApprove, uint16 tauReject) private {
        uint256 sum = uint256(wSbom) + uint256(wImg) + uint256(wRep);
        if (sum != BASIS) revert WeightsMustSumToBasis(sum);
        if (tauReject > BASIS) revert ThresholdOutOfRange(tauReject);
        if (tauApprove >= tauReject) revert ThresholdsOutOfOrder(tauApprove, tauReject);

        Policy memory old = _policy;
        Policy memory next = Policy({
            wSbom: wSbom,
            wImg: wImg,
            wRep: wRep,
            tauApprove: tauApprove,
            tauReject: tauReject,
            version: old.version + 1,
            changedBy: msg.sender,
            changedAt: uint64(block.number)
        });
        _policy = next;
        emit PolicyChanged(next.version, old, next, msg.sender);
    }
}
