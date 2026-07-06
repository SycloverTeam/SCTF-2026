// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ReentrancyGuard
/// @notice Minimal reentrancy protection
abstract contract ReentrancyGuard {
    error Reentrancy();

    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED     = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        if (_status == _ENTERED) revert Reentrancy();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    function _reentrancyStatus() internal view returns (bool entered) {
        entered = (_status == _ENTERED);
    }
}
