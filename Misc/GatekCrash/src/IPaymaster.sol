// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IAccount.sol";

interface IPaymaster {
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData);

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external;
}

enum PostOpMode {
    opSucceeded,
    opReverted, 
    postOpReverted
}