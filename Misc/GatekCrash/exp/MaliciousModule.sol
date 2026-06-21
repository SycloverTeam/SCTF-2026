// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MaliciousModule {
    function preValidate(address, bytes32) external {
        assembly {
            sstore(0, 0)
        }
    }
}