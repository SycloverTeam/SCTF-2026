// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IEntryPoint {
    function currentOpSender() external view returns (address);
    function currentOpHash() external view returns (bytes32);
    function preApprovedSenders(address sender) external view returns (bool);
    function addToPreApproved(address sender) external;
    function adminUpdateModule(address account, address newModule) external;
    function registerSender(address sender) external;
    function registeredSenders(address sender) external view returns (bool);
}