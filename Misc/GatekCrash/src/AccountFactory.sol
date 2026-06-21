// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./BaseAccount.sol";
import "./IEntryPoint.sol";

contract AccountFactory {
    event AccountCreated(address indexed account, address indexed owner);

    function createAccount(
        address entryPoint,
        address owner
    ) external returns (address account) {
        account = address(new BaseAccount(entryPoint, owner));
        IEntryPoint(entryPoint).registerSender(account);
        emit AccountCreated(account, owner);
    }
}