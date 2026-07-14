// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./EntryPoint.sol";
import "./AccountFactory.sol";
import "./BaseAccount.sol";

contract Setup {
    EntryPoint public immutable entryPoint;
    AccountFactory public immutable factory;
    BaseAccount public immutable adminAccount;
    BaseAccount public immutable attackerAccount;

    address public immutable adminOwner;
    address public immutable attackerOwner;

    constructor(address _adminOwner, address _attackerOwner) payable {
        require(msg.value >= 10 ether, "Setup: need 10 ETH");
        require(_adminOwner != address(0), "Setup: zero admin");
        require(_attackerOwner != address(0), "Setup: zero attacker");

        factory = new AccountFactory();
        entryPoint = new EntryPoint(address(factory));

        adminOwner = _adminOwner;
        attackerOwner = _attackerOwner;

        adminAccount    = BaseAccount(payable(factory.createAccount(address(entryPoint), _adminOwner)));
        attackerAccount = BaseAccount(payable(factory.createAccount(address(entryPoint), _attackerOwner)));

        payable(address(adminAccount)).transfer(10 ether);
    }

    function isSolved() external view returns (bool) {
        return address(adminAccount).balance == 0;
    }
}
