// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "../lib/tokens/ERC20.sol";

/// @title TokenC
/// @notice Quote token representing a USD-pegged reference asset (6 decimals like USDC).
///         Used as denominator in B/C pool pricing.
contract TokenC is ERC20 {
    // ── Errors ───────────────────────────────────────────────────────────────
    error OnlyOwner();
    error OnlyMinter();
    error BlacklistViolation(address account);

    // ── Events ───────────────────────────────────────────────────────────────
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event MinterSet(address indexed minter, bool approved);
    event Blacklisted(address indexed account, bool status);

    // ── State ────────────────────────────────────────────────────────────────
    address public owner;
    mapping(address => bool) public isMinter;
    mapping(address => bool) public blacklisted;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _owner) ERC20("Token Charlie (USD)", "TKCU", 6) {
        owner = _owner;
    }

    // ── Modifiers ────────────────────────────────────────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier onlyMinter() {
        if (!isMinter[msg.sender]) revert OnlyMinter();
        _;
    }

    // ── Overrides ────────────────────────────────────────────────────────────
    function _transfer(address from, address to, uint256 amount) internal override {
        if (blacklisted[from]) revert BlacklistViolation(from);
        if (blacklisted[to])   revert BlacklistViolation(to);
        super._transfer(from, to, amount);
    }

    // ── Owner functions ───────────────────────────────────────────────────────
    function setMinter(address minter, bool approved) external onlyOwner {
        isMinter[minter] = approved;
        emit MinterSet(minter, approved);
    }

    function setBlacklist(address account, bool status) external onlyOwner {
        blacklisted[account] = status;
        emit Blacklisted(account, status);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ── Minter functions ──────────────────────────────────────────────────────
    function mint(address to, uint256 amount) external onlyMinter {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyMinter {
        _burn(from, amount);
    }
}
