// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "../lib/tokens/ERC20.sol";

/// @title TokenB
/// @notice Bridge token used in both A/B and B/C UniswapV2 pools.
contract TokenB is ERC20 {
    // ── Errors ───────────────────────────────────────────────────────────────
    error OnlyOwner();
    error OnlyMinter();

    // ── Events ───────────────────────────────────────────────────────────────
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event MinterSet(address indexed minter, bool approved);

    // ── State ────────────────────────────────────────────────────────────────
    address public owner;
    mapping(address => bool) public isMinter;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _owner) ERC20("Token Beta", "TKB", 18) {
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

    // ── Owner functions ───────────────────────────────────────────────────────
    function setMinter(address minter, bool approved) external onlyOwner {
        isMinter[minter] = approved;
        emit MinterSet(minter, approved);
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
