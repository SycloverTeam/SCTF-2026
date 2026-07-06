// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "../lib/tokens/ERC20.sol";

/// @title TokenA
/// @notice Mintable ERC20 used as collateral base token (token "A" in A→B→C price path)
///         Minting is restricted to owner (setup only); no complex governance.
contract TokenA is ERC20 {
    // ── Errors ───────────────────────────────────────────────────────────────
    error OnlyOwner();
    error MintCapExceeded(uint256 requested, uint256 remaining);

    // ── Events ───────────────────────────────────────────────────────────────
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event MintCapUpdated(uint256 oldCap, uint256 newCap);

    // ── State ────────────────────────────────────────────────────────────────
    address public owner;
    uint256 public mintCap;
    uint256 public totalMinted;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _owner, uint256 _mintCap) ERC20("Token Alpha", "TKA", 18) {
        owner    = _owner;
        mintCap  = _mintCap;
    }

    // ── Modifiers ────────────────────────────────────────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ── Owner functions ───────────────────────────────────────────────────────
    function mint(address to, uint256 amount) external onlyOwner {
        uint256 remaining = mintCap - totalMinted;
        if (amount > remaining) revert MintCapExceeded(amount, remaining);
        totalMinted += amount;
        _mint(to, amount);
    }

    function setMintCap(uint256 newCap) external onlyOwner {
        emit MintCapUpdated(mintCap, newCap);
        mintCap = newCap;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
