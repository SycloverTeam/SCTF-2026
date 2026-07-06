// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "../../interfaces/IERC20.sol";

/// @title ERC20
/// @notice Standard ERC20 implementation
contract ERC20 is IERC20 {
    // ── Errors ───────────────────────────────────────────────────────────────
    error ERC20_InsufficientBalance(address account, uint256 balance, uint256 needed);
    error ERC20_InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
    error ERC20_InvalidSender(address sender);
    error ERC20_InvalidReceiver(address receiver);
    error ERC20_InvalidApprover(address approver);
    error ERC20_InvalidSpender(address spender);

    // ── State ────────────────────────────────────────────────────────────────
    string  private _name;
    string  private _symbol;
    uint8   private _decimals;
    uint256 private _totalSupply;

    mapping(address => uint256)                     private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        _name     = name_;
        _symbol   = symbol_;
        _decimals = decimals_;
    }

    // ── View ─────────────────────────────────────────────────────────────────
    function name()        public view virtual returns (string memory) { return _name; }
    function symbol()      public view virtual returns (string memory) { return _symbol; }
    function decimals()    public view virtual returns (uint8)         { return _decimals; }
    function totalSupply() public view virtual returns (uint256)       { return _totalSupply; }

    function balanceOf(address account) public view virtual returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return _allowances[owner][spender];
    }

    // ── External ─────────────────────────────────────────────────────────────
    function transfer(address to, uint256 amount) public virtual returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, amount);
        return true;
    }

    // ── Internal ──────────────────────────────────────────────────────────────
    function _transfer(address from, address to, uint256 amount) internal virtual {
        if (from == address(0)) revert ERC20_InvalidSender(from);
        if (to   == address(0)) revert ERC20_InvalidReceiver(to);

        uint256 bal = _balances[from];
        if (bal < amount) revert ERC20_InsufficientBalance(from, bal, amount);
        unchecked { _balances[from] = bal - amount; }
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal virtual {
        if (to == address(0)) revert ERC20_InvalidReceiver(to);
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal virtual {
        if (from == address(0)) revert ERC20_InvalidSender(from);
        uint256 bal = _balances[from];
        if (bal < amount) revert ERC20_InsufficientBalance(from, bal, amount);
        unchecked {
            _balances[from] = bal - amount;
            _totalSupply   -= amount;
        }
        emit Transfer(from, address(0), amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        if (owner   == address(0)) revert ERC20_InvalidApprover(owner);
        if (spender == address(0)) revert ERC20_InvalidSpender(spender);
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {
        uint256 current = _allowances[owner][spender];
        if (current != type(uint256).max) {
            if (current < amount) revert ERC20_InsufficientAllowance(spender, current, amount);
            unchecked { _allowances[owner][spender] = current - amount; }
        }
    }
}
