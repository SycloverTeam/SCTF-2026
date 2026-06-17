// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../interfaces/IERC20.sol";

contract MockERC20 is IERC20 {
    string  public name;
    string  public symbol;
    uint8   public decimals;
    uint256 private _supply;
    address public minter;
    mapping(address => uint256)                     private _bal;
    mapping(address => mapping(address => uint256)) private _allow;

    constructor(string memory n, string memory s, uint8 d) {
        name = n; symbol = s; decimals = d;
        minter = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Not minter");
        _supply += amount; _bal[to] += amount;
    }

    function totalSupply() external view override returns (uint256) { return _supply; }
    function balanceOf(address a) external view override returns (uint256) { return _bal[a]; }

    function transfer(address to, uint256 amt) external override returns (bool) {
        require(_bal[msg.sender] >= amt, "ERC20: balance");
        _bal[msg.sender] -= amt; _bal[to] += amt; return true;
    }

    function allowance(address o, address s) external view override returns (uint256) {
        return _allow[o][s];
    }

    function approve(address s, uint256 amt) external override returns (bool) {
        _allow[msg.sender][s] = amt; return true;
    }

    function transferFrom(address from, address to, uint256 amt) external override returns (bool) {
        require(_bal[from]           >= amt, "ERC20: balance");
        require(_allow[from][msg.sender] >= amt, "ERC20: allowance");
        _bal[from] -= amt; _bal[to] += amt; _allow[from][msg.sender] -= amt;
        return true;
    }
}
