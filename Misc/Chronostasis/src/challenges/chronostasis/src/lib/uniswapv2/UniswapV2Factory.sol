// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UniswapV2Pair} from "./UniswapV2Pair.sol";
import {IUniswapV2Factory} from "../../interfaces/IUniswapV2Factory.sol";

/// @title UniswapV2Factory
/// @notice Deploys UniswapV2Pair contracts and maintains pair registry.
///         Uses CREATE2 for deterministic pair addresses.
contract UniswapV2Factory is IUniswapV2Factory {
    // ── Errors ───────────────────────────────────────────────────────────────
    error IdenticalAddresses();
    error ZeroAddress();
    error PairExists(address pair);
    error Forbidden();

    // ── State ────────────────────────────────────────────────────────────────
    address public feeTo;
    address public feeToSetter;

    mapping(address => mapping(address => address)) public getPair;
    address[] public allPairs;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _feeToSetter) {
        feeToSetter = _feeToSetter;
    }

    // ── View ──────────────────────────────────────────────────────────────────
    function allPairsLength() external view returns (uint256) {
        return allPairs.length;
    }

    /// @notice Compute deterministic pair address without deploying
    function pairFor(address tokenA, address tokenB) external view returns (address pair) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        pair = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            keccak256(abi.encodePacked(token0, token1)),
            keccak256(type(UniswapV2Pair).creationCode)
        )))));
    }

    // ── Create ────────────────────────────────────────────────────────────────
    function createPair(address tokenA, address tokenB) external returns (address pair) {
        if (tokenA == tokenB) revert IdenticalAddresses();
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        if (token0 == address(0)) revert ZeroAddress();
        if (getPair[token0][token1] != address(0)) revert PairExists(getPair[token0][token1]);

        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        UniswapV2Pair p = new UniswapV2Pair{salt: salt}();
        p.initialize(token0, token1);
        pair = address(p);

        getPair[token0][token1] = pair;
        getPair[token1][token0] = pair;
        allPairs.push(pair);
        emit PairCreated(token0, token1, pair, allPairs.length);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────
    function setFeeTo(address _feeTo) external {
        if (msg.sender != feeToSetter) revert Forbidden();
        feeTo = _feeTo;
    }

    function setFeeToSetter(address _feeToSetter) external {
        if (msg.sender != feeToSetter) revert Forbidden();
        feeToSetter = _feeToSetter;
    }
}
