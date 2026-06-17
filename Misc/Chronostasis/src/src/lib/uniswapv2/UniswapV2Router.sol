// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUniswapV2Factory} from "../../interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Pair} from "../../interfaces/IUniswapV2Pair.sol";
import {SafeTransfer} from "../SafeTransfer.sol";

/// @title UniswapV2Router
/// @notice Simplified UniswapV2 router supporting single-hop and multi-hop swaps.
///         Key functions: getAmountOut, getAmountsOut (multi-hop), swapExactTokensForTokens.
///         NOTE: getAmountsOut performs sequential integer divisions which accumulate
///         Integer division may cause minor precision loss per hop.
contract UniswapV2Router {
    using SafeTransfer for address;

    // ── Errors ───────────────────────────────────────────────────────────────
    error Expired(uint256 deadline, uint256 blockTimestamp);
    error InsufficientOutputAmount(uint256 amountOut, uint256 amountOutMin);
    error InsufficientInputAmount();
    error InsufficientLiquidity();
    error InvalidPath();
    error ZeroAddress();

    // ── Events ───────────────────────────────────────────────────────────────
    event SwapExecuted(
        address indexed sender,
        address[] path,
        uint256[] amounts,
        address indexed to
    );
    event LiquidityAdded(
        address indexed sender,
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB,
        uint256 liquidity,
        address indexed to
    );
    event LiquidityRemoved(
        address indexed sender,
        address tokenA,
        address tokenB,
        uint256 amountA,
        uint256 amountB,
        address indexed to
    );

    // ── State ────────────────────────────────────────────────────────────────
    address public immutable factory;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _factory) {
        factory = _factory;
    }

    // ── Modifiers ────────────────────────────────────────────────────────────
    modifier ensure(uint256 deadline) {
        if (block.timestamp > deadline) revert Expired(deadline, block.timestamp);
        _;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────
    function _pairFor(address tokenA, address tokenB) internal view returns (address pair) {
        pair = IUniswapV2Factory(factory).getPair(tokenA, tokenB);
        if (pair == address(0)) revert ZeroAddress();
    }

    function _getReserves(address tokenA, address tokenB)
        internal
        view
        returns (uint256 reserveA, uint256 reserveB)
    {
        address pair = _pairFor(tokenA, tokenB);
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
        (reserveA, reserveB) = tokenA < tokenB ? (uint256(r0), uint256(r1)) : (uint256(r1), uint256(r0));
    }

    // ── Pure: amount calculations ─────────────────────────────────────────────

    /// @notice Given exact input, compute output (0.3% fee deducted)
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public
        pure
        returns (uint256 amountOut)
    {
        if (amountIn == 0) revert InsufficientInputAmount();
        if (reserveIn == 0 || reserveOut == 0) revert InsufficientLiquidity();
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator       = amountInWithFee * reserveOut;
        uint256 denominator     = reserveIn * 1000 + amountInWithFee;
        amountOut = numerator / denominator;
    }

    /// @notice Given exact output, compute required input
    function getAmountIn(uint256 amountOut, uint256 reserveIn, uint256 reserveOut)
        public
        pure
        returns (uint256 amountIn)
    {
        if (amountOut == 0) revert InsufficientOutputAmount(amountOut, 1);
        if (reserveIn == 0 || reserveOut == 0) revert InsufficientLiquidity();
        uint256 numerator   = reserveIn * amountOut * 1000;
        uint256 denominator = (reserveOut - amountOut) * 997;
        amountIn = numerator / denominator + 1;
    }

    /// @notice Multi-hop amount computation
    function getAmountsOut(uint256 amountIn, address[] memory path)
        public
        view
        returns (uint256[] memory amounts)
    {
        if (path.length < 2) revert InvalidPath();
        amounts = new uint256[](path.length);
        amounts[0] = amountIn;
        for (uint256 i; i < path.length - 1; i++) {
            (uint256 reserveIn, uint256 reserveOut) = _getReserves(path[i], path[i + 1]);
            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);
        }
    }

    function getAmountsIn(uint256 amountOut, address[] memory path)
        public
        view
        returns (uint256[] memory amounts)
    {
        if (path.length < 2) revert InvalidPath();
        amounts = new uint256[](path.length);
        amounts[amounts.length - 1] = amountOut;
        for (uint256 i = path.length - 1; i > 0; i--) {
            (uint256 reserveIn, uint256 reserveOut) = _getReserves(path[i - 1], path[i]);
            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);
        }
    }

    // ── Swap ─────────────────────────────────────────────────────────────────

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256[] memory amounts) {
        amounts = getAmountsOut(amountIn, path);
        if (amounts[amounts.length - 1] < amountOutMin)
            revert InsufficientOutputAmount(amounts[amounts.length - 1], amountOutMin);
        path[0].safeTransferFrom(msg.sender, _pairFor(path[0], path[1]), amounts[0]);
        _swap(amounts, path, to);
        emit SwapExecuted(msg.sender, path, amounts, to);
    }

    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256[] memory amounts) {
        amounts = getAmountsIn(amountOut, path);
        if (amounts[0] > amountInMax)
            revert InsufficientInputAmount();
        path[0].safeTransferFrom(msg.sender, _pairFor(path[0], path[1]), amounts[0]);
        _swap(amounts, path, to);
        emit SwapExecuted(msg.sender, path, amounts, to);
    }

    function _swap(uint256[] memory amounts, address[] memory path, address _to) internal {
        for (uint256 i; i < path.length - 1; i++) {
            (address input, address output) = (path[i], path[i + 1]);
            address pair  = _pairFor(input, output);
            uint256 amountOut = amounts[i + 1];
            (uint256 amount0Out, uint256 amount1Out) =
                input < output ? (uint256(0), amountOut) : (amountOut, uint256(0));
            address recipient = i < path.length - 2 ? _pairFor(output, path[i + 2]) : _to;
            IUniswapV2Pair(pair).swap(amount0Out, amount1Out, recipient, new bytes(0));
        }
    }

    // ── Liquidity ─────────────────────────────────────────────────────────────

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256 amountA, uint256 amountB, uint256 liquidity) {
        address pair = IUniswapV2Factory(factory).getPair(tokenA, tokenB);
        if (pair == address(0)) {
            pair = IUniswapV2Factory(factory).createPair(tokenA, tokenB);
        }

        (uint256 reserveA, uint256 reserveB) = _getReservesOrZero(tokenA, tokenB);

        if (reserveA == 0 && reserveB == 0) {
            (amountA, amountB) = (amountADesired, amountBDesired);
        } else {
            uint256 amountBOptimal = amountADesired * reserveB / reserveA;
            if (amountBOptimal <= amountBDesired) {
                require(amountBOptimal >= amountBMin, "Router: INSUFFICIENT_B_AMOUNT");
                (amountA, amountB) = (amountADesired, amountBOptimal);
            } else {
                uint256 amountAOptimal = amountBDesired * reserveA / reserveB;
                require(amountAOptimal >= amountAMin, "Router: INSUFFICIENT_A_AMOUNT");
                (amountA, amountB) = (amountAOptimal, amountBDesired);
            }
        }

        tokenA.safeTransferFrom(msg.sender, pair, amountA);
        tokenB.safeTransferFrom(msg.sender, pair, amountB);
        liquidity = IUniswapV2Pair(pair).mint(to);
        emit LiquidityAdded(msg.sender, tokenA, tokenB, amountA, amountB, liquidity, to);
    }

    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external ensure(deadline) returns (uint256 amountA, uint256 amountB) {
        address pair = _pairFor(tokenA, tokenB);
        IUniswapV2Pair(pair).transferFrom(msg.sender, pair, liquidity);
        (uint256 amount0, uint256 amount1) = IUniswapV2Pair(pair).burn(to);
        (amountA, amountB) = tokenA < tokenB ? (amount0, amount1) : (amount1, amount0);
        require(amountA >= amountAMin, "Router: INSUFFICIENT_A_AMOUNT");
        require(amountB >= amountBMin, "Router: INSUFFICIENT_B_AMOUNT");
        emit LiquidityRemoved(msg.sender, tokenA, tokenB, amountA, amountB, to);
    }

    function _getReservesOrZero(address tokenA, address tokenB)
        internal
        view
        returns (uint256 reserveA, uint256 reserveB)
    {
        address pair = IUniswapV2Factory(factory).getPair(tokenA, tokenB);
        if (pair == address(0)) return (0, 0);
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
        (reserveA, reserveB) = tokenA < tokenB ? (uint256(r0), uint256(r1)) : (uint256(r1), uint256(r0));
    }
}
