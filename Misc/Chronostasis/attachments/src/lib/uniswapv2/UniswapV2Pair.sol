// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UniswapV2ERC20} from "./UniswapV2ERC20.sol";
import {IUniswapV2Pair} from "../../interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Factory} from "../../interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Callee} from "../../interfaces/IUniswapV2Callee.sol";
import {FixedPointMath} from "../FixedPointMath.sol";
import {SafeTransfer} from "../SafeTransfer.sol";

/// @title UniswapV2Pair
/// @notice Full UniswapV2 pair with TWAP price accumulators (price0CumulativeLast,
///         price1CumulativeLast), flash swaps, mint/burn fees, and skim/sync.
///         THIS IS THE CANONICAL CTF TARGET — price accumulators accumulate
///         UQ112x112 prices weighted by seconds elapsed.
contract UniswapV2Pair is UniswapV2ERC20, IUniswapV2Pair {
    using FixedPointMath for uint112;
    using SafeTransfer  for address;

    // ── Constants ────────────────────────────────────────────────────────────
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    bytes4  private constant _SELECTOR        = bytes4(keccak256("transfer(address,uint256)"));

    // ── State ────────────────────────────────────────────────────────────────
    address public factory;
    address public token0;
    address public token1;

    // Packed slot: reserve0 (112 bits) + reserve1 (112 bits) + blockTimestampLast (32 bits)
    uint112 private _reserve0;
    uint112 private _reserve1;
    uint32  private _blockTimestampLast;

    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint256 public kLast; // reserve0 * reserve1 after most recent liquidity event

    uint256 private _unlocked = 1;

    // ── Modifiers ────────────────────────────────────────────────────────────
    modifier lock() {
        require(_unlocked == 1, "UniswapV2: LOCKED");
        _unlocked = 0;
        _;
        _unlocked = 1;
    }

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor() {
        factory = msg.sender;
    }

    // ── ERC20 overrides (needed because IUniswapV2Pair also declares these) ──
    function totalSupply() public view override(UniswapV2ERC20, IUniswapV2Pair) returns (uint256) {
        return super.totalSupply();
    }

    function balanceOf(address account) public view override(UniswapV2ERC20, IUniswapV2Pair) returns (uint256) {
        return super.balanceOf(account);
    }

    function approve(address spender, uint256 value) public override(UniswapV2ERC20, IUniswapV2Pair) returns (bool) {
        return super.approve(spender, value);
    }

    function transferFrom(address from, address to, uint256 value) public override(UniswapV2ERC20, IUniswapV2Pair) returns (bool) {
        return super.transferFrom(from, to, value);
    }

    // ── IUniswapV2Pair: Initialize ────────────────────────────────────────────
    function initialize(address _token0, address _token1) external {
        require(msg.sender == factory, "UniswapV2: FORBIDDEN");
        token0 = _token0;
        token1 = _token1;
    }

    // ── View ──────────────────────────────────────────────────────────────────
    function getReserves()
        public
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)
    {
        reserve0          = _reserve0;
        reserve1          = _reserve1;
        blockTimestampLast = _blockTimestampLast;
    }

    // ── Internal: cumulative price update ────────────────────────────────────
    /// @dev Called at the start of each mutating function.
    ///      Accumulates price * elapsed_seconds into the cumulative accumulators.
    ///      Accumulator overflow is handled via modular arithmetic.
    function _update(uint256 balance0, uint256 balance1, uint112 reserve0, uint112 reserve1) private {
        require(balance0 <= type(uint112).max && balance1 <= type(uint112).max, "UniswapV2: OVERFLOW");

        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed;
        unchecked {
            timeElapsed = blockTimestamp - _blockTimestampLast; // overflow handled via unchecked
        }

        if (timeElapsed > 0 && reserve0 != 0 && reserve1 != 0) {
            // price0 = reserve1/reserve0 (UQ112x112)
            // accumulator wraps — modular arithmetic
            unchecked {
                price0CumulativeLast += uint256(FixedPointMath.fraction(reserve1, reserve0)) * timeElapsed;
                price1CumulativeLast += uint256(FixedPointMath.fraction(reserve0, reserve1)) * timeElapsed;
            }
        }

        _reserve0              = uint112(balance0);
        _reserve1              = uint112(balance1);
        _blockTimestampLast    = blockTimestamp;
        emit Sync(uint112(balance0), uint112(balance1));
    }

    // ── Internal: mint fee ────────────────────────────────────────────────────
    function _mintFee(uint112 reserve0, uint112 reserve1) private returns (bool feeOn) {
        address feeTo = IUniswapV2Factory(factory).feeTo();
        feeOn = feeTo != address(0);
        uint256 _kLast = kLast;
        if (feeOn) {
            if (_kLast != 0) {
                uint256 rootK     = FixedPointMath.sqrt(uint256(reserve0) * reserve1);
                uint256 rootKLast = FixedPointMath.sqrt(_kLast);
                if (rootK > rootKLast) {
                    uint256 numerator   = totalSupply() * (rootK - rootKLast);
                    uint256 denominator = rootK * 5 + rootKLast;
                    uint256 liquidity   = numerator / denominator;
                    if (liquidity > 0) _mint(feeTo, liquidity);
                }
            }
        } else if (_kLast != 0) {
            kLast = 0;
        }
    }

    // ── Mint (add liquidity) ──────────────────────────────────────────────────
    function mint(address to) external lock returns (uint256 liquidity) {
        (uint112 reserve0, uint112 reserve1,) = getReserves();
        uint256 balance0 = SafeTransfer.balanceOf(token0, address(this));
        uint256 balance1 = SafeTransfer.balanceOf(token1, address(this));
        uint256 amount0  = balance0 - reserve0;
        uint256 amount1  = balance1 - reserve1;

        bool feeOn = _mintFee(reserve0, reserve1);
        uint256 _totalSupply = totalSupply();

        if (_totalSupply == 0) {
            liquidity = FixedPointMath.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            _mint(address(0), MINIMUM_LIQUIDITY); // permanently lock first MINIMUM_LIQUIDITY tokens
        } else {
            liquidity = FixedPointMath.min(
                amount0 * _totalSupply / reserve0,
                amount1 * _totalSupply / reserve1
            );
        }
        require(liquidity > 0, "UniswapV2: INSUFFICIENT_LIQUIDITY_MINTED");
        _mint(to, liquidity);

        _update(balance0, balance1, reserve0, reserve1);
        if (feeOn) kLast = uint256(_reserve0) * _reserve1;
        emit Mint(msg.sender, amount0, amount1);
    }

    // ── Burn (remove liquidity) ───────────────────────────────────────────────
    function burn(address to) external lock returns (uint256 amount0, uint256 amount1) {
        (uint112 reserve0, uint112 reserve1,) = getReserves();
        address _token0 = token0;
        address _token1 = token1;
        uint256 balance0  = SafeTransfer.balanceOf(_token0, address(this));
        uint256 balance1  = SafeTransfer.balanceOf(_token1, address(this));
        uint256 liquidity = balanceOf(address(this));

        bool feeOn   = _mintFee(reserve0, reserve1);
        uint256 _ts  = totalSupply();
        amount0 = liquidity * balance0 / _ts;
        amount1 = liquidity * balance1 / _ts;
        require(amount0 > 0 && amount1 > 0, "UniswapV2: INSUFFICIENT_LIQUIDITY_BURNED");
        _burn(address(this), liquidity);
        _token0.safeTransfer(to, amount0);
        _token1.safeTransfer(to, amount1);
        balance0 = SafeTransfer.balanceOf(_token0, address(this));
        balance1 = SafeTransfer.balanceOf(_token1, address(this));

        _update(balance0, balance1, reserve0, reserve1);
        if (feeOn) kLast = uint256(_reserve0) * _reserve1;
        emit Burn(msg.sender, amount0, amount1, to);
    }

    // ── Swap ──────────────────────────────────────────────────────────────────
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external lock {
        require(amount0Out > 0 || amount1Out > 0, "UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT");
        (uint112 reserve0, uint112 reserve1,) = getReserves();
        require(amount0Out < reserve0 && amount1Out < reserve1, "UniswapV2: INSUFFICIENT_LIQUIDITY");

        uint256 balance0;
        uint256 balance1;
        {
            address _token0 = token0;
            address _token1 = token1;
            require(to != _token0 && to != _token1, "UniswapV2: INVALID_TO");
            if (amount0Out > 0) _token0.safeTransfer(to, amount0Out);
            if (amount1Out > 0) _token1.safeTransfer(to, amount1Out);
            if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
            balance0 = SafeTransfer.balanceOf(_token0, address(this));
            balance1 = SafeTransfer.balanceOf(_token1, address(this));
        }

        uint256 amount0In = balance0 > reserve0 - amount0Out ? balance0 - (reserve0 - amount0Out) : 0;
        uint256 amount1In = balance1 > reserve1 - amount1Out ? balance1 - (reserve1 - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, "UniswapV2: INSUFFICIENT_INPUT_AMOUNT");

        // K invariant check with 0.3% fee
        {
            uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
            uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
            require(
                balance0Adjusted * balance1Adjusted >= uint256(reserve0) * reserve1 * 1_000_000,
                "UniswapV2: K"
            );
        }

        _update(balance0, balance1, reserve0, reserve1);
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    // ── Skim / Sync ──────────────────────────────────────────────────────────
    /// @notice Transfer excess tokens (balance > reserve) to `to`
    ///         Without calling _update, so reserves and price accumulators are NOT updated.
    ///         This is a subtle but crucial distinction from sync().
    function skim(address to) external lock {
        address _token0 = token0;
        address _token1 = token1;
        _token0.safeTransfer(to, SafeTransfer.balanceOf(_token0, address(this)) - _reserve0);
        _token1.safeTransfer(to, SafeTransfer.balanceOf(_token1, address(this)) - _reserve1);
    }

    /// @notice Force reserves to match balances (updates price accumulators)
    function sync() external lock {
        _update(
            SafeTransfer.balanceOf(token0, address(this)),
            SafeTransfer.balanceOf(token1, address(this)),
            _reserve0,
            _reserve1
        );
    }
}
