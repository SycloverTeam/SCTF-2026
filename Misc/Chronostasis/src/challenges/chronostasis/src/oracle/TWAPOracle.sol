// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ITWAPOracle} from "../interfaces/ITWAPOracle.sol";
import {IUniswapV2Pair} from "../interfaces/IUniswapV2Pair.sol";
import {FixedPointMath} from "../lib/FixedPointMath.sol";

/// @title TWAPOracle
/// @notice Sliding-window TWAP oracle for UniswapV2 pairs.
///
///         Design:
///         - Stores a ring buffer of N observations per pair.
///         - `update()` must be called at least once per `window` seconds to avoid staleness.
///         - `consult()` finds the oldest observation within `[now-window, now]` and
///           computes the time-weighted average over that interval.
contract TWAPOracle is ITWAPOracle {
    using FixedPointMath for uint224;

    // ── Constants ────────────────────────────────────────────────────────────
    uint8  public constant GRANULARITY     = 8;      // observations per window
    uint32 public constant DEFAULT_WINDOW  = 300;
    uint32 public constant MIN_WINDOW      = 60;
    uint32 public constant MAX_WINDOW      = 86400;

    // ── State ────────────────────────────────────────────────────────────────
    address public owner;
    uint32  public override window;

    // pair → ring buffer of observations
    mapping(address => Observation[GRANULARITY]) private _observations;
    // pair → index of next write slot
    mapping(address => uint8)  private _obsIndex;
    // pair → how many observations have been written (max GRANULARITY)
    mapping(address => uint8)  private _obsCount;
    // Whitelisted pairs (only registered pairs can be updated)
    mapping(address => bool)   public registered;

    // ── Events  ─────────────────────────────────────
    event PairRegistered(address indexed pair);
    event PairDeregistered(address indexed pair);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── Errors  ─────────────────────────────────────
    error OnlyOwner();
    error PairNotRegistered(address pair);
    error AlreadyRegistered(address pair);

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(address _owner, uint32 _window) {
        if (_window < MIN_WINDOW || _window > MAX_WINDOW) revert ZeroWindow();
        owner  = _owner;
        window = _window;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ── Owner ─────────────────────────────────────────────────────────────────
    function registerPair(address pair) external onlyOwner {
        if (registered[pair]) revert AlreadyRegistered(pair);
        // Validate it's a real pair by calling getReserves
        IUniswapV2Pair(pair).getReserves();
        registered[pair] = true;
        emit PairRegistered(pair);
    }

    function deregisterPair(address pair) external onlyOwner {
        registered[pair] = false;
        emit PairDeregistered(pair);
    }

    function setWindow(uint32 newWindow) external onlyOwner {
        if (newWindow < MIN_WINDOW || newWindow > MAX_WINDOW) revert ZeroWindow();
        emit TWAPWindowUpdated(window, newWindow);
        window = newWindow;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ── Update ────────────────────────────────────────────────────────────────
    /// @notice Snapshot current cumulative prices for `pair` into the ring buffer.
    function update(address pair) external override {
        if (!registered[pair]) revert PairNotRegistered(pair);

        uint256 p0c = IUniswapV2Pair(pair).price0CumulativeLast();
        uint256 p1c = IUniswapV2Pair(pair).price1CumulativeLast();

        // Add current spot accumulation since pair's last update
        {
            (uint112 r0, uint112 r1, uint32 ts) = IUniswapV2Pair(pair).getReserves();
            uint32 elapsed;
            unchecked { elapsed = uint32(block.timestamp) - ts; }
            if (elapsed > 0 && r0 > 0 && r1 > 0) {
                unchecked {
                    p0c += uint256(FixedPointMath.fraction(r1, r0)) * elapsed;
                    p1c += uint256(FixedPointMath.fraction(r0, r1)) * elapsed;
                }
            }
        }

        uint8 idx = _obsIndex[pair];
        _observations[pair][idx] = Observation({
            timestamp:         uint32(block.timestamp),
            price0Cumulative:  p0c,
            price1Cumulative:  p1c
        });
        _obsIndex[pair] = (idx + 1) % GRANULARITY;
        if (_obsCount[pair] < GRANULARITY) _obsCount[pair]++;

        emit ObservationUpdated(pair, p0c, p1c, uint32(block.timestamp));
    }

    // ── Consult ───────────────────────────────────────────────────────────────

    /// @notice Returns the latest observation struct
    function latestObservation(address pair) external view override returns (Observation memory) {
        if (!registered[pair]) revert PairNotRegistered(pair);
        uint8 idx = (_obsIndex[pair] + GRANULARITY - 1) % GRANULARITY;
        return _observations[pair][idx];
    }

    /// @notice Returns UQ112x112 TWAP of token0 priced in token1 over `_window`
    function consult0(address pair, uint32 _window) public view override returns (uint256 price) {
        price = _consult(pair, _window, true);
    }

    /// @notice Returns UQ112x112 TWAP of token1 priced in token0 over `_window`
    function consult1(address pair, uint32 _window) public view override returns (uint256 price) {
        price = _consult(pair, _window, false);
    }

    /// @notice Returns TWAP price scaled to `_decimals` precision.
    ///         Converts UQ112x112 to decimal with the given precision via integer division.
    function consultDecimal(
        address pair,
        bool    zeroForOne,
        uint32  _window,
        uint8   _decimals
    ) external view override returns (uint256 price) {
        uint224 raw = uint224(_consult(pair, _window, zeroForOne));
        price = FixedPointMath.toDecimal(raw, _decimals);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _consult(address pair, uint32 _window, bool zeroForOne)
        internal
        view
        returns (uint256 avgPrice)
    {
        if (!registered[pair]) revert InvalidPair(pair);
        if (_obsCount[pair] < 2) revert InsufficientHistory();

        uint32 targetTime = uint32(block.timestamp) - _window;

        // Find the oldest observation that is still within [now-window, now]
        // We iterate through the ring buffer to find the observation closest to targetTime
        Observation memory oldest;
        Observation memory newest;
        bool foundOldest;
        uint8 count = _obsCount[pair];
        uint8 writeIdx = _obsIndex[pair];

        // newest is the last-written slot
        uint8 newestIdx = (writeIdx + GRANULARITY - 1) % GRANULARITY;
        newest = _observations[pair][newestIdx];

        // Search for best `oldest` observation
        for (uint8 i = 0; i < count; i++) {
            uint8 slot = (writeIdx + GRANULARITY - 1 - i) % GRANULARITY;
            Observation memory obs = _observations[pair][slot];
            if (obs.timestamp <= newest.timestamp && obs.timestamp >= targetTime) {
                oldest = obs;
                foundOldest = true;
            } else if (obs.timestamp < targetTime) {
                // This one is older than window, use it as the anchor
                oldest = obs;
                foundOldest = true;
                break;
            }
        }

        if (!foundOldest) revert InsufficientHistory();

        uint32 timeElapsed;
        unchecked { timeElapsed = newest.timestamp - oldest.timestamp; }

        if (timeElapsed == 0) revert StaleObservation(0, 1);

        // Compute average price over [oldest, newest]
        if (zeroForOne) {
            unchecked {
                avgPrice = uint224(
                    (newest.price0Cumulative - oldest.price0Cumulative) / timeElapsed
                );
            }
        } else {
            unchecked {
                avgPrice = uint224(
                    (newest.price1Cumulative - oldest.price1Cumulative) / timeElapsed
                );
            }
        }
    }
}
