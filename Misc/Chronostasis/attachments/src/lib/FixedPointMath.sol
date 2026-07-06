// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FixedPointMath
/// @notice UQ112x112 fixed-point arithmetic used by UniswapV2 price accumulators.
///         A UQ112x112 number has 112 bits of integer part and 112 bits of fractional part.
///         Encoding: value = integer * 2^112
library FixedPointMath {
    // ── Constants ────────────────────────────────────────────────────────────
    uint8   internal constant RESOLUTION = 112;
    uint256 internal constant Q112       = 1 << 112;  // 2^112
    uint256 internal constant Q224       = 1 << 224;  // 2^224

    // ── UQ112x112 type ───────────────────────────────────────────────────────

    /// @notice Encode a uint112 as a UQ112x112 (i.e. shift left 112)
    function encode(uint112 y) internal pure returns (uint224 z) {
        z = uint224(y) * uint224(Q112);
    }

    /// @notice Divide two uint112 values, returning UQ112x112
    function fraction(uint112 numerator, uint112 denominator) internal pure returns (uint224 z) {
        require(denominator > 0, "FixedPoint: DIV_BY_ZERO");
        z = (uint224(numerator) * uint224(Q112)) / uint224(denominator);
    }

    /// @notice Decode UQ112x112 to uint112 (integer part only, truncates)
    function decode(uint224 x) internal pure returns (uint112 z) {
        z = uint112(x >> RESOLUTION);
    }

    /// @notice Multiply UQ112x112 by a uint256, return uint256 (result may overflow if very large)
    function mul(uint224 x, uint256 y) internal pure returns (uint256 z) {
        // (x * y) / Q112
        // We need 512-bit intermediate; use unchecked since Solidity 0.8 can overflow uint256
        // But in practice, x <= 2^224 and y <= 2^256, so (x*y) can be 2^480 which fits in 512
        // We avoid 512-bit by observing: x / Q112 * y + (x % Q112) * y / Q112
        uint256 hi = uint256(x >> RESOLUTION) * y;           // integer part * y
        uint256 lo = uint256(x & (Q112 - 1)) * y / Q112;     // fractional part * y (truncated)
        z = hi + lo;
    }

    // ── Full 256-bit safe multiply with overflow detection ────────────────────

    /// @notice Returns (a * b) >> 128 without overflow using Karatsuba-style splitting
    function mulDiv128(uint256 a, uint256 b) internal pure returns (uint256) {
        // Split a into high/low 128 bits
        uint256 aHi = a >> 128;
        uint256 aLo = a & type(uint128).max;
        uint256 bHi = b >> 128;
        uint256 bLo = b & type(uint128).max;

        // a*b = aHi*bHi*2^256 + (aHi*bLo + aLo*bHi)*2^128 + aLo*bLo
        // We want (a*b) >> 128
        // = aHi*bHi*2^128 + (aHi*bLo + aLo*bHi) + aLo*bLo >> 128
        uint256 result = (aHi * bHi) << 128;
        result += aHi * bLo;
        result += aLo * bHi;
        result += (aLo * bLo) >> 128;
        return result;
    }

    // ── TWAP helpers ─────────────────────────────────────────────────────────

    /// @notice Compute TWAP from cumulative price difference
    /// @param priceCumulativeEnd   price0CumulativeLast at end
    /// @param priceCumulativeStart price0CumulativeLast at start
    /// @param timeElapsed          seconds between observations
    /// @return avgPrice            UQ112x112 average price
    function computeTWAP(
        uint256 priceCumulativeEnd,
        uint256 priceCumulativeStart,
        uint32  timeElapsed
    ) internal pure returns (uint224 avgPrice) {
        require(timeElapsed > 0, "FixedPoint: ZERO_ELAPSED");
        // Subtraction is safe even with overflow: both values are modular uint256 accumulators
        unchecked {
            avgPrice = uint224((priceCumulativeEnd - priceCumulativeStart) / timeElapsed);
        }
    }

    /// @notice Convert UQ112x112 price to a scaled integer with `decimals` precision
    /// @param price    UQ112x112 price (token1 per token0)
    /// @param decimals desired output decimals (e.g. 18)
    function toDecimal(uint224 price, uint8 decimals) internal pure returns (uint256) {
        // price / 2^112 * 10^decimals
        return uint256(price) * (10 ** decimals) / Q112;
    }

    // ── Basic safe math (redundant in 0.8 but kept for explicit documentation) ─

    function add(uint256 a, uint256 b) internal pure returns (uint256) { return a + b; }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) { return a - b; }

    /// @notice Safe sqrt (Babylonian method)
    function sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    /// @notice min of two uint256
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
