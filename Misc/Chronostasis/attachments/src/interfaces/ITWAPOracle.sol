// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITWAPOracle {
    event ObservationUpdated(address indexed pair, uint256 price0Cumulative, uint256 price1Cumulative, uint32 timestamp);
    event TWAPWindowUpdated(uint32 oldWindow, uint32 newWindow);

    error StaleObservation(uint256 elapsed, uint256 required);
    error InvalidPair(address pair);
    error InsufficientHistory();
    error ZeroWindow();

    struct Observation {
        uint32  timestamp;
        uint256 price0Cumulative;
        uint256 price1Cumulative;
    }

    function update(address pair) external;

    /// @notice Returns TWAP price of token0 in terms of token1, scaled by 2^112
    function consult0(address pair, uint32 window) external view returns (uint256 price);

    /// @notice Returns TWAP price of token1 in terms of token0, scaled by 2^112
    function consult1(address pair, uint32 window) external view returns (uint256 price);

    /// @notice Returns TWAP price scaled to `decimals` precision
    function consultDecimal(address pair, bool zeroForOne, uint32 window, uint8 decimals)
        external
        view
        returns (uint256 price);

    function latestObservation(address pair) external view returns (Observation memory);

    function window() external view returns (uint32);
}
