// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

interface IVaultOracle {
    function getAssetPrice(address asset) external view returns (uint256);
}

contract PriceOracle is IVaultOracle {
    mapping(address => uint256) public prices;
    address public owner;

    constructor(address _owner) {
        require(_owner != address(0), "zero owner");
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }

    function setPrice(address asset, uint256 price) external onlyOwner {
        prices[asset] = price;
    }

    function getAssetPrice(address asset) external view override returns (uint256) {
        return prices[asset];
    }
}
