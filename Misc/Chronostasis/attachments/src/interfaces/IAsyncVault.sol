// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC4626} from "./IERC4626.sol";

/// @notice EIP-7540 Asynchronous Redemption Vault
interface IAsyncVault is IERC4626 {
    event RedeemRequested(
        address indexed controller,
        address indexed owner,
        uint256 indexed requestId,
        address sender,
        uint256 shares
    );
    event RedeemClaimed(
        address indexed controller,
        address indexed receiver,
        uint256 indexed requestId,
        uint256 assets,
        uint256 shares
    );
    event RedeemRequestCanceled(address indexed controller, uint256 indexed requestId, uint256 shares);

    struct RedeemRequest {
        address owner;
        address receiver;
        uint256 shares;
        uint256 requestedAt;
        uint256 snapshotPrice;
        bool fulfilled;
        bool canceled;
    }

    function requestRedeem(uint256 shares, address receiver, address owner)
        external
        returns (uint256 requestId);

    function claimRedeem(uint256 requestId) external returns (uint256 assets);

    function cancelRedeemRequest(uint256 requestId) external;

    function pendingRedeemRequest(uint256 requestId) external view returns (RedeemRequest memory);

    function claimableRedeemRequest(uint256 requestId) external view returns (bool);

    function minRedeemDelay() external view returns (uint256);

    function maxRedeemDelay() external view returns (uint256);
}
