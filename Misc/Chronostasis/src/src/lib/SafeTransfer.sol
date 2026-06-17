// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SafeTransfer
/// @notice Low-level safe ERC20 helpers that handle non-standard tokens
///         (tokens that return nothing on transfer, etc.)
library SafeTransfer {
    error TransferFailed(address token, address from, address to, uint256 amount);
    error ApproveFailed(address token, address spender, uint256 amount);

    /// @notice Transfer tokens, reverting on failure
    function safeTransfer(address token, address to, uint256 amount) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed(token, address(this), to, amount);
        }
    }

    /// @notice TransferFrom tokens, reverting on failure
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(0x23b872dd, from, to, amount));
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed(token, from, to, amount);
        }
    }

    /// @notice Approve tokens, reverting on failure
    function safeApprove(address token, address spender, uint256 amount) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(0x095ea7b3, spender, amount));
        if (!success || (data.length != 0 && !abi.decode(data, (bool)))) {
            revert ApproveFailed(token, spender, amount);
        }
    }

    /// @notice Returns the balance of `account` for `token`
    function balanceOf(address token, address account) internal view returns (uint256 bal) {
        (bool success, bytes memory data) =
            token.staticcall(abi.encodeWithSelector(0x70a08231, account));
        require(success && data.length == 32, "SafeTransfer: BALANCE_FAILED");
        bal = abi.decode(data, (uint256));
    }
}
