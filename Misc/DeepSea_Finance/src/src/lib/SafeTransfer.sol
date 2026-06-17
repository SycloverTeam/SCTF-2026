// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../interfaces/IERC20.sol";

library SafeTransfer {
    function safeTransfer(address token, address to, uint256 value) internal {
        (bool ok, bytes memory ret) = token.call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, value)
        );
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "ST");
    }

    function safeTransferFrom(
        address token, address from, address to, uint256 value
    ) internal {
        (bool ok, bytes memory ret) = token.call(
            abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value)
        );
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "STF");
    }
}
