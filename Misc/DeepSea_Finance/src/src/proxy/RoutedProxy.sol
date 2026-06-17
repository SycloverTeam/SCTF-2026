// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../lib/SlotLib.sol";

/// @notice Upgradeable proxy with domain-routed storage slot assignment.
/// @dev    Storage slots for the implementation and admin addresses are
///         derived from a deploy-time domain seed using SlotLib.locate,
///         which ensures logical isolation between protocol instances.
///
///         Slot layout:
///           SlotLib.locate(routingDomain, 0)  →  implementation address
///           SlotLib.locate(routingDomain, 1)  →  admin address
///
///         Unlike EIP-1967, the domain seed allows multiple protocol
///         instances to coexist in the same proxy's storage space
///         without manual slot management.
contract RoutedProxy {
    bytes32 private immutable _routingDomain;

    event Upgraded(address indexed implementation);
    event AdminChanged(address previousAdmin, address newAdmin);

    /// @param  impl_           Initial implementation contract.
    /// @param  admin_          Initial admin address.
    /// @param  routingDomain_  Domain seed for storage slot derivation.
    /// @param  initData        Optional delegatecall payload for initialization.
    constructor(
        address impl_,
        address admin_,
        bytes32 routingDomain_,
        bytes memory initData
    ) {
        _routingDomain = routingDomain_;
        _sstore(SlotLib.locate(_routingDomain, 0), _addrToBytes32(impl_));
        _sstore(SlotLib.locate(_routingDomain, 1), _addrToBytes32(admin_));
        emit Upgraded(impl_);
        if (initData.length > 0) {
            (bool ok, ) = impl_.delegatecall(initData);
            require(ok, "Init failed");
        }
    }

    function _addrToBytes32(address a) private pure returns (bytes32) {
        return bytes32(uint256(uint160(a)) << 96);
    }

    function _bytes32ToAddr(bytes32 b) private pure returns (address) {
        return address(uint160(uint256(b) >> 96));
    }

    function _readImpl() private view returns (address) {
        return _bytes32ToAddr(_sload(SlotLib.locate(_routingDomain, 0)));
    }

    function _readAdmin() private view returns (address) {
        return _bytes32ToAddr(_sload(SlotLib.locate(_routingDomain, 1)));
    }

    function _sstore(bytes32 slot, bytes32 value) private {
        assembly { sstore(slot, value) }
    }

    function _sload(bytes32 slot) private view returns (bytes32 value) {
        assembly { value := sload(slot) }
    }

    // ── Admin interface ─────────────────────────────────────────────

    function upgradeTo(address newImpl) external {
        require(msg.sender == _readAdmin(), "Not admin");
        _sstore(SlotLib.locate(_routingDomain, 0), _addrToBytes32(newImpl));
        emit Upgraded(newImpl);
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == _readAdmin(), "Not admin");
        emit AdminChanged(_readAdmin(), newAdmin);
        _sstore(SlotLib.locate(_routingDomain, 1), _addrToBytes32(newAdmin));
    }

    function getAdmin() external view returns (address) {
        require(msg.sender == _readAdmin(), "Not admin");
        return _readAdmin();
    }

    // ── Fallback ──────────────────────────────────────────────────

    fallback() external payable {
        address impl = _readImpl();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {
        address impl = _readImpl();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
