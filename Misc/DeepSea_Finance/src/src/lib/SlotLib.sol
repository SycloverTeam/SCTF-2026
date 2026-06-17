// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

/// @notice Deterministic storage slot derivation for proxy-routed deployments.
/// @dev    Produces a slot from a domain seed and a sequence nonce.
///         Guarantees isolation between modules within the same proxy's
///         storage space by incorporating the domain in both hashing stages.
///         Derived from the EIP-1967 pattern, generalized for multi-module use.
library SlotLib {
    /// @notice Compute a storage slot for a (domain, nonce) pair.
    /// @param  domain  Deployment-level namespace discriminator.
    /// @param  nonce   Module sequence index (e.g. 0 = impl, 1 = admin).
    /// @return slot    Deterministic storage slot hash.
    function locate(bytes32 domain, uint256 nonce) internal pure returns (bytes32 slot) {
        assembly {
            mstore(0x00, domain)
            mstore(0x20, nonce)
            let label := keccak256(0x00, 0x40)
            mstore(0x00, label)
            mstore(0x20, domain)
            slot := keccak256(0x00, 0x40)
        }
    }
}
