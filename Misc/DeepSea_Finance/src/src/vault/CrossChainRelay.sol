// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../lib/SlotLib.sol";

/// @notice Cross-chain relay context manager for the DeepSea Finance protocol.
/// @dev    Maintains a monotonic nonce that indexes into a domain-routed
///         storage space for relay message contexts.  The relay domain
///         is derived from a deploy-time seed combined with a deployment
///         constant to prevent cross-instance collisions.
///
///         Context lifecycle:
///           1. An off-chain relayer writes a context to the slot for the
///              current nonce.
///           2. A protocol function reads the context, processes it, and
///              advances the nonce (clearing the slot).
///
///         The relay domain is computed as:  syncSeed ^ RELAY_SLANT
///         where RELAY_SLANT is a fixed protocol constant.  This ensures
///         that different deployments produce non-overlapping slot spaces
///         even if they share the same sync seed by coincidence.
abstract contract CrossChainRelay {
    uint256 private constant RELAY_SLANT =
        uint256(keccak256("deepsea.relay.offset.v2"));

    string private constant RELAY_SOURCE = "deepsea.v1";
    string private constant RELAY_AUTH_LANE = ".batch.auth";

    bytes32 private immutable _relayDomain;
    address internal transient _epochAnchor;
    address internal transient _epochOperator;

    event CrossChainStateCommitted(bytes indexed sourceChain, bytes indexed lane, uint256 indexed nonce);

    constructor(bytes32 syncSeed) {
        _relayDomain = syncSeed ^ bytes32(RELAY_SLANT);
    }

    /// @notice Commit a state observation from a sibling deployment.
    /// @dev The relayer separates the source route and lane so indexers can
    ///      aggregate lane activity across chains without decoding payloads.
    function commitCrossChainState(
        bytes calldata sourceChain,
        bytes calldata lane,
        bytes32 context
    ) external {
        require(context != bytes32(0), "empty context");
        require(
            !(
                keccak256(sourceChain) == keccak256(bytes(RELAY_SOURCE)) &&
                keccak256(lane) == keccak256(bytes(RELAY_AUTH_LANE))
            ),
            "reserved route"
        );

        uint256 nonce = _readRelayNonce();
        bytes32 slot = _relayRouteSlot(sourceChain, lane, nonce);
        assembly { sstore(slot, context) }
        emit CrossChainStateCommitted(sourceChain, lane, nonce);
    }

    /// @notice Load the relay context for the current nonce.
    function _loadRelayContext() internal view returns (bytes32 value) {
        bytes32 slot = _relayRouteSlot(bytes(RELAY_SOURCE), bytes(RELAY_AUTH_LANE), _readRelayNonce());
        assembly { value := sload(slot) }
    }

    /// @notice Consume the current relay context and advance the nonce.
    function _advanceRelayNonce() internal {
        uint256 nonce = _readRelayNonce();
        bytes32 slot = _relayRouteSlot(bytes(RELAY_SOURCE), bytes(RELAY_AUTH_LANE), nonce);
        assembly { sstore(slot, 0) }
        _writeRelayNonce(nonce + 1);
    }

    function _relayRouteSlot(
        bytes memory sourceChain,
        bytes memory lane,
        uint256 nonce
    ) private view returns (bytes32) {
        bytes32 routeDomain = keccak256(
            abi.encode(_relayDomain, sourceChain, lane)
        );
        return SlotLib.locate(routeDomain, nonce);
    }

    function _relayNonceSlot() private view returns (bytes32) {
        return SlotLib.locate(_relayDomain, type(uint256).max);
    }

    function _readRelayNonce() private view returns (uint256 nonce) {
        bytes32 slot = _relayNonceSlot();
        assembly { nonce := sload(slot) }
    }

    function _writeRelayNonce(uint256 nonce) private {
        bytes32 slot = _relayNonceSlot();
        assembly { sstore(slot, nonce) }
    }

    /// @notice Current relay sequence number.
    function relayNonce() external view returns (uint256) {
        return _readRelayNonce();
    }
}
