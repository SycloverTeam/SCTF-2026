// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./proxy/RoutedProxy.sol";
import "./vault/DeepSeaVault.sol";
import "./tokens/MockERC20.sol";
import "./oracle/PriceOracle.sol";

/// @notice CTF deployment contract.
///         Deploys the DeepSea Finance protocol stack behind a
///         RoutedProxy, seeds the vault with WBTC and USDC, and
///         exposes isSolved() for the flag checker.
///
///         Victory condition: all WBTC drained from the vault.
contract Setup {
    address private constant GUARDIAN_A = 0x8a4C9f9D7B3E2A1c6D5F004e91B72c8A0f13D246;
    address private constant GUARDIAN_B = 0x6F29b4E7C1D8a5039BD6420Ea75F18C93A4d0B57;

    DeepSeaVault public vaultProxy;
    MockERC20    public wbtc;
    MockERC20    public usdc;
    PriceOracle  public oracle;

    constructor(address player) {
        require(
            player != GUARDIAN_A && player != GUARDIAN_B,
            "player is guardian"
        );

        wbtc   = new MockERC20("Wrapped Bitcoin", "WBTC", 8);
        usdc   = new MockERC20("USD Coin",         "USDC", 6);
        oracle = new PriceOracle(address(this));

        oracle.setPrice(address(wbtc), 60_000e18);
        oracle.setPrice(address(usdc), 1e18);

        // ── Protocol domain derivation ───────────────────────────
        // Each deployment receives a unique domain seed derived from
        // chain identity and setup address.  Subsystems derive their
        // own domains from this seed.
        bytes32 deploySeed = keccak256(abi.encode(block.chainid, address(this)));

        // Routing domain for proxy slot assignment
        bytes32 routingDomain = deploySeed;

        // Relay synchroniser seed. Keep this in a separately hashed
        // namespace so proxy routing slots and relay context slots cannot
        // be algebraically folded into the same domain.
        bytes32 relaySeed = keccak256(
            abi.encodePacked("deepsea.relay.seed.v3", deploySeed)
        );

        // ── Vault implementation ─────────────────────────────────
        DeepSeaVault impl = new DeepSeaVault(relaySeed);

        // ── Guardians ───────────────────────────────────────────
        address[] memory guards = new address[](2);
        guards[0] = GUARDIAN_A;
        guards[1] = GUARDIAN_B;

        bytes memory initData = abi.encodeWithSelector(
            DeepSeaVault.initialize.selector,
            address(oracle),
            address(usdc),
            guards
        );

        // ── Proxy ────────────────────────────────────────────────
        RoutedProxy proxy = new RoutedProxy(
            address(impl),
            address(this),
            routingDomain,
            initData
        );

        vaultProxy = DeepSeaVault(address(proxy));

        // ── Markets ─────────────────────────────────────────────
        vaultProxy.addMarket(address(wbtc), 10, 1e12);
        vaultProxy.addMarket(address(usdc),  5, 1e14);

        // ── Seed liquidity ──────────────────────────────────────
        wbtc.mint(address(proxy), 10e8);
        usdc.mint(address(proxy), 600_000e6);

        // ── Starter balance ─────────────────────────────────────
        usdc.mint(player, 10e6);
    }

    function isSolved() external view returns (bool) {
        return wbtc.balanceOf(address(vaultProxy)) == 0;
    }
}
