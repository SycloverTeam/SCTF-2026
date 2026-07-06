// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TokenA} from "./tokens/TokenA.sol";
import {TokenB} from "./tokens/TokenB.sol";
import {TokenC} from "./tokens/TokenC.sol";
import {UniswapV2Factory} from "./lib/uniswapv2/UniswapV2Factory.sol";
import {UniswapV2Router} from "./lib/uniswapv2/UniswapV2Router.sol";
import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import {TWAPOracle} from "./oracle/TWAPOracle.sol";
import {AsyncLPVault} from "./vault/AsyncLPVault.sol";

/// @title Setup — Chronostasis CTF Challenge
/// @notice Deploys the full Chronostasis protocol: tokens, UniswapV2 pools,
///         TWAP oracle, and async LP vault.
contract Setup {
    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration constants
    // ═══════════════════════════════════════════════════════════════════════════
    uint32  public constant ORACLE_WINDOW      = 300;
    uint256 public constant MIN_REDEEM_DELAY   = 1;
    uint256 public constant MAX_REDEEM_DELAY   = 7 days;

    // A/B pool
    uint256 public constant DEEP_LP_TKA = 1_000_000e18;
    uint256 public constant DEEP_LP_TKB = 1_000_000e18;

    // B/C pool
    uint256 public constant THIN_LP_TKB = 1_000e18;
    uint256 public constant THIN_LP_TKC = 1_000e6;

    // Player initial tokens
    uint256 public constant PLAYER_TKA = 10_000e18;
    uint256 public constant PLAYER_TKB = 10_000e18;
    uint256 public constant PLAYER_TKC = 100_000e6;

    // Initial LP deposit (provides TVL to drain)
    uint256 public constant INITIAL_TKA = 100_000e18;
    uint256 public constant INITIAL_TKB = 100_000e18;

    // ═══════════════════════════════════════════════════════════════════════════
    // Contracts (all public for cast-readability)
    // ═══════════════════════════════════════════════════════════════════════════
    TokenA          public tokenA;
    TokenB          public tokenB;
    TokenC          public tokenC;
    UniswapV2Factory public factory;
    UniswapV2Router public router;
    address         public pairAB;  // TKA/TKB
    address         public pairBC;  // TKB/TKC
    TWAPOracle      public oracle;
    AsyncLPVault    public vault;

    // ═══════════════════════════════════════════════════════════════════════════
    // Player
    // ═══════════════════════════════════════════════════════════════════════════
    address public player;

    // ═══════════════════════════════════════════════════════════════════════════
    // Solved tracking
    // ═══════════════════════════════════════════════════════════════════════════
    uint256 public initialVaultLPBalance;

    // ═══════════════════════════════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════════════════════════════
    constructor(address _player) {
        player = _player;
        // address(this) = Setup contract, which becomes owner of all child contracts
        // so it can call onlyOwner/onlyMinter functions during construction.

        // ── Deploy tokens ──────────────────────────────────────────────
        tokenA = new TokenA(address(this), 10_000_000e18);
        tokenB = new TokenB(address(this));
        tokenC = new TokenC(address(this));

        // Whitelist Setup as minter for TokenB / TokenC
        tokenB.setMinter(address(this), true);
        tokenC.setMinter(address(this), true);

        // ── Deploy UniswapV2 ───────────────────────────────────────────
        factory = new UniswapV2Factory(address(this));
        router  = new UniswapV2Router(address(factory));

        // ── Create trading pairs ───────────────────────────────────────
        pairAB = factory.createPair(address(tokenA), address(tokenB));
        pairBC = factory.createPair(address(tokenB), address(tokenC));

        // ── Deploy TWAP oracle ────────────────────────────────────────
        oracle = new TWAPOracle(address(this), ORACLE_WINDOW);
        oracle.registerPair(pairAB);
        oracle.registerPair(pairBC);

        // ── Deploy vault (wraps A/B LP tokens) ────────────────────────
        vault = new AsyncLPVault(
            address(this),
            pairAB,
            address(tokenA),
            address(tokenB),
            address(oracle),
            pairBC,
            MIN_REDEEM_DELAY,
            MAX_REDEEM_DELAY
        );

        // ── Mint all tokens to Setup ────────────────────────────────
        tokenA.mint(address(this), DEEP_LP_TKA + PLAYER_TKA + INITIAL_TKA);
        tokenB.mint(address(this), DEEP_LP_TKB + THIN_LP_TKB + PLAYER_TKB + INITIAL_TKB);
        tokenC.mint(address(this), THIN_LP_TKC + PLAYER_TKC);

        // ── Approve router for all tokens ──────────────────────────────
        tokenA.approve(address(router), type(uint256).max);
        tokenB.approve(address(router), type(uint256).max);
        tokenC.approve(address(router), type(uint256).max);

        // ── Seed A/B pool ─────────────────────────────
        router.addLiquidity(
            address(tokenA), address(tokenB),
            DEEP_LP_TKA, DEEP_LP_TKB,
            0, 0, address(this), block.timestamp
        );

        // ── Seed B/C pool ───
        router.addLiquidity(
            address(tokenB), address(tokenC),
            THIN_LP_TKB, THIN_LP_TKC,
            0, 0, address(this), block.timestamp
        );

        // ── Seed oracle with first observations ───────────────────────
        oracle.update(pairAB);
        oracle.update(pairBC);

        // ── Transfer tokens to player ─────────────────────────────────
        tokenA.transfer(player, PLAYER_TKA);
        tokenB.transfer(player, PLAYER_TKB);
        tokenC.transfer(player, PLAYER_TKC);

        // ── Setup deposits LP into vault (provides TVL) ────────────
        router.addLiquidity(
            address(tokenA), address(tokenB),
            INITIAL_TKA, INITIAL_TKB,
            0, 0, address(this), block.timestamp
        );

        uint256 deployerLP = IUniswapV2Pair(pairAB).balanceOf(address(this));
        IUniswapV2Pair(pairAB).approve(address(vault), deployerLP);
        vault.deposit(deployerLP, address(this));

        // ── Record initial vault LP for isSolved check ────────────────────
        initialVaultLPBalance = vault.totalAssetsLP();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Challenge resolution
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Returns true when vault LP balance drops below initial level.
    function isSolved() external view returns (bool) {
        return vault.totalAssetsLP() < initialVaultLPBalance;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Convenience getter (for CTF framework compatibility)
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice The main challenge contract (the vault).
    function challenge() external view returns (address) {
        return address(vault);
    }
}
