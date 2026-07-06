// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAsyncVault} from "../interfaces/IAsyncVault.sol";
import {IUniswapV2Pair} from "../interfaces/IUniswapV2Pair.sol";
import {ITWAPOracle} from "../interfaces/ITWAPOracle.sol";
import {ERC20} from "../lib/tokens/ERC20.sol";
import {SafeTransfer} from "../lib/SafeTransfer.sol";
import {ReentrancyGuard} from "../lib/ReentrancyGuard.sol";
import {FixedPointMath} from "../lib/FixedPointMath.sol";

/// @title AsyncLPVault
/// @notice EIP-7540-style asynchronous vault that wraps UniswapV2 LP tokens.
///         Share price is computed using a TWAP oracle to value the underlying LP.
///         Supports synchronous withdraw() and asynchronous requestRedeem()/claimRedeem().
contract AsyncLPVault is ERC20, ReentrancyGuard {
    using SafeTransfer for address;
    using FixedPointMath for uint224;

    // ── Errors ───────────────────────────────────────────────────────────────
    error OnlyOwner();
    error ZeroAmount();
    error ZeroAddress();
    error RequestNotFound(uint256 requestId);
    error RequestAlreadyFulfilled(uint256 requestId);
    error RequestCanceled(uint256 requestId);
    error RequestNotClaimable(uint256 requestId, uint256 claimableAt);
    error NotRequestOwner(address caller, address owner);
    error InsufficientShares(uint256 have, uint256 need);
    error OracleStalePriceData();
    error VaultPaused();
    error InvalidDelay(uint256 min, uint256 max);
    error MaxRequestsExceeded();

    // ── Events ───────────────────────────────────────────────────────────────
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(
        address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares
    );
    event RedeemRequested(
        address indexed controller, address indexed owner, uint256 indexed requestId, address sender, uint256 shares
    );
    event RedeemClaimed(
        address indexed controller, address indexed receiver, uint256 indexed requestId, uint256 assets, uint256 shares
    );
    event RedeemRequestCanceled(address indexed controller, uint256 indexed requestId, uint256 shares);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event DelayUpdated(uint256 minDelay, uint256 maxDelay);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PerformanceFeeCollected(address indexed to, uint256 amount);
    event VaultPausedEvent(address indexed by);
    event VaultUnpausedEvent(address indexed by);

    // ── Structs ───────────────────────────────────────────────────────────────
    struct RedeemRequest {
        address owner;
        address receiver;
        uint256 shares;
        uint256 requestedAt;
        uint256 snapshotPricePerShare;
        bool fulfilled;
        bool canceled;
    }

    // ── Constants ────────────────────────────────────────────────────────────
    uint256 public constant MAX_ACTIVE_REQUESTS = 64;
    uint256 public constant PRICE_PRECISION = 1e18;
    uint256 public constant PERFORMANCE_FEE_BPS = 200; // 2%

    // ── Immutables ───────────────────────────────────────────────────────────
    address public immutable lpToken;   // UniswapV2 LP (TKA/TKB pair)
    address public immutable tokenA;    // token0 of lpToken
    address public immutable tokenB;    // token1 of lpToken

    // ── State ────────────────────────────────────────────────────────────────
    address public owner;
    address public oracle;          // TWAPOracle
    address public pairAB;          // TKA/TKB UniswapV2 pair (same as lpToken)
    address public pairBC;          // TKB/TKC UniswapV2 pair

    uint256 public minRedeemDelay;  // seconds; minimum = 1 block in setup
    uint256 public maxRedeemDelay;  // seconds; maximum before request expires

    uint256 private _nextRequestId;
    mapping(uint256 => RedeemRequest) private _requests;
    mapping(address => uint256) public activeRequestCount;

    uint256 public totalAssetsLP;   // total LP tokens held
    uint256 public accumulatedFees; // performance fees accrued (in shares)

    bool public paused;

    // ── Constructor ──────────────────────────────────────────────────────────
    constructor(
        address _owner,
        address _lpToken,
        address _tokenA,
        address _tokenB,
        address _oracle,
        address _pairBC,
        uint256 _minDelay,
        uint256 _maxDelay
    ) ERC20("Ghost LP Vault Share", "gLPS", 18) {
        owner = _owner;
        lpToken = _lpToken;
        tokenA = _tokenA;
        tokenB = _tokenB;
        oracle = _oracle;
        pairAB = _lpToken; // the LP token IS the pair
        pairBC = _pairBC;
        minRedeemDelay = _minDelay;
        maxRedeemDelay = _maxDelay;
    }

    // ── Modifiers ────────────────────────────────────────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert VaultPaused();
        _;
    }

    // ── View: share price ─────────────────────────────────────────────────────

    /// @notice Returns the current USD value of one LP token, scaled by PRICE_PRECISION.
    ///         Uses composite TWAP: A/C = A/B * B/C
    ///
    ///         LP value formula:
    ///         value = 2 * sqrt(rA * rB) * sqrt(priceA_USD * priceB_USD) / totalLPSupply
    ///         Where priceA_USD = TWAP(A→B) * TWAP(B→C), priceB_USD = TWAP(B→C)
    function lpPriceUSD() public view returns (uint256 pricePerLP) {
        uint32 w = ITWAPOracle(oracle).window();

        // TWAP: A priced in B
        // zeroForOne depends on sort order
        bool abZeroForOne = tokenA < tokenB; // if tokenA == token0, price0 = B/A ... use price1 for A→B
        // price of tokenA in terms of tokenB
        uint256 priceA_in_B = ITWAPOracle(oracle).consultDecimal(pairAB, !abZeroForOne, w, 18);

        // TWAP: B priced in C (USD), scaled to 1e18
        // Query B/C TWAP directly at 18 decimals to avoid precision loss
        address _pairBC = pairBC;
        (address bc0,) = _getSortedTokens(_pairBC);
        bool bcZeroForOne = (bc0 == tokenB); // if tokenB is token0, price0 = C/B
        uint256 priceB_USD = ITWAPOracle(oracle).consultDecimal(_pairBC, bcZeroForOne, w, 18);

        // Composite: priceA_USD = priceA_in_B * priceB_USD / 1e18
        uint256 priceA_USD = priceA_in_B * priceB_USD / PRICE_PRECISION;

        // LP fair price using geometric mean:
        // fairLP = 2 * sqrt(rA * rB * priceA * priceB) / totalSupply
        (uint112 rA, uint112 rB,) = IUniswapV2Pair(pairAB).getReserves();
        // Ensure rA corresponds to tokenA
        if (!abZeroForOne) (rA, rB) = (rB, rA);

        uint256 totalLP = IUniswapV2Pair(pairAB).totalSupply();
        if (totalLP == 0) return 0;

        // Use sqrt decomposition to avoid overflow:
        // sqrt(rA * priceA_USD) * sqrt(rB * priceB_USD) * 2 / totalLP
        // Note: priceA_USD and priceB_USD are in 1e18 units, rA/rB in token-native units (18 dec)
        // So rA * priceA_USD has units: tokens^2 * (USD/token) = tokens*USD
        uint256 termA = FixedPointMath.sqrt(uint256(rA) * priceA_USD); // sqrt(rA * priceA)
        uint256 termB = FixedPointMath.sqrt(uint256(rB) * priceB_USD); // sqrt(rB * priceB)

        // 2 * termA * termB / totalLP — units check out to USD * 1e9 (sqrt of 1e18)
        // Rescale: multiply by PRICE_PRECISION, divide by 1e9 to normalize
        pricePerLP = 2 * termA * termB / totalLP * PRICE_PRECISION / 1e9;
    }

    /// @notice Returns the current price per vault share in USD (scaled by 1e18)
    ///         pricePerShare = lpPriceUSD * totalAssetsLP / totalShares
    function pricePerShare() public view returns (uint256) {
        uint256 ts = totalSupply();
        if (ts == 0) return PRICE_PRECISION; // initial price = $1
        return lpPriceUSD() * totalAssetsLP / ts;
    }

    /// @notice Preview how many assets `shares` would redeem for at current price
    function previewRedeem(uint256 shares) public view returns (uint256 assets) {
        uint256 pps = pricePerShare();
        // assets = shares * pricePerShare / PRICE_PRECISION
        // But assets are LP tokens, so we must convert USD-denominated price back to LP
        uint256 lpUSD = lpPriceUSD();
        if (lpUSD == 0) return 0;
        assets = shares * pps / lpUSD;
    }

    function totalAssets() public view returns (uint256) {
        return totalAssetsLP;
    }

    function minRedeemDelayView() external view returns (uint256) {
        return minRedeemDelay;
    }

    function maxRedeemDelayView() external view returns (uint256) {
        return maxRedeemDelay;
    }

    // ── Deposit / Sync withdraw ───────────────────────────────────────────────

    /// @notice Deposit LP tokens, receive vault shares.
    ///         Shares minted = lpAmount * totalShares / totalAssetsLP  (proportional)
    ///         On first deposit: shares = lpAmount (1:1).
    function deposit(uint256 lpAmount, address receiver) external nonReentrant whenNotPaused returns (uint256 shares) {
        if (lpAmount == 0) revert ZeroAmount();
        if (receiver == address(0)) revert ZeroAddress();

        uint256 ts = totalSupply();
        uint256 ta = totalAssetsLP;

        // Transfer LP in
        lpToken.safeTransferFrom(msg.sender, address(this), lpAmount);

        if (ts == 0 || ta == 0) {
            shares = lpAmount;
        } else {
            shares = lpAmount * ts / ta;
        }

        totalAssetsLP += lpAmount;
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, lpAmount, shares);
    }

    /// @notice Synchronous withdraw (only for small amounts, no TWAP dependency).
    ///         assets = shares * totalAssetsLP / totalShares  (pure proportion, no TWAP).
    function withdraw(uint256 shares, address receiver, address shareOwner)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 lpOut)
    {
        if (shares == 0) revert ZeroAmount();
        if (shareOwner != msg.sender) {
            _spendAllowance(shareOwner, msg.sender, shares);
        }
        uint256 ts = totalSupply();
        uint256 ta = totalAssetsLP;

        lpOut = shares * ta / ts;
        totalAssetsLP -= lpOut;
        _burn(shareOwner, shares);

        lpToken.safeTransfer(receiver, lpOut);
        emit Withdraw(msg.sender, receiver, shareOwner, lpOut, shares);
    }

    // ── Async Redeem (EIP-7540) ─────────────────────────────────────────

    /// @notice Request redemption. Locks the current pricePerShare into the request.
    function requestRedeem(uint256 shares, address receiver, address shareOwner)
        external
        nonReentrant
        whenNotPaused
        returns (uint256 requestId)
    {
        if (shares == 0) revert ZeroAmount();
        if (receiver == address(0)) revert ZeroAddress();
        if (shareOwner != msg.sender) {
            _spendAllowance(shareOwner, msg.sender, shares);
        }
        if (activeRequestCount[shareOwner] >= MAX_ACTIVE_REQUESTS) revert MaxRequestsExceeded();

        uint256 bal = balanceOf(shareOwner);
        if (bal < shares) revert InsufficientShares(bal, shares);

        // Snapshot the current pricePerShare
        uint256 snapshot = pricePerShare();

        // Transfer shares to vault (escrowed during pending period)
        _transfer(shareOwner, address(this), shares);

        requestId = _nextRequestId++;
        _requests[requestId] = RedeemRequest({
            owner: shareOwner,
            receiver: receiver,
            shares: shares,
            requestedAt: block.timestamp,
            snapshotPricePerShare: snapshot,
            fulfilled: false,
            canceled: false
        });
        activeRequestCount[shareOwner]++;

        emit RedeemRequested(shareOwner, shareOwner, requestId, msg.sender, shares);
    }

    /// @notice Claim a fulfilled redeem request.
    ///         LP OUT = shares * snapshotPricePerShare / lpPriceUSD_at_CLAIM_time
    function claimRedeem(uint256 requestId) external nonReentrant whenNotPaused returns (uint256 lpOut) {
        RedeemRequest storage req = _requests[requestId];
        if (req.requestedAt == 0) revert RequestNotFound(requestId);
        if (req.fulfilled) revert RequestAlreadyFulfilled(requestId);
        if (req.canceled) revert RequestCanceled(requestId);
        if (msg.sender != req.owner && msg.sender != req.receiver) {
            revert NotRequestOwner(msg.sender, req.owner);
        }

        // Enforce minimum delay
        uint256 claimableAt = req.requestedAt + minRedeemDelay;
        if (block.timestamp < claimableAt) {
            revert RequestNotClaimable(requestId, claimableAt);
        }

        // Enforce maximum delay (request expires)
        if (block.timestamp > req.requestedAt + maxRedeemDelay) {
            // Expired: cancel and return shares
            req.canceled = true;
            activeRequestCount[req.owner]--;
            _transfer(address(this), req.owner, req.shares);
            emit RedeemRequestCanceled(req.owner, requestId, req.shares);
            return 0;
        }

        req.fulfilled = true;
        activeRequestCount[req.owner]--;

        // Compute LP out using the locked snapshot price vs current LP price
        uint256 currentLPPrice = lpPriceUSD();
        if (currentLPPrice == 0) currentLPPrice = PRICE_PRECISION; // fallback

        // shares * snapshotPrice gives USD value at snapshot time
        // dividing by currentLPPrice converts USD back to LP tokens at current price
        lpOut = req.shares * req.snapshotPricePerShare / currentLPPrice;

        // Cap at actual available assets
        if (lpOut > totalAssetsLP) lpOut = totalAssetsLP;

        // Burn the escrowed shares
        _burn(address(this), req.shares);
        totalAssetsLP -= lpOut;

        // Performance fee on profits (if lpOut > fair share)
        uint256 fairLPOut = req.shares * totalAssets() / (totalSupply() + req.shares);
        if (lpOut > fairLPOut) {
            uint256 profit = lpOut - fairLPOut;
            uint256 fee = profit * PERFORMANCE_FEE_BPS / 10_000;
            // In practice fee would be deducted; kept as no-op for simplicity
            _unused(fee); // suppress unused warning
        }

        lpToken.safeTransfer(req.receiver, lpOut);

        emit RedeemClaimed(req.owner, req.receiver, requestId, lpOut, req.shares);
    }

    /// @notice Cancel a pending redeem request and return escrowed shares
    function cancelRedeemRequest(uint256 requestId) external nonReentrant {
        RedeemRequest storage req = _requests[requestId];
        if (req.requestedAt == 0) revert RequestNotFound(requestId);
        if (req.fulfilled) revert RequestAlreadyFulfilled(requestId);
        if (req.canceled) revert RequestCanceled(requestId);
        if (msg.sender != req.owner) revert NotRequestOwner(msg.sender, req.owner);

        req.canceled = true;
        activeRequestCount[req.owner]--;
        _transfer(address(this), req.owner, req.shares);
        emit RedeemRequestCanceled(req.owner, requestId, req.shares);
    }

    // ── View: request state ───────────────────────────────────────────────────

    function pendingRedeemRequest(uint256 requestId) external view returns (RedeemRequest memory) {
        return _requests[requestId];
    }

    function claimableRedeemRequest(uint256 requestId) external view returns (bool) {
        RedeemRequest storage req = _requests[requestId];
        if (req.requestedAt == 0 || req.fulfilled || req.canceled) return false;
        return
            block.timestamp >= req.requestedAt + minRedeemDelay && block.timestamp <= req.requestedAt + maxRedeemDelay;
    }

    // ── Admin ─────────────────────────────────────────────────────────────────
    function setOracle(address newOracle) external onlyOwner {
        emit OracleUpdated(oracle, newOracle);
        oracle = newOracle;
    }

    function setDelays(uint256 _minDelay, uint256 _maxDelay) external onlyOwner {
        if (_minDelay > _maxDelay) revert InvalidDelay(_minDelay, _maxDelay);
        minRedeemDelay = _minDelay;
        maxRedeemDelay = _maxDelay;
        emit DelayUpdated(_minDelay, _maxDelay);
    }

    function pause() external onlyOwner {
        paused = true;
        emit VaultPausedEvent(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
        emit VaultUnpausedEvent(msg.sender);
    }

    function collectFees(address to) external onlyOwner {
        uint256 fees = accumulatedFees;
        accumulatedFees = 0;
        if (fees > 0) _transfer(address(this), to, fees);
        emit PerformanceFeeCollected(to, fees);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ── Internal ──────────────────────────────────────────────────────────────
    function _getSortedTokens(address pair) internal view returns (address t0, address t1) {
        t0 = IUniswapV2Pair(pair).token0();
        t1 = IUniswapV2Pair(pair).token1();
    }

    // Suppress unused variable warning from Solidity
    function _unused(uint256) internal pure {}
}
