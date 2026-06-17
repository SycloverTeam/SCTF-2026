// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../lib/SafeTransfer.sol";
import "../interfaces/IERC20.sol";
import "../oracle/PriceOracle.sol";
import "./CrossChainRelay.sol";
import "./ReentrancyGuard.sol";

/// @notice DeepSea Finance Vault — multi-asset lending, borrowing, and cross-chain
///         relay execution engine.
///
///         Architecture:
///           Player → RoutedProxy → delegatecall → DeepSeaVault
///
///         The vault inherits CrossChainRelay for relay context management
///         and ReentrancyGuard for single-transaction safety on external-call
///         paths.  Governance uses a 2-day timelock.  Guardian multisig
///         provides emergency overrides.
contract DeepSeaVault is CrossChainRelay, ReentrancyGuard {
    using SafeTransfer for address;

    // ── Constants ──────────────────────────────────────────────────
    uint256 public constant BASE_LTV          = 75;
    uint256 public constant LIQ_THRESHOLD     = 82;
    uint256 public constant LIQ_BONUS         = 5;
    uint256 public constant FLASHLOAN_FEE_BPS = 3;
    uint256 public constant PROPOSAL_DELAY    = 2 days;
    uint256 public constant GUARDIAN_THRESHOLD = 2;

    bytes32 public constant FLASHLOAN_MAGIC =
        keccak256("DeepSea.FlashLoan.Callback.Success.v1");

    // ── State ───────────────────────────────────────────────────────
    address      public governor;
    IVaultOracle public priceOracle;
    address      public rewardToken;
    address      private _pendingRewardOperator;

    struct MarketConfig {
        bool    enabled;
        uint256 reserveFactor;
        uint256 rewardPerBlock;
        uint256 globalRewardIndex;
        uint256 lastRewardBlock;
        uint256 totalDeposited;
        uint256 totalBorrowed;
    }

    struct UserPosition {
        uint256 deposited;
        uint256 borrowed;
        address[] borrowedTokenList;
        uint256 rewardIndexSnapshot;
        uint256 pendingRewards;
        uint256 lastActivityBlock;
    }

    struct Proposal {
        bytes   callData;
        uint256 unlockTime;
        bool    executed;
        address proposer;
    }

    struct EmergencyAction {
        uint256 approvalCount;
        bool    executed;
    }

    mapping(address => MarketConfig)                          public markets;
    mapping(address => mapping(address => UserPosition))      public positions;
    mapping(address => bool)                                  public guardians;
    mapping(uint256 => Proposal)                              public proposals;
    mapping(bytes32 => EmergencyAction)                       public emergencyActions;
    mapping(bytes32 => mapping(address => bool))              public guardianApprovals;
    mapping(address => mapping(address => mapping(address => uint256))) public userDebt;
    mapping(bytes32 => address)                               private _rewardOperators;

    uint256 public proposalCount;
    uint256 public guardianCount;

    // ── Events ──────────────────────────────────────────────────────
    event Deposited(address indexed user, address indexed token, uint256 amount);
    event Withdrawn(address indexed user, address indexed token, uint256 amount);
    event Borrowed(address indexed user, address indexed token, uint256 amount);
    event Repaid(address indexed user, address indexed token, uint256 amount);
    event Liquidated(address indexed liquidator, address indexed user, address indexed token);
    event FlashLoan(address indexed receiver, address indexed token, uint256 amount, uint256 fee);
    event ProposalCreated(uint256 indexed id, address indexed proposer, uint256 unlockTime);
    event ProposalExecuted(uint256 indexed id);
    event EmergencyActionQueued(bytes32 indexed actionHash);
    event EmergencyActionExecuted(bytes32 indexed actionHash);
    event RelayExecuted();
    event AssetSettled(address indexed token, address indexed recipient, uint256 amount);

    // ── Init ────────────────────────────────────────────────────────

    /// @param syncSeed  Deployment seed for relay domain derivation.
    constructor(bytes32 syncSeed)
        CrossChainRelay(syncSeed)
        ReentrancyGuard()
    {}

    function initialize(
        address          _oracle,
        address          _rewardToken,
        address[] calldata _guardians
    ) external {
        require(governor == address(0), "Already initialized");
        governor    = msg.sender;
        priceOracle = IVaultOracle(_oracle);
        rewardToken = _rewardToken;
        for (uint256 i = 0; i < _guardians.length; i++) {
            if (!guardians[_guardians[i]]) {
                guardians[_guardians[i]] = true;
                guardianCount++;
            }
        }
    }

    modifier onlyGovernor() {
        require(msg.sender == governor, "Not governor");
        _;
    }

    function _assetValueUSD(address token, uint256 amount) internal view returns (uint256) {
        return (amount * priceOracle.getAssetPrice(token)) / (10 ** IERC20(token).decimals());
    }

    function _assetAmountFromUSD(address token, uint256 valueUSD) internal view returns (uint256) {
        return (valueUSD * (10 ** IERC20(token).decimals())) / priceOracle.getAssetPrice(token);
    }

    // ── Market Management ───────────────────────────────────────────

    function addMarket(
        address token,
        uint256 reserveFactor,
        uint256 rewardPerBlock
    ) external onlyGovernor {
        require(!markets[token].enabled, "Market exists");
        markets[token] = MarketConfig({
            enabled:           true,
            reserveFactor:     reserveFactor,
            rewardPerBlock:    rewardPerBlock,
            globalRewardIndex: 0,
            lastRewardBlock:   block.number,
            totalDeposited:    0,
            totalBorrowed:     0
        });
    }

    // ── Reward Accounting ───────────────────────────────────────────

    function _accrueRewards(address token) internal {
        MarketConfig storage m = markets[token];
        if (m.totalDeposited == 0 || block.number <= m.lastRewardBlock) return;
        uint256 elapsed        = block.number - m.lastRewardBlock;
        uint256 accrued        = elapsed * m.rewardPerBlock;
        m.globalRewardIndex   += (accrued * 1e18) / m.totalDeposited;
        m.lastRewardBlock      = block.number;
    }

    function _settlePendingRewards(address user, address token) internal {
        _accrueRewards(token);
        UserPosition storage pos = positions[user][token];
        MarketConfig  storage m  = markets[token];
        uint256 delta            = m.globalRewardIndex - pos.rewardIndexSnapshot;
        pos.pendingRewards       += (pos.deposited * delta) / 1e18;
        pos.rewardIndexSnapshot   = m.globalRewardIndex;
    }

    function claimRewards(address token) external nonReentrant {
        _settlePendingRewards(msg.sender, token);
        UserPosition storage pos = positions[msg.sender][token];
        uint256 amt = pos.pendingRewards;
        if (amt > 0 && IERC20(rewardToken).balanceOf(address(this)) >= amt) {
            pos.pendingRewards = 0;
            rewardToken.safeTransfer(msg.sender, amt);
        }
        _settleRewardEpoch(token);
    }

    /// @notice Claim rewards for multiple markets.
    function batchClaimRewards(address[] calldata tokens) external nonReentrant {
        for (uint256 i = 0; i < tokens.length; i++) {
            (bool ok, ) = address(this).call(
                abi.encodeWithSelector(this.claimRewards.selector, tokens[i])
            );
            if (!ok) continue;
        }
    }

    function _settleRewardEpoch(address token) internal {
        bytes32 epochId = keccak256(abi.encodePacked(token, block.chainid));
        _stageRewardOperator(epochId);
        _finalizeRewardEpoch(msg.sender);
    }

    function _stageRewardOperator(bytes32 epochId) internal {
        _pendingRewardOperator = _rewardOperators[epochId];
        delete _pendingRewardOperator;
    }

    function _finalizeRewardEpoch(address operator) internal {
        _epochOperator = operator;
        delete _epochOperator;
    }

    // ── Core Protocol ───────────────────────────────────────────────

    function deposit(address token, uint256 amount) external nonReentrant {
        require(markets[token].enabled, "Market disabled");
        require(amount > 0, "Zero amount");
        _settlePendingRewards(msg.sender, token);
        token.safeTransferFrom(msg.sender, address(this), amount);

        UserPosition storage pos       = positions[msg.sender][token];
        pos.deposited                 += amount;
        pos.lastActivityBlock          = block.number;
        markets[token].totalDeposited += amount;
        emit Deposited(msg.sender, token, amount);
    }

    function withdraw(address token, uint256 amount) external nonReentrant {
        require(markets[token].enabled, "Market disabled");
        UserPosition storage pos = positions[msg.sender][token];
        require(pos.deposited >= amount, "Insufficient deposit");
        if (pos.borrowed > 0) {
            uint256 remainingColUSD = _assetValueUSD(token, pos.deposited - amount);
            uint256 maxBorrowUSD    = (remainingColUSD * BASE_LTV) / 100;
            uint256 totalBorUSD;
            for (uint256 i = 0; i < pos.borrowedTokenList.length; i++) {
                address bt = pos.borrowedTokenList[i];
                uint256 d  = userDebt[msg.sender][token][bt];
                if (d > 0) totalBorUSD += _assetValueUSD(bt, d);
            }
            require(totalBorUSD <= maxBorrowUSD, "Would undercollateralize");
        }
        _settlePendingRewards(msg.sender, token);
        pos.deposited                 -= amount;
        markets[token].totalDeposited -= amount;
        pos.lastActivityBlock          = block.number;
        token.safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, token, amount);
    }

    function borrow(
        address borrowToken,
        address collateralToken,
        uint256 borrowAmount
    ) external nonReentrant {
        require(
            markets[borrowToken].enabled && markets[collateralToken].enabled,
            "Market disabled"
        );
        require(borrowAmount > 0, "Zero amount");

        UserPosition storage pos  = positions[msg.sender][collateralToken];
        uint256 colValueUSD       = _assetValueUSD(collateralToken, pos.deposited);
        uint256 maxBorrowUSD      = (colValueUSD   * BASE_LTV)    / 100;
        uint256 existingBorUSD;
        for (uint256 i = 0; i < pos.borrowedTokenList.length; i++) {
            address bt = pos.borrowedTokenList[i];
            uint256 d = userDebt[msg.sender][collateralToken][bt];
            if (d > 0) existingBorUSD += _assetValueUSD(bt, d);
        }
        uint256 newBorUSD         = _assetValueUSD(borrowToken, borrowAmount);
        require(existingBorUSD + newBorUSD <= maxBorrowUSD, "Undercollateralized");

        if (userDebt[msg.sender][collateralToken][borrowToken] == 0) {
            pos.borrowedTokenList.push(borrowToken);
        }
        userDebt[msg.sender][collateralToken][borrowToken] += borrowAmount;
        pos.borrowed                        += borrowAmount;
        markets[borrowToken].totalBorrowed  += borrowAmount;
        pos.lastActivityBlock                = block.number;
        borrowToken.safeTransfer(msg.sender, borrowAmount);
        emit Borrowed(msg.sender, borrowToken, borrowAmount);
    }

    function repay(
        address borrowToken,
        address collateralToken,
        uint256 amount
    ) external nonReentrant {
        require(amount > 0, "Zero amount");
        UserPosition storage pos = positions[msg.sender][collateralToken];
        uint256 currentDebt = userDebt[msg.sender][collateralToken][borrowToken];
        require(currentDebt > 0, "No debt for this borrow token");
        uint256 repayAmt = amount > currentDebt ? currentDebt : amount;
        userDebt[msg.sender][collateralToken][borrowToken] -= repayAmt;
        borrowToken.safeTransferFrom(msg.sender, address(this), repayAmt);
        pos.borrowed                        -= repayAmt;
        markets[borrowToken].totalBorrowed  -= repayAmt;
        pos.lastActivityBlock                = block.number;
        emit Repaid(msg.sender, borrowToken, repayAmt);
    }

    function liquidate(
        address user,
        address collateralToken,
        address borrowToken
    ) external nonReentrant {
        UserPosition storage pos = positions[user][collateralToken];
        require(pos.borrowed > 0, "No debt");

        uint256 totalBorrowUSD = 0;
        for (uint i = 0; i < pos.borrowedTokenList.length; i++) {
            address bToken = pos.borrowedTokenList[i];
            uint256 bAmount = userDebt[user][collateralToken][bToken];
            if (bAmount > 0) {
                totalBorrowUSD += _assetValueUSD(bToken, bAmount);
            }
        }

        uint256 colUSD = _assetValueUSD(collateralToken, pos.deposited);
        require(totalBorrowUSD > (colUSD * LIQ_THRESHOLD) / 100, "Position is healthy");

        uint256 debt      = userDebt[user][collateralToken][borrowToken];
        require(debt > 0, "No debt for this borrow token");

        uint256 debtValueUSD = _assetValueUSD(borrowToken, debt);
        uint256 colAmount = _assetAmountFromUSD(
            collateralToken,
            (debtValueUSD * (100 + LIQ_BONUS)) / 100
        );
        require(colAmount <= pos.deposited, "Insufficient collateral");

        userDebt[user][collateralToken][borrowToken] = 0;
        pos.borrowed  -= debt;
        pos.deposited -= colAmount;
        markets[borrowToken].totalBorrowed      -= debt;
        markets[collateralToken].totalDeposited -= colAmount;

        borrowToken.safeTransferFrom(msg.sender, address(this), debt);
        collateralToken.safeTransfer(msg.sender, colAmount);
        emit Liquidated(msg.sender, user, collateralToken);
    }

    // ── Flash Loans ─────────────────────────────────────────────────

    function flashLoan(
        address token,
        uint256 amount,
        address receiver,
        bytes calldata data
    ) external nonReentrant {
        require(markets[token].enabled, "Market disabled");
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        require(balBefore >= amount, "Insufficient liquidity");

        uint256 fee = (amount * FLASHLOAN_FEE_BPS) / 1000;
        token.safeTransfer(receiver, amount);

        bytes32 ret = IFlashLoanReceiver(receiver).onFlashLoan(
            msg.sender, token, amount, fee, data
        );
        require(ret == FLASHLOAN_MAGIC, "Invalid callback return");

        uint256 balAfter = IERC20(token).balanceOf(address(this));
        require(balAfter >= balBefore + fee, "Flash loan not repaid");
        emit FlashLoan(receiver, token, amount, fee);
    }

    // ── Cross-Chain Relay Execution ─────────────────────────────────

    uint256 private constant _RELAY_FLAG = 0x5e85a7732a35afbe19f5dc2652de0b26cf400fffab3c5fd631e74ee95c60d855;

    /// @notice Execute a transcript of relayed operations that were committed
    ///         by a cross-chain relayer.  Each operation is self-delegated,
    ///         running with the full authority of the vault context.
    /// @param  cmds  Encoded function calls to execute sequentially.
    function processTranscript(bytes[] calldata cmds) external {
        bytes32 ctx = _loadRelayContext();
        require(ctx != bytes32(0), "No active relay context");

        assembly { tstore(_RELAY_FLAG, 1) }

        uint256 n = cmds.length;
        for (uint256 i = 0; i < n; i++) {
            (bool ok, ) = address(this).delegatecall(cmds[i]);
            require(ok, "Relay operation reverted");
        }

        assembly { tstore(_RELAY_FLAG, 0) }
        _advanceRelayNonce();
        emit RelayExecuted();
    }

    /// @notice Initiate an asset settlement as part of a relayed cross-chain
    ///         transfer.  Transfers tokens from the vault to a recipient.
    /// @dev    Settlements are only valid during an active relay transcript.
    function settleAsset(
        address token,
        address recipient,
        uint256 amount
    ) external {
        uint256 flag;
        assembly { flag := tload(_RELAY_FLAG) }
        require(flag == 1, "No active relay");
        token.safeTransfer(recipient, amount);
        emit AssetSettled(token, recipient, amount);
    }

    // ── Governance ──────────────────────────────────────────────────

    function propose(bytes calldata callData) external onlyGovernor returns (uint256 id) {
        id = proposalCount++;
        proposals[id] = Proposal({
            callData:   callData,
            unlockTime: block.timestamp + PROPOSAL_DELAY,
            executed:   false,
            proposer:   msg.sender
        });
        emit ProposalCreated(id, msg.sender, block.timestamp + PROPOSAL_DELAY);
    }

    function executeProposal(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed,                     "Already executed");
        require(block.timestamp >= p.unlockTime, "Timelock active");
        p.executed = true;
        (bool ok, ) = address(this).call(p.callData);
        require(ok, "Proposal failed");
        emit ProposalExecuted(id);
    }

    // ── Guardian Emergency Module ───────────────────────────────────

    function emergencyWithdraw(address token, address to, uint256 amount) external {
        require(guardians[msg.sender], "Not guardian");
        token.safeTransfer(to, amount);
    }

    function approveEmergencyAction(bytes32 actionHash) external {
        require(guardians[msg.sender],                     "Not a guardian");
        require(!guardianApprovals[actionHash][msg.sender], "Already approved");
        guardianApprovals[actionHash][msg.sender]  = true;
        emergencyActions[actionHash].approvalCount++;
        emit EmergencyActionQueued(actionHash);
    }

    function executeEmergencyAction(
        bytes32 actionHash,
        address target,
        bytes calldata callData
    ) external {
        EmergencyAction storage action = emergencyActions[actionHash];
        require(!action.executed,                           "Already executed");
        require(action.approvalCount >= GUARDIAN_THRESHOLD, "Insufficient approvals");
        require(
            keccak256(abi.encode(target, callData)) == actionHash,
            "Hash mismatch"
        );
        action.executed = true;
        (bool ok, ) = target.call(callData);
        require(ok, "Emergency action failed");
        emit EmergencyActionExecuted(actionHash);
    }

    // ── Asset Recovery ──────────────────────────────────────────────

    /// @notice Guardian-initiated recovery of tokens mistakenly sent to
    ///         the vault.  Uses an external call to the target contract.
    function recoverERC20(
        address token,
        address to,
        uint256 amount,
        bytes32 recoveryId
    ) external {
        require(guardians[msg.sender], "Not a guardian");
        require(!_recoveryExecuted[recoveryId], "Recovery already executed");
        _recoveryExecuted[recoveryId] = true;
        (bool ok, ) = token.call(
            abi.encodeWithSelector(IERC20.transfer.selector, to, amount)
        );
        require(ok, "Recovery failed");
    }

    mapping(bytes32 => bool) private _recoveryExecuted;

    // ── Merkle Distribution ─────────────────────────────────────────

    /// @notice Claim rewards via a merkle proof.  Uses transient storage
    ///         for proof verification context to save gas.
    function merkleClaim(
        bytes32[] calldata proof,
        uint256 index,
        address account,
        uint256 amount
    ) external {
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = _hashPair(computed, proof[i]);
        }
        bytes32 merkleSlot = keccak256(abi.encode("merkle.root", block.timestamp));
        bytes32 root;
        assembly { root := tload(merkleSlot) }
        require(computed == root, "Invalid proof");
        rewardToken.safeTransfer(account, amount);
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encodePacked(a, b))
            : keccak256(abi.encodePacked(b, a));
    }

}
