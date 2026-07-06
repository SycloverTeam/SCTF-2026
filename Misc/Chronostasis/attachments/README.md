# Chronostasis

指针划过表盘，却在目光落下的那一刻……停住了。
——不，那不是静止。
在两次观测之间的裂隙里，某些东西正在改变。

## 协议概览

### 代币

| 代币 | 符号 | 说明 |
| ------ | ------ | ------ |
| TokenA | TKA | 治理代币，总量 10,000,000 |
| TokenB | TKB | 跨池桥接代币 |
| TokenC | TKC | USD 稳定币，6 位精度 |


### 交易池

- **A/B 池** — TKA ↔ TKB
- **B/C 池** — TKB ↔ TKC

两个池均为标准 UniswapV2 交易对，收取 0.3% 手续费。

### TWAP 预言机

协议使用基于时间的加权平均价格（TWAP）预言机对两个交易对报价。预言机维护一个观测值环形缓冲区。

### 异步 LP 金库（AsyncLPVault）

金库包装 A/B 池 LP 代币，遵循 EIP-7540 异步赎回模式：

- **`deposit(lpAmount, receiver)`** — 存入 A/B LP 代币，获得金库份额
- **`withdraw(shares, receiver, owner)`** — 同步赎回
- **`requestRedeem(shares, receiver, owner)`** — 提交异步赎回请求
- **`claimRedeem(requestId)`** — 清算赎回请求

金库份额价格通过组合 TWAP 计算 LP 公允价值得出。

### 初始状态

- 选手持有 10,000 TKA、10,000 TKB、100,000 TKC
- 金库中已存入初始 LP 作为 TVL

## 胜利条件

```solidity
function isSolved() external view returns (bool) {
    return vault.totalAssetsLP() < initialVaultLPBalance;
}
```

金库内 A/B LP 余额低于部署时的初始值即视为通关。

## 交互方式

选手通过 `nc` 连接服务器获取个人实例：

```bash
nc <host> 5000
```

连接后在菜单中选择 `[2] Launch new instance` 启动个人链上环境。

获取实例后通过 `cast` / `forge` 直接与 Anvil RPC 交互，或自行编写脚本交互：

```bash
export RPC=<given-RPC>
export PK=<player-private-key>
export SETUP=<setup-address>

# 查询合约地址
cast call $SETUP "vault()(address)" --rpc-url $RPC
cast call $SETUP "oracle()(address)" --rpc-url $RPC
cast call $SETUP "tokenA()(address)" --rpc-url $RPC

# 发送交易
cast send <contract> "function(args)" --rpc-url $RPC --private-key $PK
```

## 合约文件

``` tree
src/
├── Setup.sol              # 部署脚本 + 胜利条件
├── tokens/
│   ├── TokenA.sol
│   ├── TokenB.sol
│   └── TokenC.sol
├── oracle/
│   └── TWAPOracle.sol     # TWAP 价格预言机
├── vault/
│   └── AsyncLPVault.sol   # 异步 LP 金库
├── lib/                   # 在期望的解法内，可以认为 lib 内所有合约是安全的
│   ├── SafeTransfer.sol
│   ├── FixedPointMath.sol
│   ├── ReentrancyGuard.sol
│   ├── tokens/ERC20.sol
│   └── uniswapv2/         # UniswapV2 实现
└── interfaces/            # 接口定义
```
