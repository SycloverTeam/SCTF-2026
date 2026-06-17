# Chronostasis — Writeup

## 题目设计思路

Chronostasis 模拟了一个超额抵押稳定币协议，核心组件包括：

- 三种代币：TKA（治理代币）、TKB（跨池桥接代币）、TKC（USD 稳定币，6 位精度）
- 两个 UniswapV2 池：A/B 池（深度流动性，1M TVL）和 B/C 池（薄流动性，1K TVL）
- TWAPOracle：滑动窗口 TWAP 预言机，8 个观测值环形缓冲区，300 秒默认窗口
- AsyncLPVault：EIP-7540 风格异步 LP 金库，`requestRedeem` 锁定快照价格，`claimRedeem` 按当前价格结算

选手初始持有 10K 等值的 TKA、TKB、TKC。金库中预存了 100K TVL。胜利条件为金库 A/B LP 余额低于初始值。

## 漏洞分析

金库的 LP 公允价值通过**组合 TWAP** 计算：

```
priceB_USD = TWAP(B/C, tokenB → tokenC)                 // B 的 USD 价格
priceA_USD = TWAP(A/B, tokenA → tokenB) × priceB_USD    // A 的 USD 价格
LP_price   = 2 × sqrt(rA × priceA_USD) × sqrt(rB × priceB_USD) / totalLP
```

异步赎回的核心矛盾在于**时间差**：

1. `requestRedeem` 使用 **当前** TWAP 计算 `snapshotPricePerShare`
2. `claimRedeem` 使用 **清算时** TWAP 计算 LP 输出

如果能在 `requestRedeem` 时使 TWAP 膨胀（人为抬高 B/C 池中 TKB 的美元价格），在 `claimRedeem` 时使 TWAP 恢复正常，则 LP 输出将远大于公平份额：

```
lpOut = shares × snapshotPricePerShare / currentLPPrice
       = shares × 膨胀价格 / 正常价格
       > 公平份额
```

### 关键漏洞点

1. **B/C 池流动性极薄**（1K TVL），远小于 A/B 池（1M TVL）
2. **TWAP 窗口短**（300 秒），环形缓冲区仅需 8 个观测值即可完全覆盖
3. **预言机无流动性校验**，任何人均可调用 `update()`

攻击者可以通过暂时扭曲 B/C 池汇率，然后在 300 秒内用 8 个扭曲观测值覆盖环形缓冲区，从而操纵 TWAP 快照。

## 攻击步骤

### 总体流程

```
步骤 0: 初始化预言机（积累 2+ 观测值）
步骤 1: 存入 A/B LP 获得金库份额
步骤 2: 闪电贷从 B/C 池借走 95% TKB -> TKB 急剧升值
步骤 3: 推进时间 + 8 轮预言机更新 -> 环形缓冲区被操纵 TWAP 填满
步骤 4: requestRedeem -> 锁死膨胀的快照价格
步骤 5: 反向 swap 恢复 B/C 池比率
步骤 6: 推进时间 + 8 轮预言机更新 -> 环形缓冲区被正常 TWAP 覆盖
步骤 7: claimRedeem -> 抽干金库 LP
```

### 详细步骤

#### 步骤 0 — 初始化预言机

预言机需要至少 2 个观测值才能进行 TWAP 查询。Setup 构造函数已写入第一轮，攻击者需补充：

```solidity
// warp 500s → 第二次更新
oracle.update(pairAB);
oracle.update(pairBC);
// warp 12s → 第三次更新（确保足够的观测间隔）
oracle.update(pairAB);
oracle.update(pairBC);
```

#### 步骤 1 — 存入 A/B LP

攻击者用持有的 TKA、TKB 各一半添加 A/B 池流动性，将获得的 LP 代币存入金库获取份额。

#### 步骤 2 — 闪电贷操纵 B/C 池

```solidity
(uint112 r0, uint112 r1,) = pairBC.getReserves();
uint256 borrowAmt = uint256(r1) * 95 / 100;  // 借走 95% TKB
pairBC.swap(0, borrowAmt, address(this), "");
```

闪电贷回调中：预言机捕获旧观测值（swap 前状态），用 TKC 偿还借出的 TKB

swap 返回后：B/C 池 TKB 储备仅剩 5%，TKC 储备大幅增加 -> TKB 相对 TKC 的价格被急剧抬高

立即调用 `oracle.update(pairBC)` 记录被操纵的观测值

#### 步骤 3 — 填充操纵 TWAP

```python
evm_warp(400)  # 跳过 400s
for i in range(8):
    evm_warp(50)  # 每 50s 一次
    oracle.update(pairBC)
    oracle.update(pairAB)
```

8 次更新（8 × 50s = 400s）覆盖了 300s TWAP 窗口。现在环形缓冲区中最早的有效观测值就是步骤 2 记录的操纵值，整个 300s 窗口的 TWAP 都被抬高。

#### 步骤 4 — 锁死膨胀快照

```solidity
vault.approve(vault, shares);
pendingRequestId = vault.requestRedeem(shares, address(this), address(this));
```

`requestRedeem` 内部调用 `pricePerShare()` -> `lpPriceUSD()`，此时 TWAP 被操纵，快照价格远高于正常值。

#### 步骤 5 — 反向 swap 恢复池子

```solidity
router.swapExactTokensForTokens(tkbBalance, 0, [TKB, TKC], address(this), deadline);
```

将闪电贷借来的 TKB 卖回 B/C 池，换取 TKC。B/C 池储备比率恢复至接近原始状态。

#### 步骤 6 — 填充正常 TWAP

与步骤 3 相同，但此时预言机记录的是正常汇率的观测值。8 次更新后，环形缓冲区完全被正常观测值覆盖，TWAP 回到原始水平。

#### 步骤 7 — 领取赎回

```solidity
vault.claimRedeem(pendingRequestId);
```

`claimRedeem` 计算：

```
lpOut = shares × snapshotPricePerShare / currentLPPrice
```

- `snapshotPricePerShare` = 步骤 4 锁死的膨胀价格
- `currentLPPrice` = 步骤 6 恢复后的正常价格
- `lpOut > 公平份额`，金库 LP 被大量抽走

金库 `totalAssetsLP` 降至初始值以下 → `isSolved() = true`。

## Exp

### 攻击合约

见 `../exp/Expolit.sol`。

### exp.py

见 `../exp/exp.py`。

