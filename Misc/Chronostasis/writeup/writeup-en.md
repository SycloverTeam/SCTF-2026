# Chronostasis — Writeup

## Challenge Design

Chronostasis simulates an over-collateralized stablecoin protocol. Its core components include:

- Three tokens: TKA (governance token), TKB (cross-pool bridge token), TKC (USD stablecoin, 6 decimals)
- Two UniswapV2 pools: A/B pool (deep liquidity, 1M TVL) and B/C pool (thin liquidity, 1K TVL)
- TWAPOracle: a sliding-window TWAP oracle with an 8-observation ring buffer and a 300-second default window
- AsyncLPVault: an EIP-7540-style async LP vault — `requestRedeem` locks in a snapshot price, and `claimRedeem` settles at the current price

The player initially holds 10K worth of TKA, TKB, and TKC each. The vault is pre-seeded with 100K TVL. The win condition is that the vault's A/B LP balance falls below its initial value.

## Vulnerability Analysis

The vault's LP fair value is calculated via **combined TWAP**:

```
priceB_USD = TWAP(B/C, tokenB → tokenC)                 // USD price of B
priceA_USD = TWAP(A/B, tokenA → tokenB) × priceB_USD    // USD price of A
LP_price   = 2 × sqrt(rA × priceA_USD) × sqrt(rB × priceB_USD) / totalLP
```

The core contradiction of async redemption lies in the **time gap**:

1. `requestRedeem` uses the **current** TWAP to compute `snapshotPricePerShare`
2. `claimRedeem` uses the **settlement-time** TWAP to compute LP output

If the TWAP can be inflated at `requestRedeem` time (by artificially boosting TKB's USD price in the B/C pool) and then restored to normal at `claimRedeem` time, the LP output will far exceed the fair share:

```
lpOut = shares × snapshotPricePerShare / currentLPPrice
       = shares × inflated price / normal price
       > fair share
```

### Key Vulnerability Points

1. **B/C pool liquidity is extremely thin** (1K TVL), far smaller than the A/B pool (1M TVL)
2. **TWAP window is short** (300 seconds) — the ring buffer can be fully overwritten with just 8 observations
3. **The oracle has no liquidity check** — anyone can call `update()`

An attacker can temporarily distort the B/C pool exchange rate, then overwrite the ring buffer with 8 distorted observations within 300 seconds, thereby manipulating the TWAP snapshot.

## Attack Steps

### Overview

```
Step 0: Initialize the oracle (accumulate 2+ observations)
Step 1: Deposit A/B LP to obtain vault shares
Step 2: Flash loan — borrow 95% of TKB from B/C pool → TKB price spikes
Step 3: Advance time + 8 rounds of oracle updates → ring buffer filled with manipulated TWAP
Step 4: requestRedeem → lock in inflated snapshot price
Step 5: Reverse swap to restore B/C pool ratio
Step 6: Advance time + 8 rounds of oracle updates → ring buffer overwritten with normal TWAP
Step 7: claimRedeem → drain vault LP
```

### Detailed Steps

#### Step 0 — Initialize the Oracle

The oracle requires at least 2 observations to perform a TWAP query. The Setup constructor writes the first round; the attacker must supply the rest:

```solidity
// warp 500s → second update
oracle.update(pairAB);
oracle.update(pairBC);
// warp 12s → third update (ensure sufficient observation interval)
oracle.update(pairAB);
oracle.update(pairBC);
```

#### Step 1 — Deposit A/B LP

The attacker uses half of their held TKA and TKB to add liquidity to the A/B pool, then deposits the resulting LP tokens into the vault to obtain shares.

#### Step 2 — Flash Loan to Manipulate the B/C Pool

```solidity
(uint112 r0, uint112 r1,) = pairBC.getReserves();
uint256 borrowAmt = uint256(r1) * 95 / 100;  // borrow 95% of TKB
pairBC.swap(0, borrowAmt, address(this), "");
```

During the flash loan callback: the oracle captures the old observation (pre-swap state), and TKC is used to repay the borrowed TKB.

After the swap returns: the B/C pool has only 5% TKB reserves remaining while TKC reserves have greatly increased → TKB's price relative to TKC is sharply elevated.

Immediately call `oracle.update(pairBC)` to record the manipulated observation.

#### Step 3 — Fill with Manipulated TWAP

```python
evm_warp(400)  # skip 400s
for i in range(8):
    evm_warp(50)  # 50s per step
    oracle.update(pairBC)
    oracle.update(pairAB)
```

8 updates (8 × 50s = 400s) cover the 300s TWAP window. Now the earliest valid observation in the ring buffer is the manipulated observation recorded in Step 2 — the entire 300s window TWAP is inflated.

#### Step 4 — Lock in the Inflated Snapshot

```solidity
vault.approve(vault, shares);
pendingRequestId = vault.requestRedeem(shares, address(this), address(this));
```

`requestRedeem` internally calls `pricePerShare()` → `lpPriceUSD()`. At this point the TWAP is manipulated, so the snapshot price is far above normal.

#### Step 5 — Reverse Swap to Restore the Pool

```solidity
router.swapExactTokensForTokens(tkbBalance, 0, [TKB, TKC], address(this), deadline);
```

Sell the flash-loaned TKB back into the B/C pool in exchange for TKC. The B/C pool reserve ratio is restored to near the original state.

#### Step 6 — Fill with Normal TWAP

Same as Step 3, but now the oracle records observations at the normal exchange rate. After 8 updates, the ring buffer is completely overwritten with normal observations, and the TWAP returns to the original level.

#### Step 7 — Claim Redemption

```solidity
vault.claimRedeem(pendingRequestId);
```

`claimRedeem` computes:

```
lpOut = shares × snapshotPricePerShare / currentLPPrice
```

- `snapshotPricePerShare` = inflated price locked in at Step 4
- `currentLPPrice` = normal price restored after Step 6
- `lpOut > fair share` → a large portion of vault LP is drained

Vault `totalAssetsLP` drops below initial value → `isSolved() = true`.

## Exploit

### Attack Contract

See `../exp/Exploit.sol`.

### exp.py

See `../exp/exp.py`.
