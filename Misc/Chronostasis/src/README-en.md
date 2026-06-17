# Chronostasis

The hand sweeps across the dial, yet the moment your eyes land upon it…
…it halts.
No — it was never still.
Something shifts in the rift between observations.

## Protocol Overview

### Tokens

| Token | Symbol | Description |
| ------ | ------ | ------ |
| TokenA | TKA | Governance token, total supply 10,000,000 |
| TokenB | TKB | Cross-pool bridge token |
| TokenC | TKC | USD stablecoin, 6 decimals |

### Trading Pools

- **A/B Pool** — TKA ↔ TKB
- **B/C Pool** — TKB ↔ TKC

Both pools are standard UniswapV2 pairs with a 0.3% fee.

### TWAP Oracle

The protocol uses a Time-Weighted Average Price (TWAP) oracle to quote prices for both trading pairs. The oracle maintains a ring buffer of observations.

### Async LP Vault (AsyncLPVault)

The vault wraps A/B pool LP tokens and follows the EIP-7540 asynchronous redemption pattern:

- **`deposit(lpAmount, receiver)`** — Deposit A/B LP tokens to receive vault shares
- **`withdraw(shares, receiver, owner)`** — Synchronous redemption
- **`requestRedeem(shares, receiver, owner)`** — Submit an asynchronous redemption request
- **`claimRedeem(requestId)`** — Settle a redemption request

The vault share price is derived from the fair value of LP tokens calculated via combined TWAP.

### Initial State

- The player holds 10,000 TKA, 10,000 TKB, 100,000 TKC
- Initial LP has been deposited into the vault as TVL

## Win Condition

```solidity
function isSolved() external view returns (bool) {
    return vault.totalAssetsLP() < initialVaultLPBalance;
}
```

The challenge is considered solved when the A/B LP balance in the vault falls below its initial value at deployment.

## Interaction

Players connect to the server via `nc` to obtain a personal instance:

```bash
nc <host> 5000
```

After connecting, select `[2] Launch new instance` from the menu to spin up a personal on-chain environment.

Once the instance is obtained, interact with the Anvil RPC directly via `cast` / `forge`, or write your own scripts:

```bash
export RPC=<given-RPC>
export PK=<player-private-key>
export SETUP=<setup-address>

# Query contract addresses
cast call $SETUP "vault()(address)" --rpc-url $RPC
cast call $SETUP "oracle()(address)" --rpc-url $RPC
cast call $SETUP "tokenA()(address)" --rpc-url $RPC

# Send transactions
cast send <contract> "function(args)" --rpc-url $RPC --private-key $PK
```

## Contract Files

``` tree
src/
├── Setup.sol              # Deployment script + win condition
├── tokens/
│   ├── TokenA.sol
│   ├── TokenB.sol
│   └── TokenC.sol
├── oracle/
│   └── TWAPOracle.sol     # TWAP price oracle
├── vault/
│   └── AsyncLPVault.sol   # Async LP vault
├── lib/                   # Within the intended solution, all contracts in lib can be considered safe
│   ├── SafeTransfer.sol
│   ├── FixedPointMath.sol
│   ├── ReentrancyGuard.sol
│   ├── tokens/ERC20.sol
│   └── uniswapv2/         # UniswapV2 implementation
└── interfaces/            # Interface definitions
```
