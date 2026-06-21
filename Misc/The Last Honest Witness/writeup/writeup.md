# The Last Honest Witness Writeup

## 题目分析

挑战入口是 `Setup` 地址。`claim` 需要提交一份 Groth16 proof、5 个 public signals，以及 3 个权限 fragment。`p`、`q`、`m` 和 Merkle path 不再直接上链。

`N`、`e`、`c` 不再作为源码常量暴露，而是由 `Setup` 构造函数派生后写入 storage：

- slot `1`: `N`
- slot `2`: `e`
- slot `3`: `c`

`merkleRoot` 通过部署事件 `WitnessRoot(bytes32 indexed merkleRoot)` 的 indexed topic 公开。

ZK 电路会检查：

- `p * q == N`
- Poseidon `commitment(m)` 与公开 commitment 相同
- 由 `m/p/q` 派生出的 leaf 能通过 Poseidon Merkle path 得到公开 root
- nullifier 与同一组秘密值绑定

合约会检查：

- Groth16 proof 有效
- public signals 中的 `N/root/commitment/externalNullifier` 与链上值一致
- nullifier 未使用过
- Franklin-Reiter related-message RSA fragment
- secp256k1 小范围离散对数恢复后的 ECDSA 签名 fragment
- 40-bit truncated Keccak collision fragment

## 解题步骤

1. 从 `Setup` storage 读取 RSA 参数：

```bash
N_HEX=$(cast rpc eth_getStorageAt "$SETUP" 0x1 latest --rpc-url "$RPC")
E_HEX=$(cast rpc eth_getStorageAt "$SETUP" 0x2 latest --rpc-url "$RPC")
C_HEX=$(cast rpc eth_getStorageAt "$SETUP" 0x3 latest --rpc-url "$RPC")
```

2. 从部署日志读取 Merkle root：

```bash
TOPIC0=$(cast keccak "WitnessRoot(bytes32)")
cast rpc eth_getLogs \
  '[{"address":"'"$SETUP"'","fromBlock":"0x0","toBlock":"latest","topics":["'"$TOPIC0"'"]}]' \
  --rpc-url "$RPC"
```

返回日志的 `topics[1]` 就是 `merkleRoot`。

3. 把 `N/e/c` 转成整数，对 `N` 做 Fermat 分解。由于两个素因子很接近，从 `ceil(sqrt(N))` 开始枚举 `a`，直到 `a^2 - N` 是平方数。
4. 得到 `p = a - b`、`q = a + b`。
5. 计算 `phi = (p - 1) * (q - 1)` 和 `d = inverse(e, phi)`。
6. 恢复 `m = c^d mod N`。
7. 按附件 `poseidon_helper.js` 的公开规则生成电路输入，并确认生成的 root 与事件里的 root 一致。
8. 用附件里的 wasm/zkey 生成 Groth16 proof：

```bash
node poseidon_helper.js "$p" "$q" "$m" --input input.json
npx snarkjs groth16 fullprove input.json zk/LastHonestWitness.wasm zk/LastHonestWitness_final.zkey proof.json public.json
npx snarkjs zkey export soliditycalldata public.json proof.json
```

9. Franklin-Reiter fragment：对 `f(x)=x^3-c1` 和 `g(x)=(x+1337)^3-c2` 在 `Z_n[x]` 上求 gcd，得到 `x-m`，恢复 `franklinReiterPlaintext`。
10. ECC fragment：已知 secp256k1 公钥点和 `x < 2^20`，用 baby-step giant-step 恢复私钥 `x`，对题目给出的 `messageHash` 做 ECDSA 签名。
11. Collision fragment：生日搜索两个不同的 `a,b < 2^32`，使 `keccak256(abi.encodePacked(keccak256("LAST_HONEST_WITNESS_PAGE_C"), value))` 的低 40 bit 相同。
12. 调用：

```bash
cast send "$CHALLENGE" \
  "claim(uint256[2],uint256[2][2],uint256[2],uint256[5],uint256,uint8,bytes32,bytes32,uint256,uint256)" \
  "$PROOF_A" "$PROOF_B" "$PROOF_C" "$PUBLIC_SIGNALS" \
  "$FR_M" "$ECC_V" "$ECC_R" "$ECC_S" "$COLLISION_A" "$COLLISION_B" \
  --rpc-url "$RPC" \
  --private-key "$PK"
```

## 参考结果

```text
p = 784493436055779473
q = 784493436055795861
m = 474401937379412746004845
recipientCommitment = 9377985761090098792458769157668700179213141594497154267610801610404565099971
merkleRoot = 7732477719083212578752387109071435927399654988182031884976220637137317857940
nullifierHash = 8001422557285569920145416452913385853486935919178479204688850774075157728239
franklinReiterPlaintext = 25774616630246150697727911729
eccPrivateKey = 789123
collisionA = 1656330
collisionB = 2582757
```

完整自动化脚本见 `exp/exp.py`。
