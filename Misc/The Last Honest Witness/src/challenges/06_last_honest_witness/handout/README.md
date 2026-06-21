# The Last Honest Witness

事故发生后的第七天，委员会公开了一份很薄的档案。

档案里没有姓名。三十二位 witness 都被抹去了身份，只剩下各自交出的 commitment。它们被压进同一棵 Merkle Tree，像一份名单，也像一份不能直接宣读的证词目录。

其中有一份证词被认为最关键。委员会没有把原文放出来，只留下了一段按公开指数处理过的 ciphertext。合约也没有兴趣听任何解释。它只看一份 Groth16 proof：你是否真的找回了那份证词，是否知道它从哪个匿名 witness 来，是否能在不展开整棵树的情况下把它放回原来的位置。

奖励被分进 3 个 vault。只有 `claim(...)` 接受你的材料后，它们才会被清空。

## Public Dossier

你会拿到 `Setup` 合约地址。真正持有奖励和校验逻辑的是 `Challenge`：

```bash
cast call "$SETUP" "challenge()(address)" --rpc-url "$RPC"
```

附件里没有 `Setup.sol`。它只是部署时留下几页“公开但没人替你读”的记录。

部署后，`Setup` 的 storage 中保留了这些字段：

```text
slot 0: challenge address
slot 1: modulus N
slot 2: public exponent e
slot 3: ciphertext c
```

树根也没有写在源码里。部署交易发出过一条 indexed event：

```solidity
event WitnessRoot(bytes32 indexed merkleRoot);
```

这条日志是档案的一部分。

## Witness Notes

委员会给每份证词使用同一个外部编号：

```text
externalNullifier = 48879
```

关键 witness 留下的 commitment 是：

```text
recipientCommitment = 9377985761090098792458769157668700179213141594497154267610801610404565099971
```

`poseidon_helper.js` / `merkle_helper.py` 复原了公开的树构造规则。树上有 32 个座位，大多数座位只是空位；真正发声的 witness 只有一个。树、commitment 和 nullifier 都使用 Poseidon，domain tag 是整数 `1..6`。

附件 `zk/` 里给出了电路、wasm、zkey 和 verification key。恢复 `p`、`q`、`m` 后，可以生成电路输入和 proof：

```bash
npm install
node poseidon_helper.js "$P" "$Q" "$M" --input input.json
npx snarkjs groth16 fullprove input.json zk/LastHonestWitness.wasm zk/LastHonestWitness_final.zkey proof.json public.json
npx snarkjs zkey export soliditycalldata public.json proof.json
```

## Loose Pages

档案袋里还夹着三页看起来不相关的记录。合约会问起它们。

### Page A

```text
n = 760009694642386684565581461392043895505912502559714131532944907541093903
e = 3
delta = 1337
c1 = m^e mod n = 453597385863057272648915757216738828698620960961179478921819470254014847
c2 = (m + delta)^e mod n = 453597385865721903738147200739079200525533155295038017694987515419712854
```

### Page B

```text
pubX = 58815339488302044413775644787852249409224615099495920880759980194063649848583
pubY = 98550888334717328604002147137887649681647570376424892468560957640988111280493
messageHash = 0x99e1c9445f2a4aaed1cb39c5f061cff3410bf6faa5828abcafe330974301c838
```

这组公钥坐标来自一个不大的标量：

```text
x < 2^20
```

### Page C

```text
low40(keccak256(abi.encodePacked(keccak256("LAST_HONEST_WITNESS_PAGE_C"), a)))
==
low40(keccak256(abi.encodePacked(keccak256("LAST_HONEST_WITNESS_PAGE_C"), b)))
```

其中 `a` 和 `b` 是两个不同的整数，并且都小于 `2^32`。

## The Claim Form

```text
claim(
  uint256[2] proofA,
  uint256[2][2] proofB,
  uint256[2] proofC,
  uint256[5] publicSignals,
  uint256 pageAPlaintext,
  uint8 pageBv,
  bytes32 pageBr,
  bytes32 pageBs,
  uint256 pageCLeft,
  uint256 pageCRight
)
```

## Marginalia

- The two guardians of the modulus were born almost at the same time.
- Two nearby statements may share more than they should.
- A public key can be too small in the place that matters.
- Sometimes only the last few bytes of a seal are inspected.
- There is no hidden server state. The chain already contains what the committee was willing to publish.
