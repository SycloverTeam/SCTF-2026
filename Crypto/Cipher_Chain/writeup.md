# Curve_Link 官方题解

## 一、题目概述

本题为链式 Crypto 题，分为 Task1 和 Task2。

Task1 的输出不是 flag，而是 Task2 的种子材料。选手需要先从有限域校验矩阵中恢复隐藏向量 `h`，再用 `h` 派生密钥流解出 Task1 seed。Task2 再将该 seed 经过哈希迭代、X25519 协商和摘要派生，最终解出 flag。

题目核心不是攻击 X25519，也不是爆破哈希，而是正确还原两段密钥派生链路。

## 二、Task1 分析

附件给出素数域：

```text
P = 65537
```

以及一个矩阵 `G`，隐藏向量 `h` 满足：

```text
h_i in {-1, 0, 1}
wt(h) = 10
sum_{i=0}^{29} h_i * G_{i,k} = 0 mod P, k = 0,1,...,13
```

这里不能只把它当作普通线性方程组求零空间。由于 `G` 是 30x14，线性解空间很大；真正有用的是 `h_i in {-1,0,1}` 和 `wt(h)=10` 这两个低重量约束。

因此 Task1 可以看作有限域上的低重量码字搜索问题。

## 三、Task1 恢复 h

直接枚举所有可能的 `h` 复杂度约为：

```text
C(30,10) * 2^10
```

不可取。注意校验关系是加法形式：

```text
sum h_i * G_i = 0
```

可以使用 meet-in-the-middle。

```text
h_i^2 = 1 for ±1, 0 for 0
```
所以 sum h_i^2 = wt(h)
所以 wt(h)=10

将 30 个坐标拆成左右各 15 个。因为 `wt(h)=10`，可以枚举左边选 5 个、右边选 5 个的情况：

```text
left_sum  = sum sign_i * G_i
right_sum = sum sign_i * G_i
```

若：

```text
left_sum + right_sum = 0 mod P
```

则左右两部分拼接后得到一个满足校验矩阵的低重量向量。

每边枚举规模约为：

```text
C(15,5) * 2^5 = 96096
```

可以轻松完成。

需要注意：如果 `h` 满足校验方程，那么 `-h` 也满足校验方程。附件中的 `seed_sha256_prefix` 用于确认最终方向是否正确。

## 四、Task1 解密 seed

恢复 `h` 后，按照附件规则派生密钥流：

```text
material = b"Curve_Link_Task1_Hard|P=65537|w=10|h=" + b",".join(str(h_i).encode() for h_i in h)
stream = SHA256(material || uint32_be(0)) || SHA256(material || uint32_be(1)) || ...
```

然后：

```text
seed = ciphertext XOR stream[:len(ciphertext)]
```

得到：

```text
aGFjyHX1aWdadade
```

该字符串即 Task2 的输入材料。

## 五、Task2 trace 推导

Task2 附件包含：

```text
task2.pub
task2.enc
task2.log
task2.trace
```

其中 trace 给出工程侧记录：

```text

role = client
peer_key_len = 32
secret_stage = compress(seed)
burn_counter = 0xc350
exchange = montgomery25519
check = 32d39782e415b6b2
payload_mode = stream-mask
```

逐项分析：

`secret_stage = compress(seed)` 表示 Task1 seed 需要先进行摘要压缩。结合后续摘要校验，使用 SHA256。

`burn_counter = 0xc350`，换算为十进制是：

```text
50000
```

因此私钥材料为：

```text
sk = SHA256(seed)
repeat 50000 times:
    sk = SHA256(sk)
```

`peer_key_len = 32` 和 `exchange = montgomery25519` 指向标准 X25519。`task2.pub` 为对端 32 字节公钥：

```text
shared = X25519(sk, task2.pub)
```

`check` 与 `task2.log` 中的 `session_prefix` 对应。计算：

```text
k1 = SHA256(shared)
```

应满足：

```text
k1[:8].hex() == "32d39782e415b6b2"
```

这一步用于验证 Task1 seed、50000 轮迭代和 X25519 协商是否全部正确。

最后 `payload_mode = stream-mask` 表示密文由字节流掩码得到。根据链路继续派生：

```text
k2 = SHA256(k1)
flag = task2.enc XOR repeat(k2)
```

即可得到最终 flag。

## 六、参考解题代码片段

Task1 的完整参考脚本见：

```text
exp/exptask1.py
```

核心流程如下：

```python
left_table = {}

for left_sum, left_part in enumerate_signed_weight_5(left_rows):
    left_table[left_sum].append(left_part)

for right_sum, right_part in enumerate_signed_weight_5(right_rows):
    target = -right_sum mod P
    if target in left_table:
        h = merge(left_part, right_part)
```

随后使用恢复出的 `h` 解出 Task1 seed，再进入 Task2。

Task2 解密逻辑：

```python
seed = b"aGFjyHX1aWdadade"

sk = sha256(seed).digest()
for _ in range(0xc350):
    sk = sha256(sk).digest()

shared = X25519(sk, task2_pub)
k1 = sha256(shared).digest()
assert k1[:8].hex() == "32d39782e415b6b2"

k2 = sha256(k1).digest()
flag = xor(task2_enc, k2)
```

## 七、考点总结

1. 有限域 GF(65537) 运算；
2. 校验矩阵与低重量码字；
3. meet-in-the-middle 搜索；
4. SHA256 计数器模式密钥流；
5. 哈希迭代 KDF；
6. 标准 X25519 协商；
7. 摘要前缀校验；
8. 字节流异或解密。

本题中 X25519 为标准实现，无曲线漏洞。Task2 的 `log` 只用于验证中间状态，不能绕过 Task1。
