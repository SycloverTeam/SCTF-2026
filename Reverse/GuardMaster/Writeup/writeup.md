# GuardMaster Reverse Writeup

## 总体

完整链路如下：

1. 从 APK 读取公开 `classes.dex`、`assets/guard.gmx`、native so。
2. 公开 Java loader 的 `C0002.<clinit>` 初始化 64 字节 key；`C0002.m14` 将公开 `classes.dex` 与 `assets/guard.gmx` 拼接后传入 `C0007.m59`。
3. `C0007.m59` 在拼接数据中寻找 `GMX1`，校验 header，解记录表，解 metadata，定位真实 DEX 记录，按 transform flags 逆向处理 body，再用 manifest 中的 front 信息恢复完整 hidden dex。
4. hidden dex 中的反射入口是 `gm.core.Dispatcher.check(String)`。JADX 对入口和核心状态函数大多跳过，因此以 DEX method index、code offset、descriptor、调用目标和动态 trace 给方法建立分析别名。
5. `Dispatcher.check` 构造 `C0000` 状态，经过 C0001/C0002/C0003 和 native bridge 混合，最终由 `C0000.m24` 输出 184 字节 final packet，交给 native `finalizeCheck`。
6. native `finalizeCheck` 检查 seed、检查目标密文 CRC，将 184 字节 packet 补 8 字节扩展为 192 字节，对三个 64 字节块做多层可逆编码，最后与目标密文比较。
7. 先反转 native 192 字节编码，得到唯一 final packet；再从 packet 中取出 Java 最终 `f8` 状态，按 hidden Java 的 77 个 `f8` 相关操作倒序还原出 constructor 初始 64 字节 normalized bytes。
8. 对候选 bytes 执行 Java 等价 normalization，确认稳定；再正向重放 77 个 `f8` 操作，确认回到 packet 中的最终 `f8` 状态。

## 公开 Java Loader 定位

公开 dex 中能直接看到加载逻辑：`C0002` 将一个 byte array 传给 `InMemoryDexClassLoader`，再通过反射取 `gm.core.Dispatcher.check(String)`。关键定位点如下：

| 逻辑 | DEX 方法 / code offset | 证据 |
|---|---:|---|
| loader 静态初始化 | `C0002.<clinit>`，`0x672d0` | PC `0x2c4c` 调 `m15`，PC `0x2ec0` 写 `f14` |
| key 生成 | `C0002.m15`，`0x87b1c` | PC `0x62e` 分配 byte array，PC `0x1084` 调 `m18(i)`，PC `0x12a0` 写字节 |
| 单字节 key 公式 | `C0002.m18`，`0x8b168` | PC `0x1422` 读 `f11`，PC `0x19d0` 调 `m8`，PC `0x1fba` 调 `Integer.rotateRight` |
| native loader seed | `C0002.m22`，`0x9090c` | 初始常量 PC `0x2e8`，读 `f14` PC `0x50a`，逐字节混合至 PC `0x2616` |
| 字符串表 | `C0002.m19`，`0x8e30c` | PC `0x2d0` 创建 String，PC `0x59a` 生成 bytes，PC `0xb66` 调 String 构造 |
| 读取公开 dex | `C0002.m9`，`0x7bf68` | PC `0x51c` 调 `m19(4)` 得到 `classes.dex` |
| 读取 GMX | `C0002.m14`，`0x84f60` | PC `0x7ee` 调 `m19(63)` 得到 `assets/guard.gmx`，随后拼接 |
| ZipEntry 读取 | `C0002.m20`，`0x8f164` | PC `0x598` 取 APK path，PC `0x786` 取 entry，PC `0x806` 读取全部 bytes |

### 64 字节 loader key

`m15` 对 `i = 0..63` 调用 `m18(i)`。`m18` 等价公式为：

```python
idx = (i * 37 + 11) & 63
shift = ((idx ^ i) & 7) + 1
value = f11[idx] ^ m8(idx, i)
value = rotate_right_32(value, shift)
byte = (value - ((i + 5) * 257 + idx * 17)) & 0xff
```

得到的 64 字节 key 为 ASCII 十六进制串：

```text
0b3a744e955c6108c164d49cd5a5c94b8bc44da9c262c5b074d0b27bebbe0b0d
```

十六进制字节：

```text
30623361373434653935356336313038633136346434396364356135633934623862633434646139633236326335623037346430623237626562626530623064
```

### loader seed

`m22` 以常量 `0x47584d3153454544` 初始化，对 key 的每个字节执行：

```python
value ^= byte & 0xff
value *= -7046029254386353131
value = rotate_left_64(value, 7)
```

最终 seed 为：

```text
u64 = 0x4ba8fabf42fccdbe
signed = 5451883048301546942
```

Exp 中没有把 key 或 seed 作为最终常量写死：key 由公开 dex 的 `C0002.<clinit>` 和 `m15` 现场执行得到，seed 再由上述公式现场派生。

### 字符串表关键项

`m19` 是 loader 的字符串表。关键项如下：

| index | value | 用途 |
|---:|---|---|
| 1 | `check` | 反射方法名 |
| 3 | `gm.core.Dispatcher` | hidden dex 入口类 |
| 4 | `classes.dex` | 从 APK 中读取公开 dex |
| 6 | `dex
` | DEX magic |
| 8 | `GMX1` | GMX magic |
| 11 | `gmx1-root` | GMX root key label |
| 14 | `header-mac` | GMX header MAC label |
| 28 | `record-key` | GMX record key label |
| 48 | `:xor` | GMX transform label |
| 49 | `:rc4-key` | GMX transform label |
| 50 | `:sm4-prefix` | GMX transform label |
| 51 | `:wb` | GMX transform label |
| 52 | `real-dex` | manifest 真实 DEX 名称 |
| 53 | `decoy-dex` | manifest decoy 名称 |
| 54 | `metadata` | metadata 记录名 |
| 55 | `vm-table` | VM 表记录名 |
| 56 | `string-table` | 字符串表记录名 |
| 63 | `assets/guard.gmx` | GMX 资源 |

由 `m9/m14/m20` 的 PC 可确认传给 `C0007.m59` 的 payload 是：

```text
公开 classes.dex || assets/guard.gmx
```

## GMX1 容器与 Hidden Dex 恢复

`C0007.m59` 是 GMX 解包入口，method index `86`，code offset `0x15ba68`。它先判断输入是否已经以 `dex
` 开头，若不是则搜索 `GMX1`，切出 GMX 容器后继续解析。

主要方法映射如下：

| 用途 | method index | code offset |
|---|---:|---:|
| GMX 入口 `m59` | 86 | `0x15ba68` |
| header parser | 66 | `0xc7be8` |
| record/index parser | 73 | `0xfe048` |
| metadata JSON parser | 81 | `0x144118` |
| record decrypt | 84 | `0x150924` |
| final assembler | 69 | `0xe1f30` |
| transform dispatcher | 58 | `0xa5628` |
| constant provider | 59 | `0xa8610` |
| BLAKE2s | 60 | `0xa8b80` |
| KDF | 64 | `0xb7954` |
| Inflater | 72 | `0xfbc40` |

### Header

实际 payload 中 `GMX1` 位于偏移 `1499596`，即公开 `classes.dex` 之后。GMX header 解析结果：

```text
gmx_size = 420778
header_size = 68
index_start = 68
index_len = 336
index_end = 404
first_record_payload = 564
root_key = d1f65a962706918cf50716163c3675f1a7d8c2b6d0c778ceb952144dd0b60fd4
```

header 对象字段：

| 字段 | 值 | 含义 |
|---|---:|---|
| `f1` | 404 | descriptor/index end |
| `f2` | 336 | descriptor/index length |
| `f3` | 415130 | metadata payload offset |
| `f4` | -816599631 | header check field |
| `f5` | `45603e62a09f1a01fbd381a753528e3c` | 16 字节 header key |
| `f6` | 5 | record count |
| `f7` | 5640 | metadata 输入长度 |

header MAC 公式：

```python
KDF(b"header-mac", 16, root_key, gmx[0:52]) == gmx[52:68]
```

实际 MAC：

```text
692fc29a257953b33cb6f31dc6529da2
```

### Record descriptors

记录表由 method #73 解析。真实 DEX 记录由类型 `-744419327` 与 metadata manifest 中的 `order_id=1` 共同定位。

| type | flags | offset | input_len | output_len | order_id | front_size | crc32 signed | 含义 |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| -744419327 | 63 | 564 | 414390 | 1698548 | 1 | 4096 | 79693012 | real-dex |
| -744401331 | 26 | 414954 | 96 | 96 | 22016 | 0 | 832448354 | vm-table |
| -744401070 | 26 | 415050 | 80 | 80 | 22272 | 0 | -674958025 | string-table |
| -744380512 | 7 | 415130 | 5640 | 9792 | 42912 | 0 | -1634667776 | metadata |
| -744369983 | 63 | 420770 | 8 | 0 | 27905 | 156 | 115420804 | decoy-dex |

### GMX KDF 与 transform

GMX KDF：

```python
def KDF(seed, out_len, *parts):
    buf = seed
    for part in parts:
        buf += le32(len(part)) + part
    return BLAKE2s(buf, digest_size=out_len)

def stream(seed, key, out_len):
    return KDF(seed, 32, key, le32(counter)) blocks
```

record key：

```python
record_key = KDF(
    b"record-key",
    32,
    root_key,
    header_key,
    le32(order_id) + le32(record_type),
)
```

Transform flags 的执行顺序由 dispatcher method #58 的分支顺序确定：

1. bit 16: WB
2. bit 8: SM4-prefix
3. bit 4: RC4
4. bit 2: XOR
5. bit 1: Inflater

各层公式：

```python
# XOR
s = stream(context + b":xor", key, len(data))
out[i] = data[i] ^ s[i] ^ (((i * 17) + s[i >> 1]) & 0xff)

# WB
s = stream(context + b":wb", key, len(data))
v = (data[i] - s[i] - (i * 19)) & 0xff
shift = (s[i] ^ (i * 11)) & 7
out[i] = ror8(v, shift)

# SM4-prefix
prefix_len = min(len(data), 96)
s = stream(context + b":sm4-prefix", key, prefix_len)
state = s[0]
for i in range(prefix_len):
    state = rol8(state, 1) ^ (s[i] ^ ((i * 61) & 0xff))
    out[i] = data[i] ^ state
# prefix 之后的字节不变

# RC4
rc4_key = stream(context + b":rc4-key", key, 48)
KSA:  j = (j + S[i] + rc4_key[i % 48] + ((i * 13) & 255)) & 255
PRGA: j = (j + S[i] + (pos & 7)) & 255
      k = S[(S[i] + S[j] + rc4_key[pos % 48]) & 255]
      out[pos] = data[pos] ^ k

# Inflater
Java zlib Inflater stream
```

### Manifest 与 DEX front 恢复

metadata 记录解出后是 JSON。真实 DEX 的 manifest 信息包括：

```text
order_id = 1
front_size = 4096
dex_size = 1702644
dex_sha256 = 91a82e748e24b30c9f37331d8a420407380f598037ebe5133872dc0640f7fef4
dex_sha1 = 928ca4b96feab4268e23cb7463e614038e60785d
dex_adler32 = 73d8e03e
body_hash = c899d2608f7632ec227770330121d184aa1e2cc8b8c6840e29d96dca4ab34f3d7
front_hash = 3fca411eb5d277e62fd5a4f99ee7f06f641e361030cba8af4fb4f9869c8d712a
mask_seed = f4d425ecf81f05fb667356051c057a18
```

front 还原公式来自 final assembler method #69 调用的 front unmask helper：

```python
front_stream = BLAKE2s(mask_seed + le32(counter), 32) blocks
front_plain[i] = front_cipher[i] ^ front_stream[i] ^ (((i * 29) + len(front_cipher)) & 0xff)
```

最终 DEX 由 `front_plain || body_plain` 拼接，再依次校验：DEX magic、header Adler32、header SHA-1、manifest SHA-256。恢复出的 hidden dex SHA-256 为：

```text
91a82e748e24b30c9f37331d8a420407380f598037ebe5133872dc0640f7fef4
```

## Hidden Dex 命名与入口恢复

hidden dex 中类名和方法名经过混淆，多个核心方法无法由 JADX 直接反编译。这里没有修改 dex 本身，也没有声称恢复原始符号名；所有可读名称都是分析别名。别名建立规则如下：

1. 公开 loader 的字符串表给出反射入口类名 `gm.core.Dispatcher` 和方法名 `check`，所以 hidden dex method index `7`、code offset `0x64bb4`、descriptor `(Ljava/lang/String;)Z` 被命名为 `Dispatcher.check`。
2. 对 `Dispatcher.check` 做 DEX bytecode disassembly，读取所有 invoke 目标。被调用的 C0001 method #62..#66 再按其调用的 `GuardJni` 方法命名为 final wrapper、step wrapper、commit wrapper、bootstrap wrapper、pull wrapper。
3. C0003 method #81..#85 按其构造或解析的 packet 命名，例如 `m68` 构造 48 字节 BSTP，`m70` 构造 variable JSTEP，`m67` 构造 40 字节 commit packet，`m69` 解析 native 12 字节回复。
4. C0000 的字段角色由两部分确定：一是 getters/setters 与 wrappers 使用方式，二是 `m10` serializer 的 sentinel 对象测试。通过给每个字段放入唯一 sentinel，再执行 `m10` 和 `m22^-1`，定位 raw serializer 中每个字段的偏移。
5. C0000 的核心方法按 code offset 和实际行为命名，例如 `0xc0398` 是中心 64 字节可逆混合，命名为 `m11_state_mix`；`0x124a74` 在嵌套 `m11` 前还有 28 轮直接 `f8` 写入，命名为 `m40_token_round_mix`。

### Dispatcher.check 调用序列

入口 method index `7`，code offset `0x64bb4`。关键 bytecode 调用顺序：

| bytecode offset | 调用 | 作用 |
|---:|---|---|
| `0x05ea` | new `C0000(input)` | 构造 Java 状态 |
| `0x0b1a` | new `C0002()` | 构造表/轮 helper |
| `0x0e30` | `C0001.m54(state)` | native run/bootstrap |
| `0x12f8` | `state.m35()` | visible loop 条件 |
| `0x2774` | `C0002.m63(state)` | visible round selector |
| `0x2c32` | `C0002.m64(state)` | visible state feed |
| `0x31a2` | `state.m32()` | 导出 step payload |
| `0x3562` | `C0001.m52(state,payload)` | native step |
| `0x3830` | `state.m34(long)` | 混入 native step 返回 long |
| `0x3e7a` | `C0002.m65(state)` | 计算 pull index |
| `0x414c` | `C0001.m55(state,index)` | native rp/pull |
| `0x4384` | `C0002.m62(buffer,state,index)` | 合并 pull material |
| `0x58b2` | `C0001.m53(state,int)` | native commit |
| `0x5e0c` | `C0001.m51(state)` | native finalizeCheck probe |
| `0x65f2` | `state.m45(boolean)` | final stage boolean mix |
| `0x6eb4` | `state.m32()` | 再次导出 payload |
| `0x7094` | `C0002.m61(state,bytes)` | Java payload transform |
| `0x7f62` | `C0001.m53(state,int)` | commit loop |
| `0x99ee` | `state.m25(0x4c4f4f50)` | final loop signal |
| `0xa35c` | `C0001.m53(state,int)` | final commit |
| `0xa802` | `C0001.m51(state)` | final finalizeCheck fallback |
| `0xb3b8` | `state.m33()` | 返回 boolean |

### C0001 wrapper 到 JNI 的映射

| wrapper | method index / code offset | packet/helper | JNI 目标 |
|---|---|---|---|
| `m54(C0000)` | #65 / `0x14cadc` | `C0003.m68(state)` | `GuardJni.run([B)[B` |
| `m52(C0000, byte[])` | #63 / `0x14afc8` | `C0003.m70` + `C0003.m69` | `GuardJni.step([B)[B` |
| `m55(C0000,int)` | #66 / `0x14d724` | 直接参数 | `GuardJni.rp(I,I)` 或 `GuardJni.pull(I,I)` |
| `m53(C0000,int)` | #64 / `0x14be5c` | `C0003.m67(state,int)` | `GuardJni.commit([B)Z` |
| `m51(C0000)` | #62 / `0x149594` | `C0000.m24()` | `GuardJni.finalizeCheck([B)Z` |

### 输入 normalization

`C0000.m0`，code offset `0x82330`，对 Java String 做：

```java
Normalizer.normalize(input, Normalizer.Form.NFKC)
    .trim()
    .replace("
", "")
    .replace("
", "")
    .getBytes(StandardCharsets.UTF_8)
```

bytecode 锚点：

| 操作 | bytecode offset |
|---|---:|
| `Normalizer$Form.NFKC` | `0x1076` |
| `Normalizer.normalize` | `0x1312` |
| `String.trim()` | `0x1544` |
| 第一次 `replace` | `0x1c36` |
| 第二次 `replace` | `0x223a` |
| `StandardCharsets.UTF_8` | `0x25b8` |
| `String.getBytes(UTF_8)` | `0x2842` |

constructor 对 normalized bytes 的处理：前 64 字节直接放入 `f8`；不足 64 字节时用 `m21(1346454578, i)` 补齐；同时 `m1` 将 normalized bytes 切成 4 个 chunk，并用 `m6_digest32(chunk, 1196576816+i)` 填入 `f11`。本题最终候选正好是 64 字节，因此 constructor 的 `f8` 初值就是 normalized bytes。

## Native finalizeCheck

native so 的关键 JNI 入口：

| JNI | 地址 | 作用 |
|---|---:|---|
| `commit([B)Z` | `0x3841a88` | 处理 commit packet，推进 native state |
| `finalizeCheck([B)Z` | `0x3841b44` | 处理 184 字节 final packet |
| finalize core | `0x3845df4` | seed/CRC/target compare 核心 |
| expand+encode | `0x3846220` | 184 -> 192 并编码 |
| per-block encode | `0x3847108` | 64 字节块编码 |

### Native 静态常量

| 地址 | 大小 | 用途 |
|---:|---:|---|
| `0x40800` | 192 | 目标密文 |
| `0x408c0` | 64 | target seed material |
| `0x40900` | 64 | seed/table |
| `0x40940` | 4 | 目标密文 CRC |

目标密文 CRC dword：

```text
bytes = b1 59 bb 70
value = 0x70bb59b1
```

### Native helper

CRC-like checksum `sub_380f9f8`：

```python
v = seed ^ 0xA53C5A5C
for i, b in enumerate(data):
    x = v ^ (b << (8 * (i & 3)))
    for _ in range(8):
        x = ((-(x & 1) & 0x82F63B78) ^ (x >> 1)) & 0xffffffff
    v = rol32(x, 5)
return v ^ 0x5C3AC3A5
```

KDF `sub_380ff74`：

```text
SHA256(label || 00 || le32(context_len) || context || le32(counter))
```

counter 从 1 开始，连续拼接到需要的输出长度。

SplitMix-style 64-bit finalizer `sub_38279e4`：

```python
x = 0xBF58476D1CE4E5B9 * (x ^ (x >> 30))
x = 0x94D049BB133111EB * (x ^ (x >> 27))
return x ^ (x >> 31)
```

### 184 字节 packet 到 192 字节 expanded

`finalizeCheck` 要求输入长度 184，`u32[0] == 1`，`u32[4] == 8`，并检查 native state 阶段、commit count、flags 等。之后检查：

```python
KDF("GM-FINAL-TARGET-SEED", bytes_408c0 + b"", 64) == byte_40900
native_crc(target_ciphertext, 0x46494e31) == 0x70bb59b1
```

`sub_3846220(final_packet, 184, out192)` 的扩展逻辑：

```python
expanded = bytearray(192)
expanded[:184] = final_packet
pad_context = final_packet + byte_40900 + le32(184)
expanded[184:192] = KDF("GM-FINAL-PACKET-PAD", pad_context, 8)
```

反推得到的 padding：

```text
ec500d0194a6c546
```

### 每个 64 字节块的 native 编码层

正向编码顺序：

1. 初始逐字节 xor/rotl 层
2. stream layer phase 0
3. VM/whitebox layer phase 0
4. stream layer phase 1
5. 16 轮 Feistel
6. stream layer phase 2
7. VM/whitebox layer phase 1
8. stream layer phase 3
9. final 逐字节 xor/rotl/add 层

Exp 中按完全相反顺序反转。native 依赖的大表由 Unicorn/LIEF 调用本 so 中的固定 helper 现场生成：

| helper | 地址 | 用途 |
|---|---:|---|
| `sub_38484d4` | `0x38484d4` | stream context 生成 |
| `sub_3848f94` | `0x3848f94` | SM4 风格 16 字节 core |
| `sub_3849480` | `0x3849480` | VM material 生成 |
| `sub_380d31c` | `0x380d31c` | whitebox descriptor 生成 |
| `sub_380d948` | `0x380d948` | whitebox transform/decrypt primitive |
| `sub_3848340` | `0x3848340` | Feistel round material |
| `sub_3846220` | `0x3846220` | native 正向最终验证 |

初始 byte layer 正向：

```python
for i in range(64):
    k = T[(13*i + 19*block + 7) & 0x3f] ^ (17*i + 61*block - 91)
    b[i] = rotl8(b[i] ^ k, T[(i + 11*block) & 0x3f] + i + block)
```

final byte layer 正向：

```python
for n in range(64):
    k = T[(11*n - block + 8*block + 9) & 0x3f] ^ (23*n + 107*block + 61)
    b[n] = rotl8(b[n] ^ k, k ^ n ^ block) + k
```

Feistel 第 `j` 轮正向：

```python
right = b[32:64]
rk32 = round_material(right, j, (j | (block << 32)) ^ 0x46494E5245563031)
tmp[0:32] = right
for k in range(32):
    m = rotl8(T[(k - j + 8*j) & 0x3f], j + k)
    tmp[32+k] = b[k] ^ rk32[k] ^ m
for n in range(64):
    q = T[(5*n + j + 13*block) & 0x3f] ^ (29*j + n + 81*block)
    b[n] = rotl8(tmp[n] + q, q >> 4)
```

反向时 `j=15..0`，先 undo rotate/add 得到 tmp，再由 old right 重新派生 round material，恢复 old left。

反推 native 后得到 184 字节 final packet：

```text
01000000080000004f1d5b683e422cc4bf241cb256782dbb905a30775b3128da
72ea983155310ea63b3ca4a8f158ebde11a829cfb9baf9a1598b70893365c2dc
369668dc8f900b97a39eb91609e7a8f28cb6a519c5fc54cb266764a89c511a90
a9f90ebafb586204f9689f46476ee2be7ee30163ea12cf1197bbbd97a1ebab6b
1ddf1103bdac95ffd00fc3ae1d3182b36e2e3ace2a6fb84670f177f30bf1e6b
ac88611798b96cb655f20ee616a1b90eb056e21be01106896
```

## Final Packet 与 Java 状态

`C0000.m24`，code offset `0xff004`，构造 184 字节 little-endian `ByteBuffer`。packet 结构：

| offset | size | 内容 |
|---:|---:|---|
| `0x00` | 4 | version = 1 |
| `0x04` | 4 | command / `f14` = 8 |
| `0x08` | 112 | `m22(m10_raw_state, f14)` |
| `0x78` | 64 | 直接写入的最终 `f8` |

packet 中最终 `f8` 为：

```text
97bbbd97a1ebab6b1ddf1103bdac95ffd00fc3ae1d3182b36e2e3ace2a6fb84670f177f30bf1e6bac88611798b96cb655f20ee616a1b90eb056e21be01106896
```

`m22` wrapper 正向：

```python
key1 = m9(len(data), 0x4648445a)
for i:
    data[i] = m4((data[i] ^ key1[i]) & 0xff, key1[(5 + 7*i) % n] + i)

data = m8(data, False)

key2 = m9(len(data), 0x750c0109)
for i:
    data[i] = m4((data[i] + key2[i] + 19*i) & 0xff, key2[(3 + 11*i) % n] ^ i)
```

逆向顺序为：逆第二次 `m4`，`m8(data, True)`，逆第一次 `m4`。raw serializer `m10` 的 112 字节布局由 sentinel 测试确认：

| raw offset | size | 字段 | final 值 |
|---:|---:|---|---|
| 0 | 64 | `f8` | 与 packet `0x78..0xb8` 相同 |
| 64 | 4 | `f6` | `0x23e7bf9e` |
| 68 | 4 | `f15` | `0x13572468` |
| 72 | 4 | `f19` | `0xf5f8ba21` |
| 76 | 4 | `f21` | `0x02e09389` |
| 80 | 4 | `f7` | `8` |
| 84 | 4 | `f23` | `0xa0135d40` |
| 88 | 8 | `f17` | `0x3f693cb8830b3d9c` |
| 96 | 8 | `f20` | `0xee14e51cf6212231` |
| 104 | 8 | `f13` | `0x9852f000c92ffd6e` |

## C0000 可逆状态

核心 `f8` 状态是 64 字节，主要由 `m11_state_mix`、`m13_state_permute` 和 `m40_token_round_mix` 的前置段修改。

### m11_state_mix

方法 code offset `0xc0398`，descriptor `(II)V`。它读取当前 `f14/f22/f7`，只修改 `f8`。初始 key：

```python
key0 = m21(arg0 ^ arg1, f14 ^ (f22 << 8) ^ (f7 << 16))
```

每轮 `r=0..2`：

```python
for i in range(32):
    ks1 = m17(key0, r, i)
    sub = m4((f8[32+i] + ks1) & 0xff, ks1 >> 5)
    ks2 = m17(key0 ^ 0x5a17c3e1, r, 31-i)
    f8[i] ^= sub ^ ks2
swap halves
m13(key0 ^ (0x6d2b79f5 * r))
```

逆向需要正向调用时的 `arg0/arg1/f14/f22/f7`，倒序执行 `m13^-1`、swap、xor 恢复。

### m13_state_permute

方法 code offset `0xcd90c`，descriptor `(I)V`。正向：

```python
for i in range(64):
    src = (seed - 7*i) & 63
    ks = m17(seed, 3, i)
    out[i] = m4(input[src] ^ ks, ks >> 3)
```

逆向对每个输出 index 使用 `m4^-1` 后写回 `src`。

### m40_token_round_mix 的前置 f8 变换

方法 code offset `0x124a74`。它在嵌套调用 `m11` 前还有 28 轮直接 `f8` 写入。关键 PC：

| PC | 行为 |
|---:|---|
| `0x3928` | 前置 `f8` 读，`aget-byte` |
| `0x4f60` | 前置 `f8` 写，`aput-byte` |
| `0xe114` | 嵌套 `m11` 调用 |

前置 28 轮公式：

```python
base = m2(arg0, arg1)
chain = m7(arg0, arg1)
for i in range(28):
    mix = m3(arg0, arg1, i, chain) & 0xff
    chain_key = arg0 ^ arg1 ^ mix ^ i
    chain = m21(chain, chain_key)
    idx = (chain + base + 17*i) & 63
    mask = m17(chain ^ base, i & 3, idx) & 0xff
    tmp = f8[idx] ^ mix ^ mask
    key = base ^ mask ^ i
    f8[idx] = rol8(tmp, key & 7)
```

逆向必须按 `i=27..0`：

```python
tmp = ror8(f8[idx], key & 7)
f8[idx] = tmp ^ mix ^ mask
```

这个前置段是最终恢复输入的关键点。只反转 `m40` 里的嵌套 `m11` 会得到一个能被错误模型自洽重放的值，但不能通过真实 forward replay。

## Dispatcher 的 77 行 f8 调度

用 64 字节固定 ASCII 测试输入执行 hidden dex 的 `Dispatcher.check`，native bridge 返回保持 Java 有效路径的 12 字节回复和 64 字节 pull material，动态捕获所有进入 `m11` 的行。该调度与实际输入内容无关；它由 fixed round count、固定 wrapper 调用顺序、固定 native status 路径和固定 pull 次数决定。

总行数为 77，其中 `m40` wrapper 行 26 个。开头三行：

| i | caller | arg0 | arg1 | f14 | f22 | f7 | m40 entry |
|---:|---|---:|---:|---:|---:|---:|---|
| 0 | constructor init | `0x494e4954` | `64` | 0 | 0 | 0 | - |
| 1 | bootstrap return mix | `0x42535450` | `0` | 0 | 0 | 0 | - |
| 2 | m40 bootstrap | `0x4f769386` | `0xa9bda034` | 0 | 0 | 0 | `BSTP,0` |

随后 8 轮，每轮固定模式：

```text
m37 -> m11(NORM,16)
m40(PULL,i) -> pre-m40 f8 + nested m11
m39 -> m11(PULL,i+1)
m47 -> m11(PERM,16)
m25 -> m11(DIG1,3)
m40(STEP,i) -> pre-m40 f8 + nested m11
m34 -> m11(STEP,4)
m40(COMM,i) -> pre-m40 f8 + nested m11
m49(true) -> m11(COMM,i+1)
```

最后两行：

| i | caller | arg0 | arg1 | f14 | f22 | f7 | m40 entry |
|---:|---|---:|---:|---:|---:|---:|---|
| 75 | final permute | `0x46494e31` | `8` | 8 | 6 | 8 | - |
| 76 | final commit m40 | `0xfb19ec69` | `0x8e4c5a95` | 8 | 6 | 8 | `COMM,8` |

`m40` 参数表：

| entry | nested arg0 | nested arg1 |
|---|---:|---:|
| `BSTP,0` | `0x4f769386` | `0xa9bda034` |
| `PULL,0` | `0x97b8f05d` | `0xd6f27f83` |
| `PULL,1` | `0xc568010d` | `0x1389826a` |
| `PULL,2` | `0x71c7dd22` | `0x61005985` |
| `PULL,3` | `0xa088a9ed` | `0x1d690008` |
| `PULL,4` | `0xd3662283` | `0x60a48e9c` |
| `PULL,5` | `0x02174c72` | `0x7aafd275` |
| `PULL,6` | `0x8e86b863` | `0x25b8e119` |
| `PULL,7` | `0xfdb66ed3` | `0xf44b74d8` |
| `STEP,0` | `0xe444b15c` | `0xb332ca1f` |
| `STEP,1` | `0xdb7468ec` | `0x4f269682` |
| `STEP,2` | `0x47e3ddfb` | `0x5e982e64` |
| `STEP,3` | `0xb6934e0b` | `0xc97c69f2` |
| `STEP,4` | `0xa885639d` | `0x24c7f9fd` |
| `STEP,5` | `0x9fb6b62e` | `0xc0434770` |
| `STEP,6` | `0x0a251a3d` | `0x2d2e7286` |
| `STEP,7` | `0x79d5174d` | `0xdcdf5fb8` |
| `COMM,0` | `0x4d85a6f5` | `0x7b5524e5` |
| `COMM,1` | `0x1ed59025` | `0x35e21cf7` |
| `COMM,2` | `0x2f251f55` | `0x73353760` |
| `COMM,3` | `0xf8742b84` | `0x54ebef79` |
| `COMM,4` | `0x8944fc34` | `0xf90b0d15` |
| `COMM,5` | `0x5b944364` | `0x250d37bc` |
| `COMM,6` | `0x64e3de93` | `0x6e78a09d` |
| `COMM,7` | `0x353368c3` | `0xa239879e` |
| `COMM,8` | `0xfb19ec69` | `0x8e4c5a95` |

倒序处理这 77 行：

1. 对普通 `m11` 行直接执行 `m11^-1`。
2. 对 `m40` 行先执行嵌套 `m11^-1`，再执行 `m40` 前置 28 轮直接 `f8` 变换的逆。
3. 最后一行逆到 constructor pre-INIT 后，得到 64 字节 normalized bytes。
4. 对候选做 Java 等价 normalization，确认 bytes 不变。
5. 正向重放同一 77 行，确认回到 packet 中的最终 `f8`。

得到候选 bytes：

```text
534354467b325e692d42427623486b40762c73566b37652b2973417044663435325f63526f78316975704a684b6f527a51795f524c755f5445302d6e25676e7d
```

ASCII 即最终输入：

```text
SCTF{2^i-BBv#Hk@v,sVk7e+)sApDf452_cRox1iupJhKoRzQy_RLu_TE0-n%gn}
```
##  Exp

```python
#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import sys
import types
import zipfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
APK_PATH = SCRIPT_DIR / "GuardMaster-FinalVer.apk"
WORK = SCRIPT_DIR / "_generated"
OUT_FLAG = SCRIPT_DIR / "flag.txt"
DUMMY_INPUT = "A" * 64
FIELD_ALIASES = {0: 'f6x6868a7e9', 1: 'f7', 2: 'f8xa5a7934', 3: 'f0xa03bd8d1', 4: 'f9x7ea3f6dd', 5: 'f10x7fc29877', 6: 'f11x99d9d52c', 7: 'f12x978d0ca3', 8: 'f1x50b6db62', 9: 'f2x552af10a', 10: 'f3xef540ca4', 11: 'f13xcb34ab73', 12: 'f14x69ab180b', 13: 'f15xbab9595e', 14: 'f4', 15: 'f16x11cdf272', 16: 'f17xc24bec61', 17: 'f18x8da453fc', 18: 'f5', 19: 'f19xe71db4e0', 20: 'f20xb9c11465', 21: 'f21x843c54e2', 22: 'f22x73e78f8b', 23: 'f23xf2ae566b'}

def derive_loader_m22_seed(loader_key: bytes) -> int:
    value = 0x47584D3153454544
    for byte in loader_key:
        value ^= byte & 0xFF
        value = (value * (-7046029254386353131)) & 0xFFFFFFFFFFFFFFFF
        value = ((value << 7) | (value >> 57)) & 0xFFFFFFFFFFFFFFFF
    return value

def build_recover_gmx_module(classes_path: Path, gmx_path: Path, recovered_path: Path) -> types.ModuleType:
    _module_name = "recover_gmx"
    import hashlib
    import json
    import struct
    import zlib
    from pathlib import Path


    def uleb(data, off):
        out = 0
        shift = 0
        while True:
            b = data[off]
            off += 1
            out |= (b & 0x7F) << shift
            if b < 0x80:
                return out, off
            shift += 7


    def sleb(data, off):
        out = 0
        shift = 0
        size = 32
        while True:
            b = data[off]
            off += 1
            out |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                if (shift < size) and (b & 0x40):
                    out |= -(1 << shift)
                return out, off


    def read_mutf8(data, off):
        _, off = uleb(data, off)
        end = data.index(0, off)
        raw = data[off:end].replace(b"\xc0\x80", b"\x00")
        return raw.decode("utf-8", errors="surrogatepass").encode(
            "utf-16", "surrogatepass"
        ).decode("utf-16")


    def i32(x):
        x &= 0xFFFFFFFF
        return x - 0x100000000 if x & 0x80000000 else x


    def u32(x):
        return x & 0xFFFFFFFF


    def i64(x):
        x &= 0xFFFFFFFFFFFFFFFF
        return x - 0x10000000000000000 if x & 0x8000000000000000 else x


    def u64(x):
        return x & 0xFFFFFFFFFFFFFFFF


    def java_byte(x):
        x &= 0xFF
        return x - 256 if x >= 128 else x


    def as_unsigned_bytes(arr):
        if isinstance(arr, ByteArray):
            return bytes((x & 0xFF) for x in arr.data)
        if isinstance(arr, (bytes, bytearray)):
            return bytes(arr)
        return bytes((int(x) & 0xFF) for x in arr)


    def le32(value):
        return struct.pack("<i", i32(value))


    def blake2s_digest(data, out_len):
        return hashlib.blake2s(as_unsigned_bytes(data), digest_size=out_len).digest()


    def gmx_kdf(seed, out_len, *parts):
        buf = bytearray(as_unsigned_bytes(seed))
        for part in parts:
            b = as_unsigned_bytes(part)
            buf.extend(le32(len(b)))
            buf.extend(b)
        return blake2s_digest(bytes(buf), out_len)


    def gmx_stream(seed, key, out_len):
        out = bytearray()
        counter = 0
        while len(out) < out_len:
            block = gmx_kdf(seed, 32, key, le32(counter))
            out.extend(block[: out_len - len(out)])
            counter += 1
        return bytes(out)


    def xor_transform(data, key, context):
        plain = as_unsigned_bytes(data)
        stream = gmx_stream(as_unsigned_bytes(context) + b":xor", key, len(plain))
        out = bytearray(len(plain))
        for i, b in enumerate(plain):
            out[i] = b ^ stream[i] ^ (((i * 17) + stream[i >> 1]) & 0xFF)
        return bytes(out)


    def wb_transform(data, key, context):
        src = as_unsigned_bytes(data)
        stream = gmx_stream(as_unsigned_bytes(context) + b":wb", key, len(src))
        out = bytearray(len(src))
        for i, b in enumerate(src):
            v = (b - stream[i] - (i * 19)) & 0xFF
            shift = (stream[i] ^ (i * 11)) & 7
            if shift:
                v = ((v >> shift) | (v << (8 - shift))) & 0xFF
            out[i] = v
        return bytes(out)


    def sm4_prefix_transform(data, key, context):
        src = as_unsigned_bytes(data)
        if not src:
            return src
        prefix_len = min(len(src), 96)
        stream = gmx_stream(as_unsigned_bytes(context) + b":sm4-prefix", key, prefix_len)
        out = bytearray(src)
        state = stream[0]
        for i in range(prefix_len):
            rotated = ((state << 1) | (state >> 7)) & 0xFF
            mixed_stream = stream[i] ^ ((i * 61) & 0xFF)
            state = rotated ^ mixed_stream
            out[i] ^= state
        return bytes(out)


    def rc4_transform(data, key, context):
        src = as_unsigned_bytes(data)
        rc4_key = gmx_stream(as_unsigned_bytes(context) + b":rc4-key", key, 48)
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + rc4_key[i % len(rc4_key)] + ((i * 13) & 0xFF)) & 0xFF
            s[i], s[j] = s[j], s[i]
        out = bytearray(len(src))
        i = 0
        j = 0
        for pos, b in enumerate(src):
            i = (i + 1) & 0xFF
            j = (j + s[i] + (pos & 7)) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[pos] = b ^ s[(s[i] + s[j] + rc4_key[pos % len(rc4_key)]) & 0xFF]
        return bytes(out)


    def front_stream(mask_seed, out_len):
        out = bytearray()
        counter = 0
        seed = as_unsigned_bytes(mask_seed)
        while len(out) < out_len:
            out.extend(blake2s_digest(seed + le32(counter), 32))
            counter += 1
        return bytes(out[:out_len])


    def front_unmask(front_cipher, mask_seed):
        cipher = as_unsigned_bytes(front_cipher)
        stream = front_stream(mask_seed, len(cipher))
        return bytes(
            byte ^ stream[i] ^ (((i * 29) + len(cipher)) & 0xFF)
            for i, byte in enumerate(cipher)
        )


    def assemble_recovered_dex(front_info, body):
        body = as_unsigned_bytes(body)
        if hashlib.sha256(body).hexdigest() != front_info["body_hash"]:
            raise RuntimeError("body sha256 mismatch")

        front_plain = front_unmask(
            bytes.fromhex(front_info["front_cipher"]),
            bytes.fromhex(front_info["mask_seed"]),
        )
        if len(front_plain) != int(front_info["front_size"]):
            raise RuntimeError("front size mismatch")
        if hashlib.sha256(front_plain).hexdigest() != front_info["front_hash"]:
            raise RuntimeError("front sha256 mismatch")

        recovered = front_plain + body
        if len(recovered) != int(front_info["dex_size"]):
            raise RuntimeError("dex size mismatch")
        if not recovered.startswith(b"dex\n"):
            raise RuntimeError("dex magic mismatch")
        header_adler = struct.unpack_from("<I", recovered, 8)[0]
        if header_adler != (zlib.adler32(recovered[12:]) & 0xFFFFFFFF):
            raise RuntimeError("dex adler32 mismatch")
        if f"{header_adler:08x}" != front_info["dex_adler32"]:
            raise RuntimeError("manifest dex_adler32 mismatch")
        if recovered[12:32].hex() != front_info["dex_sha1"]:
            raise RuntimeError("manifest dex_sha1 mismatch")
        if hashlib.sha256(recovered).hexdigest() != front_info["dex_sha256"]:
            raise RuntimeError("manifest dex_sha256 mismatch")
        return recovered


    class ByteArray:
        def __init__(self, data):
            if isinstance(data, ByteArray):
                self.data = data.data[:]
            elif isinstance(data, (bytes, bytearray)):
                self.data = [java_byte(x) for x in data]
            else:
                self.data = [java_byte(x) for x in data]

        def __len__(self):
            return len(self.data)

        def __getitem__(self, idx):
            return self.data[idx]

        def __setitem__(self, idx, value):
            self.data[idx] = java_byte(value)

        def to_bytes(self):
            return bytes((x & 0xFF) for x in self.data)

        def __repr__(self):
            return f"ByteArray({len(self.data)}:{self.to_bytes()[:16].hex()})"


    class JavaObject:
        def __init__(self, cls):
            self.cls = cls
            self.fields = {}

        def __repr__(self):
            return f"<{self.cls} {self.fields}>"


    class VMThrow(Exception):
        def __init__(self, obj):
            super().__init__(repr(obj))
            self.obj = obj


    class ByteBufferObj:
        def __init__(self, size):
            self.buf = bytearray(size)
            self.pos = 0
            self.little = False

        def order(self, order):
            self.little = order == "LITTLE_ENDIAN"
            return self

        def put_int(self, value):
            fmt = "<i" if self.little else ">i"
            self.buf[self.pos : self.pos + 4] = struct.pack(fmt, i32(value))
            self.pos += 4
            return self

        def put(self, arr):
            data = as_unsigned_bytes(arr)
            self.buf[self.pos : self.pos + len(data)] = data
            self.pos += len(data)
            return self

        def array(self):
            return ByteArray(self.buf)


    class CRCObj:
        def __init__(self, kind):
            self.kind = kind
            self.val = 1 if kind == "Adler32" else 0

        def update(self, arr, off=None, ln=None):
            data = as_unsigned_bytes(arr)
            if off is not None:
                data = data[off : off + ln]
            if self.kind == "Adler32":
                self.val = zlib.adler32(data, self.val)
            else:
                self.val = zlib.crc32(data, self.val)

        def get_value(self):
            return self.val & 0xFFFFFFFF


    class InflaterObj:
        def __init__(self):
            self.data = b""
            self.out = b""
            self.pos = 0
            self.done = False

        def set_input(self, arr):
            self.data = as_unsigned_bytes(arr)
            self.out = zlib.decompress(self.data)
            self.pos = 0
            self.done = False

        def inflate(self, arr):
            n = min(len(arr), len(self.out) - self.pos)
            for i, b in enumerate(self.out[self.pos : self.pos + n]):
                arr[i] = b
            self.pos += n
            self.done = self.pos >= len(self.out)
            return n

        def finished(self):
            return self.done

        def end(self):
            return None


    class BAOSObj:
        def __init__(self, size=0):
            self.buf = bytearray()

        def write(self, arr, off=None, ln=None):
            data = as_unsigned_bytes(arr)
            if off is None:
                self.buf.extend(data)
            else:
                self.buf.extend(data[off : off + ln])

        def to_byte_array(self):
            return ByteArray(self.buf)

        def size(self):
            return len(self.buf)

        def close(self):
            return None


    class JsonObject:
        def __init__(self, value=None):
            self.value = {} if value is None else value

        def get_json_array(self, key):
            return JsonArray(self.value[key])

        def get_json_object(self, key):
            return JsonObject(self.value[key])

        def get_string(self, key):
            return str(self.value[key])

        def get_int(self, key):
            return int(self.value[key])

        def get_long(self, key):
            return int(self.value[key])

        def opt_int(self, key, default=0):
            return int(self.value.get(key, default))

        def opt_string(self, key, default=""):
            return str(self.value.get(key, default))

        def opt_bool(self, key, default=False):
            return bool(self.value.get(key, default))

        def has(self, key):
            return key in self.value

        def length(self):
            return len(self.value)

        def __repr__(self):
            return f"JsonObject({self.value!r})"


    class JsonArray:
        def __init__(self, value):
            self.value = value

        def length(self):
            return len(self.value)

        def get_json_object(self, idx):
            return JsonObject(self.value[idx])

        def get_int(self, idx):
            return int(self.value[idx])

        def get_string(self, idx):
            return str(self.value[idx])


    def java_string_value(obj):
        if isinstance(obj, JavaObject) and obj.cls == "Ljava/lang/String;":
            return obj.fields.get("value", "")
        if isinstance(obj, JavaObject) and obj.cls == "Ljava/nio/charset/Charset;":
            return obj.fields.get("value", "UTF-8")
        return obj


    def java_charset_name(obj):
        name = java_string_value(obj)
        if name in (None, 0):
            name = "UTF-8"
        return "utf-8" if str(name).upper().replace("_", "-") == "UTF-8" else str(name)


    class Dex:
        def __init__(self, path):
            self.path = Path(path)
            self.data = self.path.read_bytes()
            h = self.data
            self.string_ids_size, self.string_ids_off = struct.unpack_from("<II", h, 0x38)
            self.type_ids_size, self.type_ids_off = struct.unpack_from("<II", h, 0x40)
            self.proto_ids_size, self.proto_ids_off = struct.unpack_from("<II", h, 0x48)
            self.field_ids_size, self.field_ids_off = struct.unpack_from("<II", h, 0x50)
            self.method_ids_size, self.method_ids_off = struct.unpack_from("<II", h, 0x58)
            self.class_defs_size, self.class_defs_off = struct.unpack_from("<II", h, 0x60)
            self.strings = []
            for i in range(self.string_ids_size):
                (off,) = struct.unpack_from("<I", h, self.string_ids_off + 4 * i)
                self.strings.append(read_mutf8(h, off))
            self.types = []
            for i in range(self.type_ids_size):
                (sid,) = struct.unpack_from("<I", h, self.type_ids_off + 4 * i)
                self.types.append(self.strings[sid])
            self.protos = []
            for i in range(self.proto_ids_size):
                shorty, ret, params_off = struct.unpack_from("<III", h, self.proto_ids_off + 12 * i)
                params = []
                if params_off:
                    (size,) = struct.unpack_from("<I", h, params_off)
                    params = [self.types[struct.unpack_from("<H", h, params_off + 4 + 2 * j)[0]] for j in range(size)]
                self.protos.append(
                    {
                        "shorty": self.strings[shorty],
                        "return": self.types[ret],
                        "params": params,
                        "descriptor": "(" + "".join(params) + ")" + self.types[ret],
                    }
                )
            self.fields = []
            for i in range(self.field_ids_size):
                cls, typ, name = struct.unpack_from("<HHI", h, self.field_ids_off + 8 * i)
                self.fields.append({"class": self.types[cls], "type": self.types[typ], "name": self.strings[name]})
            self.methods = []
            for i in range(self.method_ids_size):
                cls, proto, name = struct.unpack_from("<HHI", h, self.method_ids_off + 8 * i)
                self.methods.append({"class": self.types[cls], "proto": self.protos[proto], "name": self.strings[name]})
            self.classes = []
            self.class_by_desc = {}
            for i in range(self.class_defs_size):
                vals = struct.unpack_from("<IIIIIIII", h, self.class_defs_off + 32 * i)
                ent = {
                    "class_idx": vals[0],
                    "descriptor": self.types[vals[0]],
                    "access": vals[1],
                    "super_idx": vals[2],
                    "interfaces_off": vals[3],
                    "source_file_idx": vals[4],
                    "annotations_off": vals[5],
                    "class_data_off": vals[6],
                    "static_values_off": vals[7],
                }
                self.classes.append(ent)
                self.class_by_desc[ent["descriptor"]] = ent
            self.method_code = {}
            for c in self.classes:
                for m in self.class_data(c)["direct_methods"] + self.class_data(c)["virtual_methods"]:
                    if m.get("code_off"):
                        self.method_code[m["method_idx"]] = m

        def class_data(self, class_def):
            off = class_def["class_data_off"]
            if not off:
                return {"static_fields": [], "instance_fields": [], "direct_methods": [], "virtual_methods": []}
            static_count, off = uleb(self.data, off)
            instance_count, off = uleb(self.data, off)
            direct_count, off = uleb(self.data, off)
            virtual_count, off = uleb(self.data, off)

            def fields(count):
                nonlocal off
                out = []
                idx = 0
                for _ in range(count):
                    diff, off = uleb(self.data, off)
                    access, off = uleb(self.data, off)
                    idx += diff
                    ent = dict(self.fields[idx])
                    ent.update({"field_idx": idx, "access": access})
                    out.append(ent)
                return out

            def methods(count):
                nonlocal off
                out = []
                idx = 0
                for _ in range(count):
                    diff, off = uleb(self.data, off)
                    access, off = uleb(self.data, off)
                    code_off, off = uleb(self.data, off)
                    idx += diff
                    ent = dict(self.methods[idx])
                    ent.update({"method_idx": idx, "access": access, "code_off": code_off})
                    if code_off:
                        regs, ins, outs, tries, debug, insn_size = struct.unpack_from("<HHHHII", self.data, code_off)
                        ent.update(
                            {
                                "registers": regs,
                                "ins": ins,
                                "outs": outs,
                                "tries": tries,
                                "debug_info_off": debug,
                                "insns_size": insn_size,
                                "insns_off": code_off + 16,
                            }
                        )
                    out.append(ent)
                return out

            return {
                "static_fields": fields(static_count),
                "instance_fields": fields(instance_count),
                "direct_methods": methods(direct_count),
                "virtual_methods": methods(virtual_count),
            }

        def code_units(self, method_idx):
            m = self.method_code[method_idx]
            off = m["insns_off"]
            size = m["insns_size"]
            return list(struct.unpack_from("<" + "H" * size, self.data, off))

        def try_handlers(self, method_idx):
            m = self.method_code[method_idx]
            tries = m["tries"]
            if not tries:
                return []
            insns_end = m["insns_off"] + m["insns_size"] * 2
            if m["insns_size"] & 1:
                insns_end += 2
            try_items = []
            for i in range(tries):
                start_addr, insn_count, handler_off = struct.unpack_from("<IHH", self.data, insns_end + i * 8)
                try_items.append((start_addr, start_addr + insn_count, handler_off))
            handlers_base = insns_end + tries * 8
            list_size, off = uleb(self.data, handlers_base)
            decoded = {}
            for _ in range(list_size):
                handler_start = off - handlers_base
                size, off = sleb(self.data, off)
                typed = []
                for _ in range(abs(size)):
                    type_idx, off = uleb(self.data, off)
                    addr, off = uleb(self.data, off)
                    typed.append((self.types[type_idx], addr))
                catch_all = None
                if size <= 0:
                    catch_all, off = uleb(self.data, off)
                decoded[handler_start] = (typed, catch_all)
            out = []
            for start, end, handler_off in try_items:
                typed, catch_all = decoded[handler_off]
                out.append({"start": start, "end": end, "typed": typed, "catch_all": catch_all})
            return out


    def target_descriptors():
        import re

        out = {}
        for fn in ["C0007x5e8afbfa.java", "C0001xbf91252a.java", "C0005xe855a16b.java", "C0010xee79d947.java"]:
            text = (SRC_DIR / fn).read_text(errors="ignore")
            m = re.search(r"renamed from: (com\.guardmaster\.ctf\.[^,]+)", text)
            out[fn.removesuffix(".java")] = "L" + m.group(1).replace(".", "/") + ";"
        return out


    class VM:
        def __init__(self, dex, trace=False):
            self.dex = dex
            self.trace = trace
            self.static_fields = {}
            self.last_result = None
            self.targets = target_descriptors()
            self.c0007 = self.targets["C0007x5e8afbfa"]
            self.call_depth = 0
            self.max_steps = 20_000_000

        def find_method(self, cls_desc, name_alias_prefix=None, proto=None):
            candidates = []
            for idx, m in enumerate(self.dex.methods):
                if m["class"] != cls_desc:
                    continue
                if proto and m["proto"]["descriptor"] != proto:
                    continue
                candidates.append((idx, m))
            if name_alias_prefix is None:
                return candidates
            # Caller passes actual aliased method index from dex_methods.json when possible.
            raise KeyError(name_alias_prefix)

        def run_method(self, method_idx, args):
            m = self.dex.methods[method_idx]
            if method_idx not in self.dex.method_code:
                return self.invoke_external(method_idx, None, args)
            code = self.dex.method_code[method_idx]
            regs = [None] * code["registers"]
            ins = code["ins"]
            start = code["registers"] - ins
            for i, a in enumerate(args):
                regs[start + i] = a
            units = self.dex.code_units(method_idx)
            handlers = self.dex.try_handlers(method_idx)
            pc = 0
            steps = 0
            pending_exception = None
            self.call_depth += 1
            try:
                while True:
                    steps += 1
                    if steps > self.max_steps:
                        raise RuntimeError(f"step limit in method {method_idx}")
                    opunit = units[pc]
                    op = opunit & 0xFF
                    old_pc = pc
                    try:
                        pc = self.exec_op(op, opunit, units, pc, regs, pending_exception)
                        pending_exception = None
                    except VMThrow as thrown:
                        handler_pc = self.find_handler(handlers, old_pc, thrown.obj)
                        if handler_pc is None:
                            mm = self.dex.methods[method_idx]
                            code_off = self.dex.method_code.get(method_idx, {}).get("code_off", 0)
                            raise RuntimeError(
                                f"unhandled throw #{method_idx} code_off=0x{code_off:x} "
                                f"name={mm['name']}{mm['proto']['descriptor']} "
                                f"pc=0x{old_pc:x} obj={thrown.obj!r} regs={regs!r}"
                            ) from thrown
                        pending_exception = thrown.obj
                        pc = handler_pc
                        continue
                    except Exception as e:
                        mm = self.dex.methods[method_idx]
                        code_off = self.dex.method_code.get(method_idx, {}).get("code_off", 0)
                        raise RuntimeError(
                            f"while executing #{method_idx} code_off=0x{code_off:x} "
                            f"name={mm['name']}{mm['proto']['descriptor']} "
                            f"pc=0x{old_pc:x} op=0x{op:02x} regs={regs!r}"
                        ) from e
                    if pc == "RETURN":
                        return self.last_result
                    if pc == old_pc:
                        raise RuntimeError(f"pc did not advance at {method_idx}:{pc:x} op {op:x}")
            finally:
                self.call_depth -= 1

        def find_handler(self, handlers, pc, thrown_obj):
            thrown_cls = getattr(thrown_obj, "cls", "Ljava/lang/Throwable;")
            for item in handlers:
                if not (item["start"] <= pc < item["end"]):
                    continue
                for typ, addr in item["typed"]:
                    if self.exception_matches(thrown_cls, typ):
                        return addr
                if item["catch_all"] is not None:
                    return item["catch_all"]
            return None

        def exception_matches(self, thrown_cls, catch_cls):
            if catch_cls in (thrown_cls, "Ljava/lang/Throwable;", "Ljava/lang/Exception;", "Ljava/lang/RuntimeException;"):
                return True
            if thrown_cls.endswith("Exception;") and catch_cls in ("Ljava/lang/Throwable;", "Ljava/lang/Exception;"):
                return True
            return False

        def invoke_external(self, method_idx, this_obj, args):
            m = self.dex.methods[method_idx]
            cls, name, proto = m["class"], m["name"], m["proto"]["descriptor"]
            # Constructors for modeled objects.
            if name == "<init>":
                return None
            raise NotImplementedError(f"external/unimplemented invoke #{method_idx} {cls}->{name}{proto}")

        def invoke(self, kind, method_idx, args):
            m = self.dex.methods[method_idx]
            cls, name, proto = m["class"], m["name"], m["proto"]["descriptor"]
            if cls == "Ljava/lang/Object;" and name == "<init>":
                return None
            if cls == "Ljava/io/ByteArrayOutputStream;" and name == "<init>":
                return None
            if name == "<init>" and cls.startswith("Ljava/lang/") and cls.endswith("Exception;"):
                return None
            if cls == "Ljava/lang/System;" and name == "arraycopy":
                src, src_pos, dst, dst_pos, ln = args
                for i in range(ln):
                    dst[dst_pos + i] = src[src_pos + i]
                return None
            if cls == "Ljava/util/Arrays;":
                if name == "copyOfRange":
                    arr, a, b = args
                    return ByteArray(as_unsigned_bytes(arr)[a:b])
                if name == "copyOf":
                    arr, ln = args
                    data = bytearray(as_unsigned_bytes(arr)[:ln])
                    data.extend(b"\x00" * (ln - len(data)))
                    return ByteArray(data)
                if name == "fill":
                    arr, val = args
                    for i in range(len(arr)):
                        arr[i] = val
                    return None
                if name == "equals":
                    return as_unsigned_bytes(args[0]) == as_unsigned_bytes(args[1])
            if cls == "Ljava/nio/ByteBuffer;":
                if name == "allocate":
                    return ByteBufferObj(args[0])
            if cls == "Ljava/security/MessageDigest;":
                if name == "getInstance":
                    alg = java_string_value(args[0])
                    return {"type": "MessageDigest", "alg": alg}
                if name == "isEqual":
                    return as_unsigned_bytes(args[0]) == as_unsigned_bytes(args[1])
            if args and isinstance(args[0], dict) and args[0].get("type") == "MessageDigest" and name == "digest":
                alg = args[0]["alg"].replace("-", "").lower()
                h = hashlib.new(alg)
                h.update(as_unsigned_bytes(args[1]))
                return ByteArray(h.digest())
            if args and isinstance(args[0], ByteBufferObj):
                if name == "order":
                    return args[0].order(args[1])
                if name == "putInt":
                    return args[0].put_int(args[1])
                if name == "put":
                    return args[0].put(args[1])
                if name == "array":
                    return args[0].array()
            if cls == "Ljava/util/zip/CRC32;" and name == "<init>":
                return None
            if cls == "Ljava/util/zip/Adler32;" and name == "<init>":
                return None
            if args and isinstance(args[0], CRCObj):
                if name == "update":
                    if len(args) == 2:
                        args[0].update(args[1])
                    else:
                        args[0].update(args[1], args[2], args[3])
                    return None
                if name == "getValue":
                    return args[0].get_value()
            if args and isinstance(args[0], InflaterObj):
                if name == "setInput":
                    return args[0].set_input(args[1])
                if name == "inflate":
                    return args[0].inflate(args[1])
                if name == "finished":
                    return args[0].finished()
                if name == "end":
                    return args[0].end()
            if args and isinstance(args[0], BAOSObj):
                if name == "write":
                    if len(args) == 2:
                        return args[0].write(args[1])
                    return args[0].write(args[1], args[2], args[3])
                if name == "size":
                    return args[0].size()
                if name == "toByteArray":
                    return args[0].to_byte_array()
                if name == "close":
                    return args[0].close()
            if cls == "Ljava/lang/String;" and name == "<init>":
                this = args[0]
                if isinstance(this, JavaObject):
                    if len(args) >= 5 and isinstance(args[1], ByteArray) and isinstance(args[2], int):
                        charset = java_charset_name(args[4])
                        raw = as_unsigned_bytes(args[1])
                        start = args[2]
                        end = start + args[3]
                        this.fields["value"] = raw[start:end].decode(charset, errors="strict")
                    elif len(args) >= 4 and isinstance(args[1], ByteArray) and isinstance(args[2], int):
                        raw = as_unsigned_bytes(args[1])
                        start = args[2]
                        end = start + args[3]
                        this.fields["value"] = raw[start:end].decode("utf-8", errors="strict")
                    elif len(args) >= 3 and isinstance(args[1], ByteArray):
                        charset = java_charset_name(args[2])
                        this.fields["value"] = as_unsigned_bytes(args[1]).decode(charset, errors="strict")
                    elif len(args) >= 2 and isinstance(args[1], ByteArray):
                        this.fields["value"] = as_unsigned_bytes(args[1]).decode("utf-8", errors="strict")
                    elif len(args) >= 2:
                        this.fields["value"] = str(java_string_value(args[1]))
                return None
            if cls == "Ljava/lang/String;" and name == "getBytes":
                return ByteArray(java_string_value(args[0]).encode("utf-8"))
            if cls == "Ljava/lang/String;" and name == "equals":
                return java_string_value(args[0]) == java_string_value(args[1])
            if cls == "Ljava/lang/String;" and name == "length":
                return len(java_string_value(args[0]))
            if cls == "Ljava/lang/String;" and name == "charAt":
                return ord(java_string_value(args[0])[args[1]])
            if cls == "Ljava/lang/String;" and name == "substring":
                s = java_string_value(args[0])
                return s[args[1] :] if len(args) == 2 else s[args[1] : args[2]]
            if cls == "Ljava/lang/Character;" and name == "digit":
                ch = chr(args[0]) if isinstance(args[0], int) else str(args[0])[0]
                return int(ch, args[1]) if ch.lower() in "0123456789abcdefghijklmnopqrstuvwxyz"[: args[1]] else -1
            if cls == "Ljava/lang/Integer;" and name in ("valueOf",):
                return int(args[0])
            if cls == "Ljava/lang/Integer;" and name == "rotateLeft":
                x, dist = u32(args[0]), args[1] & 31
                return i32(((x << dist) | (x >> (32 - dist))) & 0xFFFFFFFF)
            if cls == "Ljava/lang/Integer;" and name == "rotateRight":
                x, dist = u32(args[0]), args[1] & 31
                return i32(((x >> dist) | (x << (32 - dist))) & 0xFFFFFFFF)
            if cls == "Ljava/lang/Long;" and name == "parseLong":
                if len(args) >= 2:
                    return int(java_string_value(args[0]), args[1])
                return int(java_string_value(args[0]))
            if cls == "Ljava/lang/Math;":
                if name == "min":
                    return args[0] if args[0] <= args[1] else args[1]
                if name == "max":
                    return args[0] if args[0] >= args[1] else args[1]
            if cls == "Lorg/json/JSONObject;":
                if name == "<init>":
                    if len(args) >= 2:
                        args[0].value = json.loads(java_string_value(args[1]))
                    return None
                if isinstance(args[0], JsonObject):
                    if name == "getJSONArray":
                        return args[0].get_json_array(java_string_value(args[1]))
                    if name == "getJSONObject":
                        return args[0].get_json_object(java_string_value(args[1]))
                    if name == "getString":
                        return args[0].get_string(java_string_value(args[1]))
                    if name == "getInt":
                        return args[0].get_int(java_string_value(args[1]))
                    if name == "getLong":
                        return args[0].get_long(java_string_value(args[1]))
                    if name == "optInt":
                        default = args[2] if len(args) > 2 else 0
                        return args[0].opt_int(java_string_value(args[1]), default)
                    if name == "optString":
                        default = java_string_value(args[2]) if len(args) > 2 else ""
                        return args[0].opt_string(java_string_value(args[1]), default)
                    if name == "optBoolean":
                        default = bool(args[2]) if len(args) > 2 else False
                        return args[0].opt_bool(java_string_value(args[1]), default)
                    if name == "has":
                        return args[0].has(java_string_value(args[1]))
                    if name == "length":
                        return args[0].length()
            if cls == "Lorg/json/JSONArray;" and isinstance(args[0], JsonArray):
                if name == "length":
                    return args[0].length()
                if name == "getJSONObject":
                    return args[0].get_json_object(args[1])
                if name == "getInt":
                    return args[0].get_int(args[1])
                if name == "getString":
                    return args[0].get_string(args[1])
            if cls.startswith("Lcom/guardmaster/ctf/") and method_idx in self.dex.method_code:
                # The following methods were recovered from C0007 and mirrored here
                # to keep the bytecode interpreter on structural code instead of hot
                # hash/stream loops.
                if method_idx == 60:  # m29(data, outLen): BLAKE2s
                    return ByteArray(blake2s_digest(args[0], args[1]))
                if method_idx == 63:  # m32(int): little-endian int
                    return ByteArray(le32(args[0]))
                if method_idx == 64:  # m33(seed, outLen, byte[]...)
                    varargs = args[2] if len(args) > 2 and args[2] is not None else []
                    return ByteArray(gmx_kdf(args[0], args[1], *varargs))
                if method_idx == 65:  # m34(data, key, context): RC4-like stream
                    return ByteArray(rc4_transform(args[0], args[1], args[2]))
                if method_idx == 71:  # m40(data, key, context): wb transform
                    return ByteArray(wb_transform(args[0], args[1], args[2]))
                if method_idx == 75:  # m44(seed, key, outLen): counter stream
                    return ByteArray(gmx_stream(args[0], args[1], args[2]))
                if method_idx == 79:  # m48(int, int): two little-endian ints
                    return ByteArray(le32(args[0]) + le32(args[1]))
                if method_idx == 80:  # m49(data, key, context): sm4-prefix transform
                    return ByteArray(sm4_prefix_transform(args[0], args[1], args[2]))
                if method_idx == 85:  # m54(data, key, context): xor stream
                    return ByteArray(xor_transform(args[0], args[1], args[2]))
                if method_idx == 72:  # m41(data, expectedLen): java.util.zip.Inflater
                    return ByteArray(zlib.decompress(as_unsigned_bytes(args[0])))

            # Interpret dex methods in the target package, including the small constant provider.
            if cls.startswith("Lcom/guardmaster/ctf/") and method_idx in self.dex.method_code:
                return self.run_method(method_idx, args)
            raise NotImplementedError(f"invoke #{method_idx} {cls}->{name}{proto}")

        def exec_op(self, op, opunit, units, pc, regs, pending_exception=None):
            def reg4_hi():
                return (opunit >> 12) & 0xF

            def reg4_lo():
                return (opunit >> 8) & 0xF

            def s16(u):
                return u - 0x10000 if u & 0x8000 else u

            def s32(lo, hi):
                v = lo | (hi << 16)
                return v - 0x100000000 if v & 0x80000000 else v

            if op == 0x00:
                return pc + 1
            if op in (0x01, 0x04, 0x07):  # move, move-wide, move-object
                a = reg4_lo()
                b = reg4_hi()
                regs[a] = regs[b]
                return pc + 1
            if op in (0x02, 0x05, 0x08):  # move/from16
                a = (opunit >> 8) & 0xFF
                b = units[pc + 1]
                regs[a] = regs[b]
                return pc + 2
            if op in (0x03, 0x06, 0x09):  # move/16
                a = units[pc + 1]
                b = units[pc + 2]
                regs[a] = regs[b]
                return pc + 3
            if op in (0x0A, 0x0B, 0x0C):
                a = (opunit >> 8) & 0xFF
                regs[a] = self.last_result
                return pc + 1
            if op == 0x0D:  # move-exception
                a = (opunit >> 8) & 0xFF
                regs[a] = pending_exception or JavaObject("Ljava/lang/Exception;")
                return pc + 1
            if op == 0x0E:
                self.last_result = None
                return "RETURN"
            if op in (0x0F, 0x10, 0x11):
                a = (opunit >> 8) & 0xFF
                self.last_result = regs[a]
                return "RETURN"
            if op == 0x12:
                a = reg4_lo()
                lit = reg4_hi()
                if lit & 0x8:
                    lit -= 0x10
                regs[a] = lit
                return pc + 1
            if op == 0x13:
                a = (opunit >> 8) & 0xFF
                regs[a] = s16(units[pc + 1])
                return pc + 2
            if op == 0x14:
                a = (opunit >> 8) & 0xFF
                regs[a] = s32(units[pc + 1], units[pc + 2])
                return pc + 3
            if op == 0x15:
                a = (opunit >> 8) & 0xFF
                regs[a] = i32(s16(units[pc + 1]) << 16)
                return pc + 2
            if op in (0x16, 0x17, 0x18, 0x19):
                a = (opunit >> 8) & 0xFF
                if op == 0x16:
                    regs[a] = s16(units[pc + 1])
                    return pc + 2
                if op == 0x17:
                    regs[a] = s32(units[pc + 1], units[pc + 2])
                    return pc + 3
                if op == 0x18:
                    lo = units[pc + 1] | (units[pc + 2] << 16) | (units[pc + 3] << 32) | (units[pc + 4] << 48)
                    if lo & (1 << 63):
                        lo -= 1 << 64
                    regs[a] = lo
                    return pc + 5
                regs[a] = s16(units[pc + 1]) << 48
                return pc + 2
            if op == 0x1A:
                a = (opunit >> 8) & 0xFF
                regs[a] = self.dex.strings[units[pc + 1]]
                return pc + 2
            if op == 0x1B:
                a = (opunit >> 8) & 0xFF
                idx = units[pc + 1] | (units[pc + 2] << 16)
                regs[a] = self.dex.strings[idx]
                return pc + 3
            if op == 0x1C:
                a = (opunit >> 8) & 0xFF
                regs[a] = self.dex.types[units[pc + 1]]
                return pc + 2
            if op in (0x1D, 0x1E):
                return pc + 1
            if op == 0x1F:
                return pc + 2
            if op == 0x20:
                a = reg4_lo()
                b = reg4_hi()
                typ = self.dex.types[units[pc + 1]]
                obj = regs[b]
                regs[a] = isinstance(obj, JavaObject) and obj.cls == typ
                return pc + 2
            if op == 0x21:
                a = reg4_lo()
                b = reg4_hi()
                regs[a] = len(regs[b])
                return pc + 1
            if op == 0x22:
                a = (opunit >> 8) & 0xFF
                cls = self.dex.types[units[pc + 1]]
                if cls == "Ljava/util/zip/CRC32;":
                    regs[a] = CRCObj("CRC32")
                elif cls == "Ljava/util/zip/Adler32;":
                    regs[a] = CRCObj("Adler32")
                elif cls == "Ljava/util/zip/Inflater;":
                    regs[a] = InflaterObj()
                elif cls == "Ljava/io/ByteArrayOutputStream;":
                    regs[a] = BAOSObj()
                elif cls == "Lorg/json/JSONObject;":
                    regs[a] = JsonObject()
                else:
                    regs[a] = JavaObject(cls)
                return pc + 2
            if op == 0x23:
                a = reg4_lo()
                b = reg4_hi()
                typ = self.dex.types[units[pc + 1]]
                n = regs[b]
                if typ == "[B":
                    regs[a] = ByteArray([0] * n)
                elif typ in ("[I", "[S", "[C", "[Z"):
                    regs[a] = [0] * n
                else:
                    regs[a] = [None] * n
                return pc + 2
            if op == 0x24:  # filled-new-array
                count = (opunit >> 8) & 0xFF
                reg_word = units[pc + 2]
                regs_list = [reg_word & 0xF, (reg_word >> 4) & 0xF, (reg_word >> 8) & 0xF, (reg_word >> 12) & 0xF, units[pc + 1] >> 12]
                self.last_result = [regs[r] for r in regs_list[:count]]
                return pc + 3
            if op == 0x25:
                count = (opunit >> 8) & 0xFF
                start = units[pc + 2]
                self.last_result = [regs[start + i] for i in range(count)]
                return pc + 3
            if op == 0x26:  # fill-array-data
                a = (opunit >> 8) & 0xFF
                off = s32(units[pc + 1], units[pc + 2])
                payload_pc = pc + off
                ident = units[payload_pc]
                if ident != 0x0300:
                    raise RuntimeError(f"bad fill-array-data payload 0x{ident:04x}")
                elem_width = units[payload_pc + 1]
                size = units[payload_pc + 2] | (units[payload_pc + 3] << 16)
                data_off = payload_pc + 4
                arr = regs[a]

                # The payload is embedded in the same code item; using code units is
                # simpler and avoids depending on absolute dex offsets.
                data_bytes = bytearray()
                data_units = (size * elem_width + 1) // 2
                for u in units[data_off : data_off + data_units]:
                    data_bytes.extend(struct.pack("<H", u))
                for i in range(size):
                    raw = data_bytes[i * elem_width : (i + 1) * elem_width]
                    if elem_width == 1:
                        arr[i] = java_byte(raw[0])
                    elif elem_width == 2:
                        arr[i] = struct.unpack("<h", raw)[0]
                    elif elem_width == 4:
                        arr[i] = struct.unpack("<i", raw)[0]
                    elif elem_width == 8:
                        arr[i] = struct.unpack("<q", raw)[0]
                    else:
                        raise RuntimeError(f"unsupported fill width {elem_width}")
                return pc + 3
            if op == 0x27:
                raise VMThrow(regs[(opunit >> 8) & 0xFF])
            if op == 0x28:
                off = opunit >> 8
                if off & 0x80:
                    off -= 0x100
                return pc + off
            if op == 0x29:
                return pc + s16(units[pc + 1])
            if op == 0x2A:
                return pc + s32(units[pc + 1], units[pc + 2])
            if 0x32 <= op <= 0x37:
                a = reg4_lo()
                b = reg4_hi()
                off = s16(units[pc + 1])
                av, bv = regs[a], regs[b]
                conds = {
                    0x32: av == bv,
                    0x33: av != bv,
                    0x34: av < bv,
                    0x35: av >= bv,
                    0x36: av > bv,
                    0x37: av <= bv,
                }
                return pc + off if conds[op] else pc + 2
            if 0x38 <= op <= 0x3D:
                a = (opunit >> 8) & 0xFF
                off = s16(units[pc + 1])
                av = regs[a]
                zero = 0 if isinstance(av, int) else None
                conds = {
                    0x38: av == zero,
                    0x39: av != zero,
                    0x3A: av < 0,
                    0x3B: av >= 0,
                    0x3C: av > 0,
                    0x3D: av <= 0,
                }
                return pc + off if conds[op] else pc + 2
            if 0x44 <= op <= 0x4A:
                a = (opunit >> 8) & 0xFF
                bc = units[pc + 1]
                b = bc & 0xFF
                c = (bc >> 8) & 0xFF
                regs[a] = regs[b][regs[c]]
                return pc + 2
            if 0x4B <= op <= 0x51:
                a = (opunit >> 8) & 0xFF
                bc = units[pc + 1]
                b = bc & 0xFF
                c = (bc >> 8) & 0xFF
                regs[b][regs[c]] = regs[a]
                return pc + 2
            if 0x52 <= op <= 0x58:
                a = reg4_lo()
                b = reg4_hi()
                field_idx = units[pc + 1]
                field = self.dex.fields[field_idx]
                obj = regs[b]
                regs[a] = obj.fields.get(field_idx, 0 if field["type"][0] in "IZBSCJ" else None)
                return pc + 2
            if 0x59 <= op <= 0x5F:
                a = reg4_lo()
                b = reg4_hi()
                field_idx = units[pc + 1]
                obj = regs[b]
                obj.fields[field_idx] = regs[a]
                return pc + 2
            if 0x60 <= op <= 0x66:
                a = (opunit >> 8) & 0xFF
                field_idx = units[pc + 1]
                field = self.dex.fields[field_idx]
                if field["class"] == "Ljava/nio/ByteOrder;" and field["name"] == "LITTLE_ENDIAN":
                    regs[a] = "LITTLE_ENDIAN"
                elif field["class"] == "Ljava/nio/charset/StandardCharsets;" and field["name"] == "UTF_8":
                    charset = JavaObject("Ljava/nio/charset/Charset;")
                    charset.fields["value"] = "UTF-8"
                    regs[a] = charset
                else:
                    regs[a] = self.static_fields.get(field_idx, 0)
                return pc + 2
            if 0x67 <= op <= 0x6D:
                a = (opunit >> 8) & 0xFF
                field_idx = units[pc + 1]
                self.static_fields[field_idx] = regs[a]
                return pc + 2
            if 0x6E <= op <= 0x72:
                count = (opunit >> 12) & 0xF
                method_idx = units[pc + 1]
                regs_word = units[pc + 2]
                reg_list = [regs_word & 0xF, (regs_word >> 4) & 0xF, (regs_word >> 8) & 0xF, (regs_word >> 12) & 0xF, (opunit >> 8) & 0xF]
                args = [regs[r] for r in reg_list[:count]]
                self.last_result = self.invoke(op, method_idx, args)
                return pc + 3
            if 0x74 <= op <= 0x78:
                count = (opunit >> 8) & 0xFF
                method_idx = units[pc + 1]
                start = units[pc + 2]
                args = [regs[start + i] for i in range(count)]
                self.last_result = self.invoke(op, method_idx, args)
                return pc + 3
            if op == 0x7B:  # neg-int
                a = reg4_lo()
                b = reg4_hi()
                regs[a] = i32(-regs[b])
                return pc + 1
            if op == 0x7C:  # not-int
                a = reg4_lo()
                b = reg4_hi()
                regs[a] = i32(~regs[b])
                return pc + 1
            if 0x81 <= op <= 0x8F:
                a = reg4_lo()
                b = reg4_hi()
                v = regs[b]
                if op == 0x81:  # int-to-long
                    regs[a] = int(v)
                elif op in (0x82, 0x83):  # int-to-float/double
                    regs[a] = float(v)
                elif op == 0x84:  # long-to-int
                    regs[a] = i32(v)
                elif op in (0x85, 0x86):  # long-to-float/double
                    regs[a] = float(v)
                elif op in (0x87, 0x8A):  # float/double-to-int
                    regs[a] = i32(int(v))
                elif op in (0x88, 0x8B):  # float/double-to-long
                    regs[a] = int(v)
                elif op in (0x89, 0x8C):  # float/double widening/narrowing
                    regs[a] = float(v)
                elif op == 0x8D:  # int-to-byte
                    regs[a] = java_byte(v)
                elif op == 0x8F:  # int-to-short
                    regs[a] = struct.unpack("<h", struct.pack("<H", v & 0xFFFF))[0]
                elif op == 0x8E:  # int-to-char
                    regs[a] = v & 0xFFFF
                return pc + 1
            if 0x90 <= op <= 0xAF:
                a = (opunit >> 8) & 0xFF
                bc = units[pc + 1]
                b = bc & 0xFF
                c = (bc >> 8) & 0xFF
                regs[a] = self.binop(op, regs[b], regs[c])
                return pc + 2
            if 0xB0 <= op <= 0xCF:
                a = reg4_lo()
                b = reg4_hi()
                regs[a] = self.binop(op - 0x20, regs[a], regs[b])
                return pc + 1
            if 0xD0 <= op <= 0xD7:
                a = reg4_lo()
                b = reg4_hi()
                lit = s16(units[pc + 1])
                regs[a] = self.binop_lit(op, regs[b], lit)
                return pc + 2
            if 0xD8 <= op <= 0xE2:
                a = (opunit >> 8) & 0xFF
                bc = units[pc + 1]
                b = bc & 0xFF
                lit = (bc >> 8) & 0xFF
                if lit & 0x80:
                    lit -= 0x100
                regs[a] = self.binop_lit(op, regs[b], lit)
                return pc + 2
            raise NotImplementedError(f"op 0x{op:02x} at pc 0x{pc:x}")

        def binop(self, op, a, b):
            if op == 0x90:
                return i32(a + b)
            if op == 0x91:
                return i32(a - b)
            if op == 0x92:
                return i32(a * b)
            if op == 0x93:
                if b == 0:
                    raise VMThrow(JavaObject("Ljava/lang/ArithmeticException;"))
                return i32((abs(a) // abs(b)) * (-1 if (a < 0) ^ (b < 0) else 1))
            if op == 0x94:
                if b == 0:
                    raise VMThrow(JavaObject("Ljava/lang/ArithmeticException;"))
                q = (abs(a) // abs(b)) * (-1 if (a < 0) ^ (b < 0) else 1)
                return i32(a - q * b)
            if op == 0x95:
                return i32(a & b)
            if op == 0x96:
                return i32(a | b)
            if op == 0x97:
                return i32(a ^ b)
            if op == 0x98:
                return i32(a << (b & 0x1F))
            if op == 0x99:
                return i32(a >> (b & 0x1F))
            if op == 0x9A:
                return i32((a & 0xFFFFFFFF) >> (b & 0x1F))
            if op == 0x9B:
                return i64(a + b)
            if op == 0x9C:
                return i64(a - b)
            if op == 0x9D:
                return i64(a * b)
            if op == 0x9E:
                if b == 0:
                    raise VMThrow(JavaObject("Ljava/lang/ArithmeticException;"))
                return i64((abs(a) // abs(b)) * (-1 if (a < 0) ^ (b < 0) else 1))
            if op == 0x9F:
                if b == 0:
                    raise VMThrow(JavaObject("Ljava/lang/ArithmeticException;"))
                q = (abs(a) // abs(b)) * (-1 if (a < 0) ^ (b < 0) else 1)
                return i64(a - q * b)
            if op == 0xA0:
                return i64(a & b)
            if op == 0xA1:
                return i64(a | b)
            if op == 0xA2:
                return i64(a ^ b)
            if op == 0xA3:
                return i64(a << (b & 0x3F))
            if op == 0xA4:
                return i64(a >> (b & 0x3F))
            if op == 0xA5:
                return i64(u64(a) >> (b & 0x3F))
            if 0xA6 <= op <= 0xAA:
                return self.binop(op - 0x16, a, b)
            raise NotImplementedError(f"binop 0x{op:x}")

        def binop_lit(self, op, a, lit):
            if op in (0xD1, 0xD9):  # rsub-int/lit16, rsub-int/lit8
                return i32(lit - a)
            mapping = {
                0xD0: 0x90,
                0xD2: 0x92,
                0xD3: 0x93,
                0xD4: 0x94,
                0xD5: 0x95,
                0xD6: 0x96,
                0xD7: 0x97,
                0xD8: 0x90,
                0xDA: 0x92,
                0xDB: 0x93,
                0xDC: 0x94,
                0xDD: 0x95,
                0xDE: 0x96,
                0xDF: 0x97,
                0xE0: 0x98,
                0xE1: 0x99,
                0xE2: 0x9A,
            }
            return self.binop(mapping[op], a, lit)


    def method_idx_by_code_off(dex, code_off):
        for idx, m in dex.method_code.items():
            if m["code_off"] == code_off:
                return idx
        raise KeyError(hex(code_off))


    REAL_DEX_RECORD_TYPE = -744419327


    def recover_gmx(trace=False):
        payload, key = load_app_payload_and_key()

        gmx_off = payload.find(b"GMX1")
        if gmx_off < 0:
            raise RuntimeError("GMX1 magic not found in loader payload")
        gmx = payload[gmx_off:]
        root_key = blake2s_digest(b"gmx1-root" + key, 32)

        dex = Dex(DEX_PATH)
        vm = VM(dex, trace=trace)
        vm.run_method(25, [])

        header = vm.run_method(66, [ByteArray(gmx), ByteArray(root_key)])
        records = vm.run_method(73, [ByteArray(gmx), header])
        header_key = header.fields[5]
        manifest = vm.run_method(81, [ByteArray(gmx), ByteArray(root_key), header_key, records])

        manifest_records = manifest.value["records"]
        real_manifest = next(item for item in manifest_records if not item.get("decoy", False))
        real_order_id = int(real_manifest["order_id"])
        real_record = next(
            rec
            for rec in records
            if rec.fields.get(18) == REAL_DEX_RECORD_TYPE and rec.fields.get(22) == real_order_id
        )

        body = vm.run_method(84, [ByteArray(gmx), ByteArray(root_key), header_key, real_record])
        recovered = assemble_recovered_dex(real_manifest["front"], body)
        OUT_DEX.parent.mkdir(parents=True, exist_ok=True)
        OUT_DEX.write_bytes(recovered)

        digest = hashlib.sha256(recovered).hexdigest()
        expected_digest = real_manifest["front"]["dex_sha256"]
        if digest != expected_digest:
            raise RuntimeError(f"recovered dex sha256 mismatch: {digest} != {expected_digest}")
        return {
            "output": str(OUT_DEX),
            "gmx_offset": gmx_off,
            "size": len(recovered),
            "sha256": digest,
        }


    DEX_PATH = classes_path
    GMX_PATH = gmx_path
    OUT_DEX = recovered_path

    # The C0007 class descriptor is not taken from JADX output.  Method #60 is the
    # bytecode method later verified as the BLAKE2s primitive, so its defining class
    # is the GMX decoder class used by this interpreter.
    def target_descriptors():
        dex = Dex(classes_path)
        c0007 = dex.methods[60]["class"]
        return {
            "C0007x5e8afbfa": c0007,
            "C0001xbf91252a": "",
            "C0005xe855a16b": "",
            "C0010xee79d947": "",
        }

    # Recover the loader key by executing the public loader bytecode from the
    # original classes.dex.  The key is not embedded as a solved constant.
    def load_app_payload_and_key():
        dex = Dex(classes_path)
        vm = VM(dex, trace=False)
        vm.run_method(25, [])
        m15 = method_idx_by_code_off(dex, 0x87B1C)
        key_obj = vm.run_method(m15, [])
        key = as_unsigned_bytes(key_obj)
        if len(key) != 64:
            raise RuntimeError(f"loader key length mismatch: {len(key)}")
        return classes_path.read_bytes() + gmx_path.read_bytes(), key

    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_bridge_semantics_module() -> types.ModuleType:
    _module_name = "bridge_semantics"
    """
    Python model for GuardMaster native Java-bridge JNI helpers.

    Addresses are from libguardmaster.so as loaded at base 0 in IDA:
    load 0x3841390, cl 0x3841528, ra 0x38415A4, rp 0x384163C,
    run 0x384176C, ip 0x38419E0, step 0x3841A18, pull 0x3841A4C.
    """


    from dataclasses import dataclass, field
    from hashlib import sha256
    from struct import pack, unpack_from


    MASK32 = 0xFFFFFFFF
    MASK64 = 0xFFFFFFFFFFFFFFFF

    GOLDEN_NEG = 0x61C8864680B583EB

    PROTO_INIT = 0x50524F544F494E49
    FINIT001 = 0x46494E4954303031
    LOADSEED = 0x4C4F414453454544
    LOADED = 0x4C4F41444544
    LOADFIN1 = 0x4C4F414446494E31
    CLASS = 0x434C415353
    CLASFIN1 = 0x434C415346494E31
    TOKENCOM = 0x544F4B454E434F4D
    NATIVEPA = 0x4E41544956455041
    NSTEP000 = 0x4E53544550303030
    BSTPJAVA = 0x425354504A415641
    BSTPFIN1 = 0x4253545046494E31
    JSTEP000 = 0x4A53544550303030
    JSTEPDIG = 0x4A53544550444947
    PULLFIN0 = 0x50554C4C46494E30
    PACKETCK = 0x5041434B4554434B
    COMMFIN0 = 0x434F4D4D46494E30

    MAGIC_GPK1 = 0x314B5047
    MAGIC_BSTP = 0x42535450


    def u32(x: int) -> int:
        return x & MASK32


    def u64(x: int) -> int:
        return x & MASK64


    def rol32(x: int, n: int) -> int:
        n &= 31
        return u32((x << n) | (x >> ((32 - n) & 31)))


    def rol64(x: int, n: int) -> int:
        n &= 63
        return u64((x << n) | (x >> ((64 - n) & 63)))


    def rol8(x: int, n: int) -> int:
        n &= 7
        x &= 0xFF
        return ((x << n) | (x >> ((8 - n) & 7))) & 0xFF


    def le32(x: int) -> bytes:
        return pack("<I", u32(x))


    def le64(x: int) -> bytes:
        return pack("<Q", u64(x))


    def get32(buf: bytes | bytearray, off: int = 0) -> int:
        return unpack_from("<I", buf, off)[0]


    def get64(buf: bytes | bytearray, off: int = 0) -> int:
        return unpack_from("<Q", buf, off)[0]


    def splitmix64_final(x: int) -> int:
        x = u64(x)
        x = u64((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9)
        x = u64((x ^ (x >> 27)) * 0x94D049BB133111EB)
        return u64(x ^ (x >> 31))


    def digest64(data: bytes | bytearray, seed: int) -> int:
        v = splitmix64_final(seed ^ (2 * len(data)) ^ 0x474D52544D495831)
        for i, b in enumerate(data):
            v = splitmix64_final(rol64(v ^ (b << (8 * (i & 7))), 11) - GOLDEN_NEG + i)
        return splitmix64_final(v ^ seed)


    def expand32(data: bytes | bytearray, seed: int) -> bytes:
        out = bytearray()
        for suffix in (0x534F3031, 0x534F3032, 0x534F3033, 0x534F3034):
            out += le64(digest64(data, seed ^ suffix))
        return bytes(out)


    def sig32(a: int, b: int) -> int:
        v4 = u32(73244475 * rol32(a ^ 0x53494744, (b & 7) + 3) + 655360001)
        v2 = rol32(b ^ 0x43535431, 11)
        x = u32(668265261 * (v4 ^ v2) - 1640531527)
        return u32(x ^ (x >> 16))


    def ra_bytes(n: int, size: int = 16) -> bytes:
        seed_a = 0x524131
        v = sig32(seed_a, n)
        out = bytearray(size)
        for i in range(size):
            v = sig32(v ^ seed_a, n ^ i)
            out[i] = (rol32(v, i & 31) ^ (seed_a >> (8 * (i & 3)))) & 0xFF
        return bytes(out)


    def ip_value() -> int:
        return sig32(18768, 1347571522)


    def kdf(label: str, data: bytes | bytearray, out_len: int) -> bytes:
        label_b = label.encode("ascii")
        out = bytearray()
        counter = 1
        while len(out) < out_len:
            h = sha256()
            h.update(label_b)
            h.update(b"\x00")
            h.update(le32(len(data)))
            h.update(data)
            h.update(le32(counter))
            out += h.digest()
            counter += 1
        return bytes(out[:out_len])


    def crc_guard(data: bytes | bytearray, seed: int) -> int:
        v = u32(seed ^ 0xA53C5A5C)
        for i, b in enumerate(data):
            cur = u32(v ^ (b << (8 * (i & 3))))
            for _ in range(8):
                cur = u32((-(cur & 1) & 0x82F63B78) ^ (cur >> 1))
            v = rol32(cur, 5)
        return u32(v ^ 0x5C3AC3A5)


    def xorshift64star(x: int) -> int:
        x = u64(x)
        if x == 0:
            x = 0x6A09E667F3BCC909
        x = u64(x ^ (x >> 12))
        x = u64(x ^ (x << 25))
        return u64((x ^ (x >> 27)) * 0x2545F4914F6CDD1D)


    @dataclass
    class WbDesc:
        rounds: int
        param: int
        w2: int
        w3: int
        perm: list[int]
        crc: int = 0

        def to_bytes(self, include_crc: bool = False) -> bytes:
            out = bytearray()
            out += le32(self.rounds)
            out += le32(self.param)
            out += le32(self.w2)
            out += le32(self.w3)
            out += bytes(x & 0xFF for x in self.perm)
            if include_crc:
                out += le32(self.crc)
            return bytes(out)


    def make_desc(snapshot96: bytes, seed32: int) -> WbDesc:
        seed32 = u32(seed32)
        material = bytes(snapshot96) + le32(seed32)
        rnd = kdf("GM-WBAES-DESC", material, 64)
        perm = list(range(16))
        rng = get64(rnd, 16)
        for j in range(15, 0, -1):
            rng = xorshift64star(rng ^ j)
            k = rng % (j + 1)
            perm[j], perm[k] = perm[k], perm[j]
        desc = WbDesc(
            rounds=rnd[0] % 3 + 6,
            param=rnd[1] % 5 + 3,
            w2=get32(rnd, 4),
            w3=get32(rnd, 8),
            perm=perm,
        )
        desc.crc = crc_guard(desc.to_bytes(False), seed32 ^ 0x57424145)
        return desc


    def sip_round(v: list[int]) -> None:
        v[0] = u64(v[0] + v[1])
        v[1] = rol64(v[1], 13) ^ v[0]
        v[0] = rol64(v[0], 32)
        v[2] = u64(v[2] + v[3])
        v[3] = rol64(v[3], 16) ^ v[2]
        v[0] = u64(v[0] + v[3])
        v[3] = rol64(v[3], 21) ^ v[0]
        v[2] = u64(v[2] + v[1])
        v[1] = rol64(v[1], 17) ^ v[2]
        v[2] = rol64(v[2], 32)


    def siphash_like(msg: bytes | bytearray, key_material: bytes | bytearray) -> int:
        key = kdf("GM-SIPHASH-LIKE-KEY", bytes(key_material), 16)
        k0 = get64(key, 0)
        k1 = get64(key, 8)
        v = [
            k0 ^ 0x736F6D6570736575,
            k1 ^ 0x646F72616E646F6D,
            k0 ^ 0x6C7967656E657261,
            k1 ^ 0x7465646279746573,
        ]
        i = 0
        msg = bytes(msg)
        while i < len(msg):
            block_len = min(8, len(msg) - i)
            block = bytearray(8)
            block[:block_len] = msg[i : i + block_len]
            m = get64(block)
            if block_len != 8:
                m ^= len(msg) << 56
            v[3] ^= m
            sip_round(v)
            sip_round(v)
            v[0] ^= m
            i += block_len
        v[2] ^= 0xFF
        for _ in range(4):
            sip_round(v)
        return u64(v[0] ^ v[1] ^ v[2] ^ v[3])


    def wbaes_schedule(data: bytes, desc: WbDesc, token: int) -> list[int]:
        material = bytes(data) + desc.to_bytes(True)
        token_key = kdf("GM-WBAES-TOKEN-KEY", material, 16)
        v = u64(token)
        sched = []
        for i in range(desc.rounds):
            sched.append(v)
            block = le64(v) + le32(desc.crc) + le32(i)
            v = siphash_like(block, token_key)
        return sched


    def wbaes_round_key(data: bytes, desc: WbDesc, round_no: int) -> bytes:
        return kdf("GM-WBAES-RK", bytes(data) + desc.to_bytes(True) + le32(round_no), 16)


    def wbaes_round_byte(data: bytes, desc: WbDesc, round_no: int, pos: int, x: int) -> int:
        v9 = u32(
            desc.w2
            ^ rol32(desc.w3, (round_no + pos) & 31)
            ^ u32(-1640531527 * round_no)
            ^ u32(-2048144789 * pos)
            ^ data[(round_no + pos) % len(data)]
        )
        v8 = (
            rol8((x ^ v9) & 0xFF, (v9 >> 8) & 7)
            * (((v9 >> 16) & 0xFE) | 1)
            + ((v9 >> 24) & 0xFF)
            + 17 * round_no
            + 31 * pos
        )
        return (v8 ^ rol8((v9 >> 5) & 0xFF, (x + pos) & 7)) & 0xFF


    def wbaes_f(data: bytes, desc: WbDesc, round_no: int, token: int, block8: bytes) -> bytes:
        rk = wbaes_round_key(data, desc, round_no)
        tmp = bytearray(8)
        for i in range(8):
            src = (
                block8[desc.perm[(i + round_no) & 0xF] & 7]
                ^ rk[(i + desc.param) & 0xF]
                ^ ((token >> (8 * (i & 7))) & 0xFF)
                ^ (19 * round_no + 23 * i)
            )
            tmp[i] = wbaes_round_byte(data, desc, round_no, i, src)
        out = bytearray(8)
        for j in range(8):
            out[j] = tmp[j] ^ rol8(tmp[(j - 1) & 7], 1) ^ rol8(tmp[(j + 1) & 7], 2) ^ rk[j]
        return bytes(out)


    def xor8(a: bytes, b: bytes) -> bytes:
        return bytes((x ^ y) & 0xFF for x, y in zip(a, b))


    def wbaes_transform(data: bytes, desc: WbDesc, initial16: bytes, token: int, decrypt: bool = False) -> tuple[bytes, int]:
        sched = wbaes_schedule(data, desc, token)
        left = bytes(initial16[:8])
        right = bytes(initial16[8:16])
        if decrypt:
            for i in range(desc.rounds):
                r = desc.rounds - 1 - i
                f = wbaes_f(data, desc, r, sched[r], left)
                left, right = xor8(right, f), left
        else:
            for r in range(desc.rounds):
                f = wbaes_f(data, desc, r, sched[r], right)
                left, right = right, xor8(left, f)
        return left + right, desc.crc


    def token_block(seed: int) -> bytes:
        return expand32(le64(seed), seed ^ TOKENCOM)


    def decoy(code: int, a: int = 0, b: int = 0) -> int:
        return splitmix64_final(code ^ 0x4445434F59544F4B ^ (u32(a) << 24) ^ (u32(b) << 1))


    @dataclass
    class BridgeState:
        phase: int = 0
        seq: int = 0
        token32: int = 0
        flags: int = 0
        jstep_index: int = 0
        commit_count: int = 0
        mix_counter: int = 0
        seed: int = 0
        prev_seed: int = 0
        pull_index: int = 0
        mix_key: int = 0
        mask: bytes = field(default_factory=lambda: b"\x00" * 32)
        token: bytes = field(default_factory=lambda: b"\x00" * 32)
        init_token: bytes = field(default_factory=lambda: b"\x00" * 32)
        work: bytes = field(default_factory=lambda: b"\x00" * 32)
        initialized: bool = False

        def init_from_seed(self, seed: int) -> None:
            self.phase = 0
            self.seq = 0
            self.token32 = 0
            self.flags = 0
            self.jstep_index = 0
            self.commit_count = 0
            self.mix_counter = 0
            self.seed = splitmix64_final(seed ^ PROTO_INIT)
            self.prev_seed = 0
            self.pull_index = 0
            self.mix_key = splitmix64_final(seed ^ FINIT001)
            self.mask = b"\x00" * 32
            self.token = b"\x00" * 32
            self.init_token = token_block(self.seed)
            self.work = expand32(le64(seed), self.mix_key)
            self.initialized = True

        def ensure_init(self) -> None:
            if not self.initialized:
                # Mirrors 0x3841C00 fallback. With the static public object seen in
                # IDA, the public seed collapses to digest32(expand32(empty, LOADSEED), 0).
                self.init_from_seed(digest64(expand32(b"", LOADSEED), 0))

        def load(self, session_seed: int = 1) -> bool:
            load_block = expand32(b"", LOADSEED)
            self.init_from_seed(digest64(load_block, session_seed))
            if self.phase != 0:
                self.flags |= 0x80
                return False
            self.phase = 1
            self.seed = splitmix64_final(self.seed ^ session_seed ^ LOADED)
            self.token = token_block(self.seed)
            self.mix_native(le64(session_seed), LOADFIN1)
            return True

        def cl(self, i: int, j: int, public_guard: int = 0) -> int:
            self.ensure_init()
            class_seed = splitmix64_final(j ^ u32(public_guard))
            if self.phase == 0:
                self.flags |= 0x80
                return self.seed
            self.phase = 3
            self.prev_seed = self.seed
            self.seed = splitmix64_final(self.seed ^ rol64(class_seed, 11) ^ CLASS)
            self.token = token_block(self.seed)
            self.token32 = u32(self.seed)
            self.mix_native(le64(class_seed), CLASFIN1)
            return self.seed

        def export_snapshot96(self, tag: int) -> bytes:
            out = bytearray(self.work + self.token + self.mask)
            for i in range(96):
                stream = splitmix64_final(tag + self.mix_key - GOLDEN_NEG * i)
                out[i] ^= (stream >> (8 * (i & 7))) & 0xFF
                out[i] = rol8(out[i], (self.mix_counter & 0xFF) + i)
            return bytes(out)

        def mix_native(self, data: bytes | bytearray, tag: int) -> None:
            data = bytes(data)
            if len(data) == 0:
                self.flags |= 4
                return
            snapshot = self.export_snapshot96(tag)
            desc = make_desc(snapshot, u32(tag) ^ self.mix_counter ^ 0x5742464E)
            seed = self.mix_key ^ self.seed ^ tag ^ (self.mix_counter << 32)
            tmp = expand32(data, seed)
            work = bytearray(self.work)
            for lane in range(2):
                block = bytearray(16)
                for j in range(16):
                    idx1 = (j + 16 * lane + desc.perm[(j + lane) & 0xF]) & 0x1F
                    idx2 = (-16 * lane + 8 * (j + 16 * lane)) & 0x1F
                    block[j] = (
                        tmp[j + 16 * lane]
                        ^ work[idx1]
                        ^ self.token[idx2]
                        ^ ((self.mix_key >> (8 * (j & 7))) & 0xFF)
                    )
                out16, crc = wbaes_transform(snapshot, desc, bytes(block), self.mix_key ^ self.seed ^ tag ^ lane, False)
                for k in range(16):
                    idx = (5 * k + desc.perm[(k + lane) & 0xF] + (self.mix_counter & 0xFF) + lane) & 0x1F
                    work[idx] = rol8((work[idx] ^ out16[k]) ^ snapshot[(11 * k + lane) % 96], k + lane + self.mix_counter)
                self.mix_key = splitmix64_final(
                    self.mix_key
                    ^ get64(out16, 0)
                    ^ rol64(get64(out16, 8), 17)
                    ^ crc
                    ^ tag
                    ^ (lane << 48)
                )
            self.work = bytes(work)
            self.token = expand32(self.work, self.mix_key ^ tag ^ NATIVEPA)
            self.mix_counter = u32(self.mix_counter + 1)

        def rp(self, a: int, index: int) -> bytes:
            self.ensure_init()
            out = bytearray(64)
            if self.phase >= 3 and u32(index) == u32(self.pull_index):
                stream = splitmix64_final(self.seed ^ (u32(a) << 32) ^ u32(index))
                for i in range(64):
                    if (i & 7) == 0:
                        stream = splitmix64_final(stream + i + u32(a))
                    out[i] = (stream >> (8 * (i & 7))) & 0xFF
                self.mask = expand32(out, self.seed ^ u32(a))
                self.mix_native(out, (u32(a) | (u32(index) << 32)) ^ PULLFIN0)
                self.pull_index = u64(self.pull_index + 1)
            else:
                self.flags |= 0x80
            return bytes(out)

        pull = rp

        def run(self, input_bytes: bytes | bytearray | None) -> bytes:
            self.ensure_init()
            data = bytes(input_bytes or b"")
            if self._parse_gpk1_ok(data):
                code = self._apply_gpk1(data)
                status = self.flags
            else:
                code, err = self._apply_java_packet(data)
                status = err if err else self.flags
            return le64(code) + le32(status)

        step = run

        def _parse_gpk1_ok(self, data: bytes) -> bool:
            if len(data) < 0xA0 or len(data) > 0x1000:
                return False
            if get32(data, 0) != MAGIC_GPK1 or get32(data, 4) & 0xFFFF != 1 or (get32(data, 4) >> 16) != 24:
                return False
            if get32(data, 20) != 128 or len(data) != 160:
                return False
            tag = get32(data, 0) ^ (get32(data, 8) << 17) ^ (get32(data, 12) << 31) ^ get32(data, 16) ^ get32(data, 20)
            expect = digest64(data[:152], tag ^ PACKETCK)
            return get64(data, 152) == expect

        def _apply_gpk1(self, data: bytes) -> int:
            err = 0
            f8 = get32(data, 8)
            f12 = get32(data, 12)
            if self.phase <= 2:
                err |= 0x80
            if f8 != self.seq:
                err |= 0x08
            if f12 != self.token32:
                err |= 0x10
            if token_block(self.seed) != data[88:120]:
                err |= 0x20
            if any(self.mask) and self.mask != data[56:88]:
                err |= 0x40
            if err:
                self.flags |= err
                self.prev_seed = self.seed
                self.seed = decoy(err, f8, f12)
                return self.seed
            v20 = bytearray(data[120:152])
            for i in range(32):
                v20[i] ^= data[24 + i] ^ data[56 + i] ^ ((self.seed >> (8 * (i & 7))) & 0xFF)
            self.prev_seed = self.seed
            self.seed = digest64(v20, self.seed ^ f8 ^ f12)
            self.token = expand32(v20, self.seed)
            self.mix_native(v20, f8 ^ NSTEP000)
            self.seq = u32(self.seq + 1)
            self.token32 = u32(splitmix64_final(self.seed ^ self.seq))
            return self.seed

        def _is_bstp(self, data: bytes) -> bool:
            return len(data) == 48 and get32(data, 0) == 1 and get32(data, 4) == MAGIC_BSTP and get32(data, 44) != 0

        def _apply_bstp(self, data: bytes) -> int:
            f8 = get32(data, 8)
            f12 = get32(data, 12)
            f16 = get32(data, 16)
            f20 = get32(data, 20)
            f24 = get64(data, 24)
            f32 = get64(data, 32)
            f40 = get32(data, 40)
            self.prev_seed = self.seed
            self.seed = splitmix64_final(self.seed ^ f24 ^ rol64(f32, 9) ^ (f8 << 23) ^ (f16 << 7) ^ f20 ^ f12 ^ f40)
            self.token = expand32(data, self.seed ^ BSTPJAVA)
            self.mix_native(data, BSTPFIN1)
            return self.seed

        def _parse_jstep(self, data: bytes) -> dict[str, int | bytes] | None:
            if len(data) < 48 or len(data) > 0x1000 or get32(data, 0) != 1:
                return None
            payload_len = get32(data, 16)
            if len(data) != payload_len + 48:
                return None
            cmd = get32(data, 4)
            idx = get32(data, 8)
            f12 = get32(data, 12)
            f20 = get32(data, 20)
            f24 = get32(data, 24)
            f28 = get64(data, 28)
            f36 = get64(data, 36)
            payload = data[44 : 44 + payload_len]
            trailer = get32(data, 44 + payload_len)
            if cmd > 7 or idx == 0 or trailer == 0:
                return None
            return {
                "cmd": cmd,
                "idx": idx,
                "f12": f12,
                "payload_len": payload_len,
                "f20": f20,
                "f24": f24,
                "f28": f28,
                "f36": f36,
                "payload": payload,
                "trailer": trailer,
            }

        def _mix_jstep_serialized(self, p: dict[str, int | bytes]) -> None:
            payload = p["payload"]
            assert isinstance(payload, (bytes, bytearray))
            buf = bytearray()
            for key in ("cmd", "idx", "f12", "payload_len", "f20", "f24"):
                buf += le32(int(p[key]))
            buf += le64(int(p["f28"]))
            buf += le64(int(p["f36"]))
            buf += le32(int(p["trailer"]))
            buf += bytes(payload)
            self.mix_native(buf, int(p["cmd"]) ^ (int(p["idx"]) << 19) ^ JSTEP000)

        def _apply_jstep(self, p: dict[str, int | bytes]) -> int:
            self._mix_jstep_serialized(p)
            payload = p["payload"]
            assert isinstance(payload, (bytes, bytearray))
            self.prev_seed = self.seed
            hseed = int(p["f36"]) ^ (int(p["f24"]) << 32) ^ int(p["f20"])
            hd = digest64(payload, hseed)
            self.seed = splitmix64_final(
                self.seed
                ^ hd
                ^ rol64(int(p["f28"]), 13)
                ^ (int(p["idx"]) << 21)
                ^ int(p["f12"])
                ^ int(p["trailer"])
                ^ self.mix_key
            )
            full_len = 48 + int(p["payload_len"])
            # Original input layout is needed for the digest block: version dword
            # followed by fields/payload/trailer.
            original = bytearray()
            original += le32(1)
            original += le32(int(p["cmd"]))
            original += le32(int(p["idx"]))
            original += le32(int(p["f12"]))
            original += le32(int(p["payload_len"]))
            original += le32(int(p["f20"]))
            original += le32(int(p["f24"]))
            original += le64(int(p["f28"]))
            original += le64(int(p["f36"]))
            original += bytes(payload)
            original += le32(int(p["trailer"]))
            self.token = expand32(bytes(original[:full_len]), self.seed ^ JSTEPDIG)
            self.jstep_index = u32(self.jstep_index + 1)
            self.seq = self.jstep_index
            self.token32 = u32(splitmix64_final(self.seed ^ self.seq))
            return self.seed

        def _apply_java_packet(self, data: bytes) -> tuple[int, int]:
            if self.phase <= 2:
                self.flags |= 0x80
                return decoy(0x80, 0, 0), 0x80
            if self._is_bstp(data):
                return self._apply_bstp(data), 0
            p = self._parse_jstep(data)
            if p is None:
                self.flags |= 0x03
                return decoy(3, 0, 0), 3
            if int(p["cmd"]) != self.jstep_index:
                self.flags |= 0x08
                return decoy(8, int(p["cmd"]), int(p["idx"])), 8
            return self._apply_jstep(p), 0


    def run_record_value(record12: bytes) -> tuple[int, int]:
        return get64(record12, 0), get32(record12, 8)

    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_recover_hidden_state_module(recovered_path: Path, work_dir: Path, field_aliases: dict[int, str]) -> types.ModuleType:
    _module_name = "recover_hidden_state"
    """
    Recover and validate the GuardMaster hidden C0000 64-byte reversible state.

    The recovered hidden DEX uses non-printable Unicode identifiers.  This script
    addresses C0000 methods by DEX code offsets / JADX aliases and executes the
    needed bytecode directly with a small Dalvik interpreter.  The interpreter is
    purpose-built for this CTF artifact and intentionally models only the Java
    classes and opcodes used by the hidden state branch.
    """


    import ast
    import json
    import struct
    import unicodedata
    from dataclasses import dataclass, field
    from pathlib import Path
    from typing import Any

    from loguru import logger

    logger.remove()

    from androguard.core.dex import DEX  # noqa: E402


    MASK32 = 0xFFFFFFFF
    MASK64 = 0xFFFFFFFFFFFFFFFF
    DEX_PATH = recovered_path
    C0000_JAVA = work_dir / "unused_C0000.java"


    METHOD_ALIASES: dict[str, int] = {
        "clinit": 0x7021C,
        "init": 0x70DD0,
        "m0_normalize": 0x82330,
        "m1_split": 0x84D78,
        "m2": 0x8A3C4,
        "m3": 0x8B360,
        "m4": 0x8F184,
        "m5": 0x910F4,
        "m6_digest32": 0x95410,
        "m7": 0x97378,
        "m8_block": 0x9890C,
        "m9_stream": 0xA2D78,
        "m10_serialize_state": 0xB9A88,
        "m11_state_mix": 0xC0398,
        "m12": 0xCA4E0,
        "m13_state_permute": 0xCD90C,
        "m14": 0xD1CF4,
        "m15_put_le32": 0xD4FA0,
        "m16": 0xD76D8,
        "m17": 0xE0374,
        "m18_put_le64": 0xE25B8,
        "m19_clock_f6": 0xE4710,
        "m20": 0xE6874,
        "m21_rot": 0xECCF0,
        "m22_wrap_serialized": 0xEE7F4,
        "m23_round": 0xF8290,
        "m24_final_packet": 0xFF004,
        "m25_step_token_mix": 0x101760,
        "m26_get_f6": 0x107E24,
        "m27_getter": 0x1082F8,
        "m28_getter": 0x1087B4,
        "m29_permute_mix": 0x108CAC,
        "m30_fixed_commit_mix": 0x10C680,
        "m31_getter": 0x111F98,
        "m32_copy_f10": 0x112584,
        "m33_getter": 0x1133A4,
        "m34_commit_round_mix": 0x113958,
        "m35_getter": 0x118450,
        "m36_get_f7": 0x118990,
        "m37_final_digest_cache": 0x118F14,
        "m38_get_f13": 0x11E358,
        "m39_pull_merge_mix": 0x11E95C,
        "m40_token_round_mix": 0x124A74,
        "m41_bootstrap_return_mix": 0x132E64,
        "m42_get_f20": 0x13C0D0,
        "m43_getter": 0x13C6E4,
        "m44_getter": 0x13CBE8,
        "m45_final_stage_mix": 0x13D0AC,
        "m46_getter": 0x13FD68,
        "m47_digest_mix": 0x140358,
        "m48_getter": 0x14426C,
        "m49_commit_boolean_mix": 0x14484C,
        "m50_getter": 0x1476CC,
    }


    def u32(x: int) -> int:
        return x & MASK32


    def s32(x: int) -> int:
        x &= MASK32
        return x - 0x100000000 if x & 0x80000000 else x


    def u64(x: int) -> int:
        return x & MASK64


    def s64(x: int) -> int:
        x &= MASK64
        return x - 0x10000000000000000 if x & 0x8000000000000000 else x


    def s8(x: int) -> int:
        x &= 0xFF
        return x - 0x100 if x & 0x80 else x


    def rol32(x: int, n: int) -> int:
        n &= 31
        x &= MASK32
        return ((x << n) | (x >> ((32 - n) & 31))) & MASK32


    def rol64(x: int, n: int) -> int:
        n &= 63
        x &= MASK64
        return ((x << n) | (x >> ((64 - n) & 63))) & MASK64


    def parse_method_slots(desc: str, include_this: bool) -> list[str]:
        desc = desc.replace(" ", "")
        args = ["this"] if include_this else []
        inside = desc[desc.index("(") + 1 : desc.index(")")]
        i = 0
        while i < len(inside):
            c = inside[i]
            if c in "ZBSCIF":
                args.append(c)
                i += 1
            elif c in "JD":
                args.append(c)
                i += 1
            elif c == "L":
                j = inside.index(";", i) + 1
                args.append(inside[i:j])
                i = j
            elif c == "[":
                j = i
                while inside[j] == "[":
                    j += 1
                if inside[j] == "L":
                    j = inside.index(";", j) + 1
                else:
                    j += 1
                args.append(inside[i:j])
                i = j
            else:
                raise ValueError(f"bad descriptor {desc!r} at {i}")
        return args


    def slot_width(t: str) -> int:
        return 2 if t in ("J", "D") else 1


    def result_kind(desc: str) -> str:
        desc = desc.replace(" ", "")
        return desc[desc.index(")") + 1 :]


    def le32(x: int) -> bytes:
        return struct.pack("<I", u32(x))


    def le64(x: int) -> bytes:
        return struct.pack("<Q", u64(x))


    def get32(buf: bytes | bytearray, off: int) -> int:
        return struct.unpack_from("<I", buf, off)[0]


    def get64(buf: bytes | bytearray, off: int) -> int:
        return struct.unpack_from("<Q", buf, off)[0]


    @dataclass
    class ByteBuffer:
        buf: bytearray
        pos: int = 0

        @classmethod
        def allocate(cls, n: int) -> "ByteBuffer":
            return cls(bytearray(n))

        def order(self, _order: Any) -> "ByteBuffer":
            return self

        def put_int(self, x: int) -> "ByteBuffer":
            self.buf[self.pos : self.pos + 4] = le32(x)
            self.pos += 4
            return self

        def put(self, data: bytes | bytearray) -> "ByteBuffer":
            self.buf[self.pos : self.pos + len(data)] = bytes(data)
            self.pos += len(data)
            return self

        def array(self) -> bytearray:
            return bytearray(self.buf)


    @dataclass
    class JavaObj:
        cls: str
        fields: dict[int, Any] = field(default_factory=dict)


    @dataclass
    class MethodBody:
        encoded: Any
        cls_name: str
        name: str
        desc: str
        code_off: int
        registers_size: int
        ins_size: int
        instructions: list[Any]
        offsets: list[int]
        off_to_index: dict[int, int]
        payloads: dict[int, bytes]


    class HiddenDexVM:
        def __init__(self, dex_path: Path = DEX_PATH, java_path: Path = C0000_JAVA):
            self.dex = DEX(dex_path.read_bytes())
            self.classes = list(self.dex.get_classes())
            self.c0000_cls = self.classes[1].get_name()
            self.field_alias = self._load_field_aliases(java_path)
            self.static_fields: dict[int, Any] = {}
            self.methods_by_ref: dict[int, MethodBody] = {}
            self.methods_by_off: dict[int, MethodBody] = {}
            self.trace_code_offsets: set[int] = set()
            self.trace_detail_offsets: set[tuple[int, int]] = set()
            self.trace_register_limit = 14
            self.trace_predicate: Any = None
            self.event_hook: Any = None
            self.trace_log: list[str] = []
            self._load_methods()
            self._clinit_done = False

        def _load_field_aliases(self, java_path: Path) -> dict[int, str]:
            lines = java_path.read_text().splitlines()[:90]
            actual_to_alias: dict[str, str] = {}
            pending: str | None = None
            for line in lines:
                if "renamed from:" in line:
                    pending = line.split("renamed from:", 1)[1].split(", reason:", 1)[0].strip()
                if pending and ";" in line and " f" in line:
                    before = line.split("=", 1)[0].strip().rstrip(";")
                    alias = before.split()[-1]
                    if alias.startswith("f"):
                        actual_to_alias[pending] = alias
                        pending = None
            out: dict[int, str] = {}
            for idx, field_id in enumerate(self.dex.get_fields()):
                if field_id.get_class_name() == self.classes[1].get_name():
                    out[idx] = actual_to_alias.get(field_id.get_name(), f"field_{idx}")
            return out

        def _load_methods(self) -> None:
            encoded_lookup: dict[tuple[str, str, str], Any] = {}
            for cls in self.classes:
                for method in cls.get_methods():
                    encoded_lookup[(cls.get_name(), method.get_name(), method.get_descriptor())] = method
            for idx, method_id in enumerate(self.dex.get_methods()):
                key = (method_id.get_class_name(), method_id.get_name(), method_id.get_descriptor())
                encoded = encoded_lookup.get(key)
                if encoded is None or encoded.get_code() is None:
                    continue
                body = self._body_from_method(encoded, key[0])
                self.methods_by_ref[idx] = body
                self.methods_by_off[body.code_off] = body

        def _body_from_method(self, method: Any, cls_name: str) -> MethodBody:
            code = method.get_code()
            instructions = list(method.get_instructions())
            offsets: list[int] = []
            off = 0
            payloads: dict[int, bytes] = {}
            for ins in instructions:
                offsets.append(off)
                if ins.get_name() == "fill-array-data-payload":
                    raw = ins.get_raw()
                    width = int.from_bytes(raw[2:4], "little")
                    size = int.from_bytes(raw[4:8], "little")
                    payloads[off] = raw[8 : 8 + width * size]
                off += ins.get_length()
            return MethodBody(
                encoded=method,
                cls_name=cls_name,
                name=method.get_name(),
                desc=method.get_descriptor(),
                code_off=code.get_off(),
                registers_size=code.get_registers_size(),
                ins_size=code.get_ins_size(),
                instructions=instructions,
                offsets=offsets,
                off_to_index={o: i for i, o in enumerate(offsets)},
                payloads=payloads,
            )

        def ensure_clinit(self) -> None:
            if not self._clinit_done:
                self._clinit_done = True
                self.call_offset(METHOD_ALIASES["clinit"], [])

        def new_c0000(self) -> JavaObj:
            self.ensure_clinit()
            obj = JavaObj(self.c0000_cls)
            # Static finals are held separately.  Instance fields default to Java zero.
            for idx, alias in self.field_alias.items():
                if alias in {"f8xa5a7934", "f10x7fc29877", "f11x99d9d52c", "f12x978d0ca3"}:
                    obj.fields.setdefault(idx, None)
                elif alias in {"f13xcb34ab73", "f17xc24bec61", "f20xb9c11465"}:
                    obj.fields.setdefault(idx, 0)
                elif alias in {"f9x7ea3f6dd", "f16x11cdf272", "f18x8da453fc"}:
                    obj.fields.setdefault(idx, False)
                elif not alias.startswith("f0") and alias not in {
                    "f1x50b6db62",
                    "f2x552af10a",
                    "f3xef540ca4",
                    "f4",
                    "f5",
                }:
                    obj.fields.setdefault(idx, 0)
            return obj

        def call_alias(self, alias: str, args: list[Any]) -> Any:
            return self.call_offset(METHOD_ALIASES[alias], args)

        def call_offset(self, code_off: int, args: list[Any]) -> Any:
            body = self.methods_by_off[code_off]
            return self._exec(body, args)

        def _setup_registers(self, body: MethodBody, args: list[Any], include_this: bool | None = None) -> list[Any]:
            if include_this is None:
                # Constructors and virtual/direct instance methods have "this" in
                # args.  Static callers pass exactly the descriptor argument count.
                include_this = bool(args and isinstance(args[0], JavaObj))
            regs: list[Any] = [0] * body.registers_size
            types = parse_method_slots(body.desc, include_this)
            slots = sum(slot_width(t) for t in types)
            start = body.registers_size - slots
            r = start
            for t, val in zip(types, args):
                regs[r] = val
                r += slot_width(t)
            return regs

        def _invoke_regs(self, ins: Any) -> tuple[list[int], int]:
            ops = ins.get_operands()
            method_idx = ops[-1][1]
            if ins.get_name().endswith("/range"):
                start = ops[0][1]
                method_id = self.dex.get_methods()[method_idx]
                include_this = not ins.get_name().startswith("invoke-static")
                count = sum(slot_width(t) for t in parse_method_slots(method_id.get_descriptor(), include_this))
                return list(range(start, start + count)), method_idx
            return [op[1] for op in ops[:-1]], method_idx

        def _field_id(self, ins: Any) -> int:
            return ins.get_operands()[-1][1]

        def _branch_target(self, off: int, ins: Any) -> int:
            delta_code_units = ins.get_operands()[-1][1]
            return off + delta_code_units * 2

        def _array_new(self, type_desc: str, size: int) -> Any:
            size = s32(size)
            if size < 0:
                raise ValueError(f"negative array size {size}")
            if type_desc == "[B":
                return bytearray(size)
            if type_desc == "[I":
                return [0] * size
            if type_desc in ("[[B", "[Ljava/lang/Object;") or type_desc.startswith("[L") or type_desc.startswith("[["):
                return [None] * size
            raise NotImplementedError(f"new-array type {type_desc}")

        def _array_get(self, arr: Any, idx: int, signed_byte: bool = False) -> Any:
            idx = s32(idx)
            val = arr[idx]
            return s8(val) if signed_byte else val

        def _array_put(self, arr: Any, idx: int, val: Any, byte: bool = False) -> None:
            idx = s32(idx)
            if byte:
                arr[idx] = s32(val) & 0xFF
            else:
                arr[idx] = val

        def _java_invoke(self, method_idx: int, args: list[Any], invoke_name: str) -> tuple[bool, Any]:
            method_id = self.dex.get_methods()[method_idx]
            cls = method_id.get_class_name()
            name = method_id.get_name()
            desc = method_id.get_descriptor()

            if cls == "Ljava/lang/Object;" and name == "<init>":
                return True, None
            if cls == "Ljava/lang/Integer;" and name == "rotateLeft":
                return True, s32(rol32(args[0], args[1]))
            if cls == "Ljava/lang/Long;" and name == "rotateLeft":
                return True, s64(rol64(args[0], args[1]))
            if cls == "Ljava/lang/Math;" and name == "min":
                return True, min(s32(args[0]), s32(args[1]))
            if cls == "Ljava/lang/System;" and name == "arraycopy":
                src, src_pos, dst, dst_pos, length = args
                tmp = [src[s32(src_pos) + i] for i in range(s32(length))]
                for i, b in enumerate(tmp):
                    dst[s32(dst_pos) + i] = b
                return True, None
            if cls == "Ljava/util/Arrays;" and name == "fill":
                arr = args[0]
                val = args[1]
                if isinstance(arr, bytearray):
                    arr[:] = bytes([s32(val) & 0xFF]) * len(arr)
                else:
                    for i in range(len(arr)):
                        arr[i] = val
                return True, None
            if cls == "Ljava/util/Arrays;" and name == "copyOf":
                arr, n = args
                n = s32(n)
                if isinstance(arr, bytearray):
                    out = bytearray(n)
                    out[: min(len(arr), n)] = arr[: min(len(arr), n)]
                    return True, out
                out = [0] * n
                out[: min(len(arr), n)] = arr[: min(len(arr), n)]
                return True, out
            if cls == "Ljava/util/Arrays;" and name == "copyOfRange":
                arr, start, end = args
                start = s32(start)
                end = s32(end)
                if isinstance(arr, bytearray):
                    return True, bytearray(arr[start:end])
                return True, list(arr[start:end])
            if cls == "Ljava/nio/ByteBuffer;" and name == "allocate":
                return True, ByteBuffer.allocate(s32(args[0]))
            if cls == "Ljava/nio/ByteBuffer;" and name == "order":
                return True, args[0].order(args[1])
            if cls == "Ljava/nio/ByteBuffer;" and name == "putInt":
                return True, args[0].put_int(args[1])
            if cls == "Ljava/nio/ByteBuffer;" and name == "put":
                return True, args[0].put(args[1])
            if cls == "Ljava/nio/ByteBuffer;" and name == "array":
                return True, args[0].array()
            if cls == "Ljava/text/Normalizer;" and name == "normalize":
                # args[1] is Normalizer.Form.NFKC; the exact enum object is not
                # needed for this hidden branch.
                return True, unicodedata.normalize("NFKC", args[0])
            if cls == "Ljava/lang/String;" and name == "trim":
                return True, args[0].strip()
            if cls == "Ljava/lang/String;" and name == "replace":
                return True, args[0].replace(args[1], args[2])
            if cls == "Ljava/lang/String;" and name == "getBytes":
                return True, bytearray(args[0].encode("utf-8"))
            if cls in ("Ljava/nio/ByteOrder;", "Ljava/text/Normalizer$Form;", "Ljava/nio/charset/StandardCharsets;"):
                return True, object()

            body = self.methods_by_ref.get(method_idx)
            if body is not None:
                return True, self._exec(body, args)
            raise NotImplementedError(f"invoke {invoke_name} {cls}->{name}{desc}")

        def _exec(self, body: MethodBody, args: list[Any]) -> Any:
            regs = self._setup_registers(body, args)
            pc = 0
            last_result: Any = None
            steps = 0
            while True:
                if steps > 2_000_000:
                    raise RuntimeError(f"step limit in method off {body.code_off:#x} pc {pc:#x}")
                steps += 1
                idx = body.off_to_index.get(pc)
                if idx is None:
                    raise RuntimeError(f"bad pc {pc:#x} in method {body.code_off:#x}")
                ins = body.instructions[idx]
                off = body.offsets[idx]
                name = ins.get_name()
                ops = ins.get_operands()
                next_pc = off + ins.get_length()
                if self.event_hook is not None:
                    self.event_hook(body, off, regs, ins)
                if body.code_off in self.trace_code_offsets:
                    self.trace_log.append(f"{body.code_off:#x}+{off:#06x} {name} {ins.get_output()}")
                if self.trace_predicate is not None and self.trace_predicate(body, off, regs, ins):
                    def trace_value(v: Any) -> Any:
                        if isinstance(v, (bytes, bytearray)):
                            return bytes(v).hex()
                        if isinstance(v, list):
                            return [trace_value(x) for x in v]
                        if isinstance(v, JavaObj):
                            return f"<{v.cls} fields={len(v.fields)}>"
                        return v

                    snap = {f"v{i}": trace_value(v) for i, v in enumerate(regs) if i < self.trace_register_limit}
                    self.trace_log.append(f"PRED {body.code_off:#x}+{off:#06x} {name} {ins.get_output()} {json.dumps(snap, ensure_ascii=False)}")
                if (body.code_off, off) in self.trace_detail_offsets:
                    def trace_value(v: Any) -> Any:
                        if isinstance(v, (bytes, bytearray)):
                            return bytes(v).hex()
                        if isinstance(v, list):
                            return [trace_value(x) for x in v]
                        if isinstance(v, JavaObj):
                            return f"<{v.cls} fields={len(v.fields)}>"
                        return v

                    snap = {f"v{i}": trace_value(v) for i, v in enumerate(regs) if i < self.trace_register_limit}
                    self.trace_log.append(f"DETAIL {body.code_off:#x}+{off:#06x} {name} {json.dumps(snap, ensure_ascii=False)}")

                if name == "nop" or name.endswith("-payload"):
                    pass
                elif name in ("const/4", "const/16", "const"):
                    regs[ops[0][1]] = s32(ops[1][1])
                elif name in ("const-wide/16", "const-wide"):
                    regs[ops[0][1]] = s64(ops[1][1])
                elif name == "const/high16":
                    regs[ops[0][1]] = s32(ops[1][1])
                elif name == "const-string":
                    regs[ops[0][1]] = ops[1][2]
                elif name in ("move", "move/from16", "move-object", "move-object/from16", "move-wide/from16"):
                    regs[ops[0][1]] = regs[ops[1][1]]
                elif name == "move-result" or name == "move-result-object" or name == "move-result-wide":
                    regs[ops[0][1]] = last_result
                elif name == "move-exception":
                    regs[ops[0][1]] = None
                elif name == "goto/32":
                    next_pc = self._branch_target(off, ins)
                elif name.startswith("if-"):
                    vals = [regs[op[1]] for op in ops if op[0].name == "REGISTER"]
                    take = False
                    if name == "if-eqz":
                        take = vals[0] == 0 or vals[0] is False or vals[0] is None
                    elif name == "if-nez":
                        take = not (vals[0] == 0 or vals[0] is False or vals[0] is None)
                    elif name == "if-gtz":
                        take = s32(vals[0]) > 0
                    elif name == "if-gez":
                        take = s32(vals[0]) >= 0
                    elif name == "if-ltz":
                        take = s32(vals[0]) < 0
                    elif name == "if-lez":
                        take = s32(vals[0]) <= 0
                    elif name == "if-eq":
                        take = vals[0] == vals[1]
                    elif name == "if-ne":
                        take = vals[0] != vals[1]
                    elif name == "if-lt":
                        take = s32(vals[0]) < s32(vals[1])
                    elif name == "if-ge":
                        take = s32(vals[0]) >= s32(vals[1])
                    elif name == "if-gt":
                        take = s32(vals[0]) > s32(vals[1])
                    else:
                        raise NotImplementedError(name)
                    if take:
                        next_pc = self._branch_target(off, ins)
                elif name == "add-int":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] + regs[ops[2][1]])
                elif name == "add-int/2addr":
                    regs[ops[0][1]] = s32(regs[ops[0][1]] + regs[ops[1][1]])
                elif name == "add-int/lit8":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] + ops[2][1])
                elif name == "sub-int":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] - regs[ops[2][1]])
                elif name == "sub-int/2addr":
                    regs[ops[0][1]] = s32(regs[ops[0][1]] - regs[ops[1][1]])
                elif name == "rsub-int/lit8":
                    regs[ops[0][1]] = s32(ops[2][1] - regs[ops[1][1]])
                elif name == "mul-int":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] * regs[ops[2][1]])
                elif name == "mul-int/2addr":
                    regs[ops[0][1]] = s32(regs[ops[0][1]] * regs[ops[1][1]])
                elif name == "mul-int/lit8":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] * ops[2][1])
                elif name == "div-int/lit8":
                    regs[ops[0][1]] = s32(int(s32(regs[ops[1][1]]) / ops[2][1]))
                elif name == "rem-int":
                    regs[ops[0][1]] = s32(s32(regs[ops[1][1]]) % s32(regs[ops[2][1]]))
                elif name == "rem-int/2addr":
                    regs[ops[0][1]] = s32(s32(regs[ops[0][1]]) % s32(regs[ops[1][1]]))
                elif name == "xor-int":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] ^ regs[ops[2][1]])
                elif name == "xor-int/2addr":
                    regs[ops[0][1]] = s32(regs[ops[0][1]] ^ regs[ops[1][1]])
                elif name == "xor-int/lit8":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] ^ ops[2][1])
                elif name == "and-int/lit8":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] & ops[2][1])
                elif name == "and-int/lit16":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] & ops[2][1])
                elif name == "or-int/2addr":
                    regs[ops[0][1]] = s32(regs[ops[0][1]] | regs[ops[1][1]])
                elif name == "or-int/lit8":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] | ops[2][1])
                elif name == "shl-int":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] << (regs[ops[2][1]] & 31))
                elif name == "shl-int/lit8":
                    regs[ops[0][1]] = s32(regs[ops[1][1]] << (ops[2][1] & 31))
                elif name == "ushr-int":
                    regs[ops[0][1]] = s32((regs[ops[1][1]] & MASK32) >> (regs[ops[2][1]] & 31))
                elif name == "ushr-int/2addr":
                    regs[ops[0][1]] = s32((regs[ops[0][1]] & MASK32) >> (regs[ops[1][1]] & 31))
                elif name == "ushr-int/lit8":
                    regs[ops[0][1]] = s32((regs[ops[1][1]] & MASK32) >> (ops[2][1] & 31))
                elif name == "xor-long/2addr":
                    regs[ops[0][1]] = s64(regs[ops[0][1]] ^ regs[ops[1][1]])
                elif name == "and-long/2addr":
                    regs[ops[0][1]] = s64(regs[ops[0][1]] & regs[ops[1][1]])
                elif name == "shl-long":
                    regs[ops[0][1]] = s64(regs[ops[1][1]] << (regs[ops[2][1]] & 63))
                elif name == "shl-long/2addr":
                    regs[ops[0][1]] = s64(regs[ops[0][1]] << (regs[ops[1][1]] & 63))
                elif name == "ushr-long":
                    regs[ops[0][1]] = s64((regs[ops[1][1]] & MASK64) >> (regs[ops[2][1]] & 63))
                elif name == "ushr-long/2addr":
                    regs[ops[0][1]] = s64((regs[ops[0][1]] & MASK64) >> (regs[ops[1][1]] & 63))
                elif name == "cmp-long":
                    a = s64(regs[ops[1][1]])
                    b = s64(regs[ops[2][1]])
                    regs[ops[0][1]] = (a > b) - (a < b)
                elif name == "int-to-byte":
                    regs[ops[0][1]] = s8(regs[ops[1][1]])
                elif name == "int-to-long":
                    regs[ops[0][1]] = s64(s32(regs[ops[1][1]]))
                elif name == "long-to-int":
                    regs[ops[0][1]] = s32(regs[ops[1][1]])
                elif name == "new-array":
                    regs[ops[0][1]] = self._array_new(ops[2][2], regs[ops[1][1]])
                elif name in ("filled-new-array", "filled-new-array/range"):
                    type_desc = ops[-1][2]
                    vals = [regs[op[1]] for op in ops[:-1]]
                    arr = bytearray((s32(v) & 0xFF) for v in vals) if type_desc == "[B" else list(vals)
                    last_result = arr
                elif name == "array-length":
                    regs[ops[0][1]] = len(regs[ops[1][1]])
                elif name == "aget":
                    regs[ops[0][1]] = self._array_get(regs[ops[1][1]], regs[ops[2][1]])
                elif name == "aget-byte":
                    regs[ops[0][1]] = self._array_get(regs[ops[1][1]], regs[ops[2][1]], signed_byte=True)
                elif name == "aget-object":
                    regs[ops[0][1]] = self._array_get(regs[ops[1][1]], regs[ops[2][1]])
                elif name == "aput":
                    self._array_put(regs[ops[1][1]], regs[ops[2][1]], regs[ops[0][1]])
                elif name == "aput-byte":
                    self._array_put(regs[ops[1][1]], regs[ops[2][1]], regs[ops[0][1]], byte=True)
                elif name == "aput-object":
                    self._array_put(regs[ops[1][1]], regs[ops[2][1]], regs[ops[0][1]])
                elif name == "fill-array-data":
                    arr = regs[ops[0][1]]
                    target = self._branch_target(off, ins)
                    payload = body.payloads[target]
                    if isinstance(arr, bytearray):
                        arr[: len(payload)] = payload
                    else:
                        width = 4
                        for i in range(0, len(payload), width):
                            arr[i // width] = s32(int.from_bytes(payload[i : i + width], "little"))
                elif name in ("iget", "iget-object", "iget-boolean", "iget-wide"):
                    regs[ops[0][1]] = regs[ops[1][1]].fields.get(self._field_id(ins), 0)
                elif name in ("iput", "iput-object", "iput-boolean", "iput-wide"):
                    regs[ops[1][1]].fields[self._field_id(ins)] = regs[ops[0][1]]
                elif name in ("sget", "sget-boolean", "sget-wide", "sget-object"):
                    regs[ops[0][1]] = self.static_fields.get(self._field_id(ins))
                elif name in ("sput", "sput-boolean", "sput-wide", "sput-object"):
                    self.static_fields[self._field_id(ins)] = regs[ops[0][1]]
                elif name.startswith("invoke-"):
                    reg_ids, method_idx = self._invoke_regs(ins)
                    call_args = [regs[r] for r in reg_ids]
                    handled, last_result = self._java_invoke(method_idx, call_args, name)
                    if not handled:
                        raise NotImplementedError(ins.get_output())
                elif name == "return":
                    return regs[ops[0][1]]
                elif name == "return-object":
                    return regs[ops[0][1]]
                elif name == "return-wide":
                    return regs[ops[0][1]]
                elif name == "return-void":
                    return None
                else:
                    raise NotImplementedError(f"{name} at {body.code_off:#x}+{off:#x}")

                pc = next_pc


    def parse_final_packet(packet: bytes) -> dict[str, Any]:
        if len(packet) != 184:
            raise ValueError(f"final packet length is {len(packet)}, expected 184")
        return {
            "version": get32(packet, 0),
            "command": get32(packet, 4),
            "wrapped_serialized": packet[8:120],
            "final_state": packet[120:184],
        }


    def build_final_object(vm: HiddenDexVM, parsed: dict[str, Any]) -> JavaObj:
        obj = vm.new_c0000()
        # Minimal object for m24 validation after the wrapped serializer is decoded
        # or when a caller injects known final fields.  The final 64-byte state and
        # f14 are always directly present in the packet.
        alias_to_id = {alias: idx for idx, alias in vm.field_alias.items()}
        obj.fields[alias_to_id["f8xa5a7934"]] = bytearray(parsed["final_state"])
        obj.fields[alias_to_id["f14x69ab180b"]] = parsed["command"]
        return obj


    def try_forward_wrap(vm: HiddenDexVM, raw: bytes, seed: int) -> bytes:
        return bytes(vm.call_alias("m22_wrap_serialized", [bytearray(raw), seed]))


    M22_SEED1 = 0x4648445A
    M22_SEED2 = 0x750C0109


    def _m4_inverse_table(vm: HiddenDexVM, key: int) -> list[int]:
        # C0000.m4 ultimately feeds the second argument only as a rotate count /
        # 5-bit lane selector.  Normalizing here keeps m22 inversion fast while
        # still validating the table through the bytecode implementation.
        key &= 31
        inv = [-1] * 256
        for x in range(256):
            y = vm.call_alias("m4", [x, key]) & 0xFF
            if inv[y] != -1:
                raise ValueError(f"m4 is not bijective for key {key:#x}: {inv[y]:#x}/{x:#x}->{y:#x}")
            inv[y] = x
        if any(v < 0 for v in inv):
            raise ValueError(f"m4 inverse table for key {key:#x} is incomplete")
        return inv


    def invert_m22_wrap(vm: HiddenDexVM, wrapped: bytes | bytearray, seed: int) -> bytes:
        """Invert C0000.m22x7cad926 for the serializer seed used by m10/m24."""
        if seed != 8:
            raise NotImplementedError(f"only the observed serializer command seed 8 is implemented, got {seed}")
        n = len(wrapped)
        key1 = bytes(vm.call_alias("m9_stream", [n, M22_SEED1]))
        key2 = bytes(vm.call_alias("m9_stream", [n, M22_SEED2]))
        inv_cache: dict[int, list[int]] = {}

        def inv_m4(y: int, key: int) -> int:
            key &= 31
            table = inv_cache.get(key)
            if table is None:
                table = _m4_inverse_table(vm, key)
                inv_cache[key] = table
            return table[y & 0xFF]

        data = bytearray(wrapped)
        # m22 second substitution loop, bytecode invoke at 0xee7f4+0x8ec2.
        for i in range(n):
            mixed = inv_m4(data[i], (key2[(3 + 11 * i) % n] & 0xFF) ^ i)
            data[i] = (mixed - (key2[i] & 0xFF) - 19 * i) & 0xFF
        # m8 forward is called with false at 0xee7f4+0x4a78; true selects inverse.
        data = bytearray(vm.call_alias("m8_block", [data, True]))
        # m22 first substitution loop, bytecode invoke at 0xee7f4+0x38a8.
        for i in range(n):
            mixed = inv_m4(data[i], (key1[(5 + 7 * i) % n] & 0xFF) + i)
            data[i] = mixed ^ (key1[i] & 0xFF)
        return bytes(data)


    def field_id_by_alias(vm: HiddenDexVM) -> dict[str, int]:
        return {alias: idx for idx, alias in vm.field_alias.items()}


    def make_sentinel_object(vm: HiddenDexVM) -> JavaObj:
        ids = field_id_by_alias(vm)
        obj = vm.new_c0000()
        obj.fields[ids["f8xa5a7934"]] = bytearray(range(64))
        obj.fields[ids["f6x6868a7e9"]] = 0x11111111
        obj.fields[ids["f15xbab9595e"]] = 0x22222222
        obj.fields[ids["f19xe71db4e0"]] = 0x33333333
        obj.fields[ids["f21x843c54e2"]] = 0x44444444
        obj.fields[ids["f7"]] = 0x55555555
        obj.fields[ids["f23xf2ae566b"]] = 0x66666666
        obj.fields[ids["f17xc24bec61"]] = 0x1111111122222222
        obj.fields[ids["f20xb9c11465"]] = 0x3333333344444444
        obj.fields[ids["f13xcb34ab73"]] = 0x5555555566666666
        obj.fields[ids["f14x69ab180b"]] = 8
        return obj


    def infer_serialized_layout(vm: HiddenDexVM) -> list[dict[str, Any]]:
        """Infer m10 raw layout by serializing a sentinel object and unwrapping it."""
        wrapped = bytes(vm.call_alias("m10_serialize_state", [make_sentinel_object(vm)]))
        raw = invert_m22_wrap(vm, wrapped, 8)
        expected = {
            "f8xa5a7934": bytes(range(64)),
            "f6x6868a7e9": le32(0x11111111),
            "f15xbab9595e": le32(0x22222222),
            "f19xe71db4e0": le32(0x33333333),
            "f21x843c54e2": le32(0x44444444),
            "f7": le32(0x55555555),
            "f23xf2ae566b": le32(0x66666666),
            "f17xc24bec61": le64(0x1111111122222222),
            "f20xb9c11465": le64(0x3333333344444444),
            "f13xcb34ab73": le64(0x5555555566666666),
        }
        layout = []
        used: set[int] = set()
        for alias, needle in expected.items():
            start = raw.find(needle)
            if start < 0:
                raise ValueError(f"could not locate sentinel for {alias}")
            layout.append({"field": alias, "offset": start, "size": len(needle), "hex": needle.hex()})
            used.update(range(start, start + len(needle)))
        gaps = []
        gap_start: int | None = None
        for i in range(len(raw) + 1):
            if i < len(raw) and i not in used:
                if gap_start is None:
                    gap_start = i
            elif gap_start is not None:
                gaps.append({"field": "unmapped_gap", "offset": gap_start, "size": i - gap_start, "hex": raw[gap_start:i].hex()})
                gap_start = None
        return sorted(layout + gaps, key=lambda x: x["offset"])


    def parse_raw_serialized(raw: bytes, layout: list[dict[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {"raw_len": len(raw), "raw_hex": raw.hex()}
        fields: dict[str, Any] = {}
        for item in layout:
            name = item["field"]
            if name == "unmapped_gap":
                continue
            off = item["offset"]
            size = item["size"]
            chunk = raw[off : off + size]
            if size == 64:
                fields[name] = {"offset": off, "size": size, "hex": chunk.hex()}
            elif size == 8:
                fields[name] = {
                    "offset": off,
                    "size": size,
                    "u64": get64(chunk, 0),
                    "hex": chunk.hex(),
                }
            elif size == 4:
                fields[name] = {
                    "offset": off,
                    "size": size,
                    "u32": get32(chunk, 0),
                    "hex": chunk.hex(),
                }
            else:
                fields[name] = {"offset": off, "size": size, "hex": chunk.hex()}
        out["fields"] = fields
        return out


    def _load_field_aliases(self, java_path):
        return dict(field_aliases)

    HiddenDexVM._load_field_aliases = _load_field_aliases
    HiddenDexVM.__init__.__defaults__ = (DEX_PATH, C0000_JAVA)

    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_c0000_primitives_module() -> types.ModuleType:
    _module_name = "c0000_primitives"
    """C0000 primitive forward/inverse helpers backed by recovered DEX bytecode."""


    import copy
    import json
    import random
    from typing import Any

    import recover_hidden_state as hs  # noqa: E402

    MASK32 = 0xFFFFFFFF
    ROUND_XOR_DELTA = 0x6D2B79F5
    M11_SECONDARY_XOR = 0x5A17C3E1

    TARGET_PRIMITIVES = [
        "m11_state_mix",
        "m13_state_permute",
        "m23_round",
        "m25_step_token_mix",
        "m29_permute_mix",
        "m30_fixed_commit_mix",
        "m34_commit_round_mix",
        "m39_pull_merge_mix",
        "m40_token_round_mix",
        "m41_bootstrap_return_mix",
        "m45_final_stage_mix",
        "m47_digest_mix",
        "m49_commit_boolean_mix",
    ]

    SERIALIZED_FIELDS = [
        "f8xa5a7934",
        "f6x6868a7e9",
        "f15xbab9595e",
        "f19xe71db4e0",
        "f21x843c54e2",
        "f7",
        "f23xf2ae566b",
        "f17xc24bec61",
        "f20xb9c11465",
        "f13xcb34ab73",
    ]

    SCALAR_M11_FIELDS = ["f14x69ab180b", "f22x73e78f8b", "f7"]


    def u32(x: int) -> int:
        return x & MASK32


    def signed_arg32(x: int) -> int:
        return hs.s32(x)


    def deep_clone(value: Any) -> Any:
        if isinstance(value, bytearray):
            return bytearray(value)
        if isinstance(value, bytes):
            return bytes(value)
        if isinstance(value, list):
            return [deep_clone(v) for v in value]
        if isinstance(value, dict):
            return {k: deep_clone(v) for k, v in value.items()}
        return copy.deepcopy(value)


    def jsonable(value: Any) -> Any:
        if isinstance(value, bytearray):
            return {"type": "bytes", "hex": bytes(value).hex(), "len": len(value)}
        if isinstance(value, bytes):
            return {"type": "bytes", "hex": value.hex(), "len": len(value)}
        if isinstance(value, list):
            return [jsonable(v) for v in value]
        if isinstance(value, hs.JavaObj):
            return {"type": "JavaObj", "class": value.cls}
        if isinstance(value, bool) or value is None or isinstance(value, str):
            return value
        if isinstance(value, int):
            return value
        return repr(value)


    def alias_to_id(vm: hs.HiddenDexVM) -> dict[str, int]:
        return {alias: idx for idx, alias in vm.field_alias.items()}


    def snapshot_fields(vm: hs.HiddenDexVM, obj: hs.JavaObj) -> dict[str, Any]:
        return {alias: deep_clone(obj.fields.get(idx)) for idx, alias in vm.field_alias.items()}


    def restore_fields(vm: hs.HiddenDexVM, obj: hs.JavaObj, snapshot: dict[str, Any]) -> None:
        ids = alias_to_id(vm)
        for alias, value in snapshot.items():
            if alias in ids:
                obj.fields[ids[alias]] = deep_clone(value)


    def snapshots_equal(a: dict[str, Any], b: dict[str, Any]) -> bool:
        return json.dumps(jsonable(a), sort_keys=True) == json.dumps(jsonable(b), sort_keys=True)


    def m17_byte(vm: hs.HiddenDexVM, seed: int, lane: int, index: int) -> int:
        return vm.call_alias("m17", [signed_arg32(seed), signed_arg32(lane), signed_arg32(index)]) & 0xFF


    def m21_u32(vm: hs.HiddenDexVM, x: int, y: int) -> int:
        return vm.call_alias("m21_rot", [signed_arg32(x), signed_arg32(y)]) & MASK32


    def m4_byte(vm: hs.HiddenDexVM, x: int, key: int) -> int:
        return vm.call_alias("m4", [x & 0xFF, signed_arg32(key)]) & 0xFF


    _M4_INV_CACHE: dict[int, list[int]] = {}


    def m4_inverse_table(vm: hs.HiddenDexVM, key: int) -> list[int]:
        key &= 31
        cached = _M4_INV_CACHE.get(key)
        if cached is not None:
            return cached
        inv = [-1] * 256
        for x in range(256):
            y = m4_byte(vm, x, key)
            if inv[y] != -1:
                raise ValueError(f"m4 is not bijective for key {key:#x}")
            inv[y] = x
        if any(v < 0 for v in inv):
            raise ValueError(f"incomplete m4 inverse table for key {key:#x}")
        _M4_INV_CACHE[key] = inv
        return inv


    def inv_m4_byte(vm: hs.HiddenDexVM, y: int, key: int) -> int:
        return m4_inverse_table(vm, key)[y & 0xFF]


    def m13_state_permute_forward_bytes(vm: hs.HiddenDexVM, data: bytes | bytearray, seed: int) -> bytearray:
        """Forward C0000.m13 over a 64-byte state."""
        if len(data) != 64:
            raise ValueError("m13 state must be 64 bytes")
        src = bytearray(data)
        out = bytearray(64)
        for i in range(64):
            ks = m17_byte(vm, seed, 3, i)
            src_idx = (u32(seed) - 7 * i) & 63
            out[i] = m4_byte(vm, src[src_idx] ^ ks, ks >> 3)
        return out


    def inverse_m13_state_permute_bytes(vm: hs.HiddenDexVM, data: bytes | bytearray, seed: int) -> bytearray:
        """Inverse C0000.m13 over a 64-byte state."""
        if len(data) != 64:
            raise ValueError("m13 state must be 64 bytes")
        out = bytearray(64)
        cur = bytearray(data)
        for i in range(64):
            ks = m17_byte(vm, seed, 3, i)
            src_idx = (u32(seed) - 7 * i) & 63
            out[src_idx] = inv_m4_byte(vm, cur[i], ks >> 3) ^ ks
        return out


    def inverse_m13_state_permute(vm: hs.HiddenDexVM, obj: hs.JavaObj, seed: int) -> None:
        ids = alias_to_id(vm)
        obj.fields[ids["f8xa5a7934"]] = inverse_m13_state_permute_bytes(
            vm, obj.fields[ids["f8xa5a7934"]], seed
        )


    def m11_key0(vm: hs.HiddenDexVM, arg0: int, arg1: int, f14: int, f22: int, f7: int) -> int:
        mixed_args = u32(arg0 ^ arg1)
        packed_scalars = u32(f14 ^ u32(f22 << 8) ^ u32(f7 << 16))
        return m21_u32(vm, mixed_args, packed_scalars)


    def m11_round_keys(vm: hs.HiddenDexVM, arg0: int, arg1: int, f14: int, f22: int, f7: int) -> list[int]:
        k0 = m11_key0(vm, arg0, arg1, f14, f22, f7)
        return [u32(k0 ^ u32(ROUND_XOR_DELTA * r)) for r in range(3)]


    def _m11_round_forward(
        vm: hs.HiddenDexVM,
        state: bytearray,
        mix_key: int,
        m13_seed: int,
        round_index: int,
    ) -> bytearray:
        for i in range(32):
            a = state[i]
            b = state[32 + i]
            ks1 = m17_byte(vm, mix_key, round_index, i)
            sub = m4_byte(vm, (b + ks1) & 0xFF, ks1 >> 5)
            ks2 = m17_byte(vm, u32(mix_key ^ M11_SECONDARY_XOR), round_index, 31 - i)
            state[i] = a ^ sub ^ ks2
        state = state[32:64] + state[0:32]
        return m13_state_permute_forward_bytes(vm, state, m13_seed)


    def _m11_round_inverse(
        vm: hs.HiddenDexVM,
        state: bytearray,
        mix_key: int,
        m13_seed: int,
        round_index: int,
    ) -> bytearray:
        state = inverse_m13_state_permute_bytes(vm, state, m13_seed)
        state = state[32:64] + state[0:32]
        for i in range(32):
            transformed_a = state[i]
            b = state[32 + i]
            ks1 = m17_byte(vm, mix_key, round_index, i)
            sub = m4_byte(vm, (b + ks1) & 0xFF, ks1 >> 5)
            ks2 = m17_byte(vm, u32(mix_key ^ M11_SECONDARY_XOR), round_index, 31 - i)
            state[i] = transformed_a ^ sub ^ ks2
        return state


    def m11_state_mix_forward_bytes(
        vm: hs.HiddenDexVM,
        data: bytes | bytearray,
        arg0: int,
        arg1: int,
        f14: int,
        f22: int,
        f7: int,
    ) -> bytearray:
        """Forward C0000.m11 over f8 using explicit scalar values read by m11."""
        if len(data) != 64:
            raise ValueError("m11 state must be 64 bytes")
        state = bytearray(data)
        m13_seeds = m11_round_keys(vm, arg0, arg1, f14, f22, f7)
        mix_key = m13_seeds[0]
        for round_index, m13_seed in enumerate(m13_seeds):
            state = _m11_round_forward(vm, state, mix_key, m13_seed, round_index)
        return state


    def inverse_m11_state_mix_bytes(
        vm: hs.HiddenDexVM,
        data: bytes | bytearray,
        arg0: int,
        arg1: int,
        f14: int,
        f22: int,
        f7: int,
    ) -> bytearray:
        """Inverse C0000.m11 over f8.

        The caller must pass the scalar values that m11 read before forward
        execution: f14, f22, and f7.
        """
        if len(data) != 64:
            raise ValueError("m11 state must be 64 bytes")
        state = bytearray(data)
        m13_seeds = m11_round_keys(vm, arg0, arg1, f14, f22, f7)
        mix_key = m13_seeds[0]
        for round_index in reversed(range(3)):
            state = _m11_round_inverse(vm, state, mix_key, m13_seeds[round_index], round_index)
        return state


    def inverse_m11_state_mix(
        vm: hs.HiddenDexVM,
        obj: hs.JavaObj,
        arg0: int,
        arg1: int,
        f14: int,
        f22: int,
        f7: int,
    ) -> None:
        ids = alias_to_id(vm)
        obj.fields[ids["f8xa5a7934"]] = inverse_m11_state_mix_bytes(
            vm, obj.fields[ids["f8xa5a7934"]], arg0, arg1, f14, f22, f7
        )


    def rol32(x: int, n: int) -> int:
        n &= 31
        x &= MASK32
        return ((x << n) | (x >> ((32 - n) & 31))) & MASK32


    def ror32(x: int, n: int) -> int:
        n &= 31
        x &= MASK32
        return ((x >> n) | (x << ((32 - n) & 31))) & MASK32


    def m23_round_forward(words: list[int], a: int, b: int, c: int, d: int) -> None:
        """Forward C0000.m23, the ChaCha quarter round over an int array."""
        words[a] = u32(words[a] + words[b])
        words[d] = rol32(words[d] ^ words[a], 16)
        words[c] = u32(words[c] + words[d])
        words[b] = rol32(words[b] ^ words[c], 12)
        words[a] = u32(words[a] + words[b])
        words[d] = rol32(words[d] ^ words[a], 8)
        words[c] = u32(words[c] + words[d])
        words[b] = rol32(words[b] ^ words[c], 7)


    def inverse_m23_round(words: list[int], a: int, b: int, c: int, d: int) -> None:
        words[b] = ror32(words[b], 7) ^ words[c]
        words[c] = u32(words[c] - words[d])
        words[d] = ror32(words[d], 8) ^ words[a]
        words[a] = u32(words[a] - words[b])
        words[b] = ror32(words[b], 12) ^ words[c]
        words[c] = u32(words[c] - words[d])
        words[d] = ror32(words[d], 16) ^ words[a]
        words[a] = u32(words[a] - words[b])


    def _array_alias_map(vm: hs.HiddenDexVM, obj: hs.JavaObj) -> dict[int, str]:
        out: dict[int, str] = {}
        for idx, alias in vm.field_alias.items():
            val = obj.fields.get(idx)
            if isinstance(val, (bytearray, list)):
                out[id(val)] = alias
        return out


    def _format_arg(value: Any) -> Any:
        if isinstance(value, hs.JavaObj):
            return {"this": True}
        return jsonable(value)


    def record_forward_primitive(
        vm: hs.HiddenDexVM, obj: hs.JavaObj, alias: str, args: list[Any]
    ) -> dict[str, Any]:
        """Run a primitive through HiddenDexVM and return an exact undo record."""
        before = snapshot_fields(vm, obj)
        reads: list[str] = []
        writes: list[str] = []
        array_events: list[dict[str, Any]] = []
        nested_calls: list[dict[str, Any]] = []
        array_alias = _array_alias_map(vm, obj)
        code_to_alias = {off: name for name, off in hs.METHOD_ALIASES.items()}
        old_hook = vm.event_hook
        old_invoke = vm._java_invoke

        def hook(body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            name = ins.get_name()
            ops = ins.get_operands()
            if name.startswith(("iget", "sget")):
                field_id = ops[-1][1]
                reads.append(vm.field_alias.get(field_id, f"field_{field_id}"))
            elif name.startswith(("iput", "sput")):
                field_id = ops[-1][1]
                field_alias = vm.field_alias.get(field_id, f"field_{field_id}")
                writes.append(field_alias)
                if name in ("iput-object", "sput-object"):
                    value = regs[ops[0][1]]
                    if isinstance(value, (bytearray, list)):
                        array_alias[id(value)] = field_alias
            elif name in ("aget-byte", "aget", "aget-object"):
                arr = regs[ops[1][1]]
                arr_alias = array_alias.get(id(arr))
                if arr_alias:
                    reads.append(arr_alias)
            elif name in ("aput-byte", "aput", "aput-object"):
                arr = regs[ops[1][1]]
                arr_alias = array_alias.get(id(arr))
                if arr_alias:
                    idx = hs.s32(regs[ops[2][1]])
                    old_val = deep_clone(arr[idx])
                    new_val = regs[ops[0][1]]
                    if name == "aput-byte":
                        new_val = hs.s32(new_val) & 0xFF
                    array_events.append(
                        {
                            "method": code_to_alias.get(body.code_off, hex(body.code_off)),
                            "off": off,
                            "array": arr_alias,
                            "index": idx,
                            "old": jsonable(old_val),
                            "new": jsonable(new_val),
                        }
                    )
                    writes.append(arr_alias)

        def wrapped_invoke(method_idx: int, call_args: list[Any], invoke_name: str) -> tuple[bool, Any]:
            method_body = vm.methods_by_ref.get(method_idx)
            code_off = method_body.code_off if method_body else None
            nested_alias = code_to_alias.get(code_off)
            if nested_alias in {
                "m11_state_mix",
                "m13_state_permute",
                "m19_clock_f6",
                "m30_fixed_commit_mix",
                "m25_step_token_mix",
                "m29_permute_mix",
            }:
                scalar_pack = {
                    field: before.get(field)
                    for field in SCALAR_M11_FIELDS
                }
                if call_args and isinstance(call_args[0], hs.JavaObj):
                    scalar_pack = {
                        field: snapshot_fields(vm, call_args[0]).get(field)
                        for field in SCALAR_M11_FIELDS
                    }
                nested_calls.append(
                    {
                        "alias": nested_alias,
                        "code_off": code_off,
                        "args": [_format_arg(a) for a in call_args],
                        "scalar_pack_at_call": jsonable(scalar_pack),
                    }
                )
            return old_invoke(method_idx, call_args, invoke_name)

        try:
            vm.event_hook = hook
            vm._java_invoke = wrapped_invoke
            vm.call_alias(alias, [obj, *args])
        finally:
            vm.event_hook = old_hook
            vm._java_invoke = old_invoke

        after = snapshot_fields(vm, obj)
        return {
            "alias": alias,
            "code_off": hs.METHOD_ALIASES[alias],
            "args": [_format_arg(a) for a in args],
            "before": before,
            "after": after,
            "read_fields": sorted(set(reads)),
            "written_fields": sorted(set(writes)),
            "array_write_count": len(array_events),
            "array_writes_sample": array_events[:16],
            "nested_calls": nested_calls,
        }


    def inverse_from_record(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        """Exact inverse for wrapper primitives: restore recorded pre-state fields."""
        restore_fields(vm, obj, record["before"])


    def inverse_m25_step_token_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m29_permute_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m30_fixed_commit_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m34_commit_round_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m39_pull_merge_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m40_token_round_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m41_bootstrap_return_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m45_final_stage_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m47_digest_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def inverse_m49_commit_boolean_mix(vm: hs.HiddenDexVM, obj: hs.JavaObj, record: dict[str, Any]) -> None:
        inverse_from_record(vm, obj, record)


    def make_random_c0000(vm: hs.HiddenDexVM, rng: random.Random) -> hs.JavaObj:
        ids = alias_to_id(vm)
        obj = vm.new_c0000()
        obj.fields[ids["f8xa5a7934"]] = bytearray(rng.randrange(256) for _ in range(64))
        obj.fields[ids["f10x7fc29877"]] = bytearray(rng.randrange(256) for _ in range(32))
        obj.fields[ids["f11x99d9d52c"]] = [hs.s32(rng.getrandbits(32)) for _ in range(4)]
        obj.fields[ids["f12x978d0ca3"]] = [
            bytearray(rng.randrange(256) for _ in range(8)) for _ in range(4)
        ]
        for alias in [
            "f6x6868a7e9",
            "f7",
            "f14x69ab180b",
            "f15xbab9595e",
            "f19xe71db4e0",
            "f21x843c54e2",
            "f22x73e78f8b",
            "f23xf2ae566b",
        ]:
            obj.fields[ids[alias]] = hs.s32(rng.getrandbits(32))
        for alias in ["f13xcb34ab73", "f17xc24bec61", "f20xb9c11465"]:
            obj.fields[ids[alias]] = hs.s64(rng.getrandbits(64))
        for alias in ["f9x7ea3f6dd", "f16x11cdf272", "f18x8da453fc"]:
            obj.fields[ids[alias]] = bool(rng.getrandbits(1))
        return obj


    def selftest_case_summary(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "alias": record["alias"],
            "code_off": f"0x{record['code_off']:x}",
            "read_fields": record["read_fields"],
            "written_fields": record["written_fields"],
            "array_write_count": record["array_write_count"],
            "nested_calls": [
                {
                    "alias": call["alias"],
                    "code_off": f"0x{call['code_off']:x}" if call["code_off"] is not None else None,
                    "args": call["args"],
                    "scalar_pack_at_call": call["scalar_pack_at_call"],
                }
                for call in record["nested_calls"][:12]
            ],
        }


    def run_selftests(seed: int = 0xC0000) -> dict[str, Any]:
        rng = random.Random(seed)
        vm = hs.HiddenDexVM()
        vm.ensure_clinit()
        ids = alias_to_id(vm)
        tests: list[dict[str, Any]] = []

        # m13 structured inverse
        for m13_seed in [0, 1, 0x0EE85EC5, 0xD4BEAD2F, rng.getrandbits(32)]:
            obj = make_random_c0000(vm, rng)
            before = snapshot_fields(vm, obj)
            vm.call_alias("m13_state_permute", [obj, hs.s32(m13_seed)])
            inverse_m13_state_permute(vm, obj, m13_seed)
            tests.append(
                {
                    "alias": "m13_state_permute",
                    "code_off": "0xcd90c",
                    "seed": f"0x{m13_seed & MASK32:08x}",
                    "ok": snapshots_equal(before, snapshot_fields(vm, obj)),
                    "inverse": "structured",
                }
            )

        # m11 structured inverse
        for args in [(0x12345678, 0x9ABCDEF0), (0x42535450, 0), (rng.getrandbits(32), rng.getrandbits(32))]:
            obj = make_random_c0000(vm, rng)
            before = snapshot_fields(vm, obj)
            f14 = obj.fields[ids["f14x69ab180b"]]
            f22 = obj.fields[ids["f22x73e78f8b"]]
            f7 = obj.fields[ids["f7"]]
            vm.call_alias("m11_state_mix", [obj, hs.s32(args[0]), hs.s32(args[1])])
            inverse_m11_state_mix(vm, obj, args[0], args[1], f14, f22, f7)
            tests.append(
                {
                    "alias": "m11_state_mix",
                    "code_off": "0xc0398",
                    "args": [f"0x{x & MASK32:08x}" for x in args],
                    "half_mix_key": f"0x{m11_key0(vm, args[0], args[1], f14, f22, f7):08x}",
                    "secondary_seed": f"0x{u32(m11_key0(vm, args[0], args[1], f14, f22, f7) ^ M11_SECONDARY_XOR):08x}",
                    "m13_seeds": [f"0x{x:08x}" for x in m11_round_keys(vm, args[0], args[1], f14, f22, f7)],
                    "ok": snapshots_equal(before, snapshot_fields(vm, obj)),
                    "inverse": "structured",
                }
            )

        # m23 int-array round
        for _ in range(5):
            words = [rng.getrandbits(32) for _ in range(8)]
            before_words = words[:]
            vm_words = [hs.s32(x) for x in words]
            vm.call_alias("m23_round", [vm_words, 0, 1, 2, 3])
            m23_round_forward(words, 0, 1, 2, 3)
            forward_ok = [x & MASK32 for x in vm_words] == [x & MASK32 for x in words]
            inverse_m23_round(words, 0, 1, 2, 3)
            tests.append(
                {
                    "alias": "m23_round",
                    "code_off": "0xf8290",
                    "ok": forward_ok and [x & MASK32 for x in words] == before_words,
                    "inverse": "structured",
                }
            )

        wrapper_cases = [
            ("m25_step_token_mix", [0x11223344]),
            ("m29_permute_mix", []),
            ("m30_fixed_commit_mix", [0x55667788]),
            ("m34_commit_round_mix", [0x1122334455667788]),
            ("m39_pull_merge_mix", [bytearray(range(64)), 2]),
            ("m40_token_round_mix", [0x42535450, 0]),
            ("m41_bootstrap_return_mix", [bytearray(range(12))]),
            ("m45_final_stage_mix", [True]),
            ("m45_final_stage_mix", [False]),
            ("m47_digest_mix", [bytearray(range(32))]),
            ("m49_commit_boolean_mix", [True]),
            ("m49_commit_boolean_mix", [False]),
        ]
        for alias, args in wrapper_cases:
            obj = make_random_c0000(vm, rng)
            record = record_forward_primitive(vm, obj, alias, args)
            inverse_from_record(vm, obj, record)
            tests.append({**selftest_case_summary(record), "ok": snapshots_equal(record["before"], snapshot_fields(vm, obj)), "inverse": "record"})

        return {
            "seed": seed,
            "test_count": len(tests),
            "ok": all(t["ok"] for t in tests),
            "tests": tests,
        }


    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_m40_f8_pre_module() -> types.ModuleType:
    _module_name = "m40_f8_pre"
    """Forward/inverse model for C0000.m40 pre-m11 direct f8 update."""


    import copy
    import random
    from dataclasses import dataclass
    from typing import Any

    import recover_hidden_state as hs  # noqa: E402
    import c0000_primitives as prim  # noqa: E402


    MASK32 = 0xFFFFFFFF
    M40_CODE_OFF = 0x124A74
    PRE_F8_READ_PC = 0x3928
    PRE_F8_WRITE_PC = 0x4F60
    NESTED_M11_PC = 0xE114
    M40_PRE_ROUNDS = 28


    @dataclass
    class M40PreRound:
        i: int
        mix_byte: int
        chain_key: int
        chain: int
        index: int
        mask_byte: int
        m4_key: int


    class StopAtNestedM11(Exception):
        pass


    def u32(x: int) -> int:
        return x & MASK32


    def rol8(x: int, n: int) -> int:
        n &= 7
        x &= 0xFF
        return ((x << n) | (x >> ((8 - n) & 7))) & 0xFF


    def ror8(x: int, n: int) -> int:
        n &= 7
        x &= 0xFF
        return ((x >> n) | (x << ((8 - n) & 7))) & 0xFF


    def m4_byte(x: int, key: int) -> int:
        """C0000.m4, reduced from bytecode: 8-bit rotate-left by key & 7."""
        return rol8(x, key)


    def inv_m4_byte(y: int, key: int) -> int:
        return ror8(y, key)


    def _vm() -> hs.HiddenDexVM:
        vm = hs.HiddenDexVM()
        vm.ensure_clinit()
        return vm


    def _s32(x: int) -> int:
        return hs.s32(x)


    def m40_pre_schedule(vm: hs.HiddenDexVM, arg0: int, arg1: int) -> tuple[int, int, list[M40PreRound]]:
        """Return bytecode-derived round schedule for the direct pre-m11 f8 update."""
        a0 = _s32(arg0)
        a1 = _s32(arg1)
        base = u32(vm.call_alias("m2", [a0, a1]))
        chain = u32(vm.call_alias("m7", [a0, a1]))
        chain0 = chain
        rounds: list[M40PreRound] = []

        for i in range(M40_PRE_ROUNDS):
            mix_full = u32(vm.call_alias("m3", [a0, a1, _s32(i), _s32(chain)]))
            mix = mix_full & 0xFF
            chain_key = u32(u32(arg0) ^ u32(arg1) ^ mix_full ^ i)
            chain = u32(vm.call_alias("m21_rot", [_s32(chain), _s32(chain_key)]))
            index = (chain + base + 17 * i) & 0x3F
            mask = u32(vm.call_alias("m17", [_s32(chain ^ base), _s32(i & 3), _s32(index)])) & 0xFF
            m4_key = u32(base ^ mask ^ i)
            rounds.append(M40PreRound(i, mix, chain_key, chain, index, mask, m4_key))

        return base, chain0, rounds


    def forward_pre_m40_f8(
        f8: bytes | bytearray,
        arg0: int,
        arg1: int,
        vm: hs.HiddenDexVM | None = None,
    ) -> bytearray:
        """Apply only C0000.m40 direct f8 writes before the nested m11 call."""
        if len(f8) != 64:
            raise ValueError("m40 pre-f8 state must be exactly 64 bytes")
        if vm is None:
            vm = _vm()
        out = bytearray(f8)
        _, _, rounds = m40_pre_schedule(vm, arg0, arg1)
        for rec in rounds:
            mixed = (out[rec.index] ^ rec.mix_byte ^ rec.mask_byte) & 0xFF
            out[rec.index] = m4_byte(mixed, rec.m4_key)
        return out


    def inverse_pre_m40_f8(
        f8: bytes | bytearray,
        arg0: int,
        arg1: int,
        vm: hs.HiddenDexVM | None = None,
    ) -> bytearray:
        """Invert only C0000.m40 direct f8 writes before the nested m11 call."""
        if len(f8) != 64:
            raise ValueError("m40 pre-f8 state must be exactly 64 bytes")
        if vm is None:
            vm = _vm()
        out = bytearray(f8)
        _, _, rounds = m40_pre_schedule(vm, arg0, arg1)
        for rec in reversed(rounds):
            mixed = inv_m4_byte(out[rec.index], rec.m4_key)
            out[rec.index] = (mixed ^ rec.mix_byte ^ rec.mask_byte) & 0xFF
        return out


    def _clone_obj(obj: hs.JavaObj) -> hs.JavaObj:
        return hs.JavaObj(obj.cls, copy.deepcopy(obj.fields))


    def _jsonable(value: Any) -> Any:
        if isinstance(value, bytearray):
            return bytes(value).hex()
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, hs.JavaObj):
            return "<C0000>"
        if isinstance(value, list):
            return [_jsonable(v) for v in value]
        if isinstance(value, dict):
            return {k: _jsonable(v) for k, v in value.items()}
        return value


    def make_case_obj(vm: hs.HiddenDexVM, rng: random.Random, kind: str) -> hs.JavaObj:
        ids = prim.alias_to_id(vm)
        obj = prim.make_random_c0000(vm, rng)
        if kind == "affine":
            obj.fields[ids["f8xa5a7934"]] = bytearray(((i * 7 + 3) & 0xFF) for i in range(64))
        elif kind == "counting":
            obj.fields[ids["f8xa5a7934"]] = bytearray(range(64))
        elif kind == "edge":
            obj.fields[ids["f8xa5a7934"]] = bytearray([0x00, 0xFF, 0x80, 0x7F] * 16)
        elif kind == "random":
            obj.fields[ids["f8xa5a7934"]] = bytearray(rng.randrange(256) for _ in range(64))
        else:
            raise ValueError(f"unknown case kind {kind!r}")
        return obj


    def run_real_m40_until_m11(
        vm: hs.HiddenDexVM,
        obj: hs.JavaObj,
        arg0: int,
        arg1: int,
    ) -> dict[str, Any]:
        ids = prim.alias_to_id(vm)
        old_hook = vm.event_hook
        result: dict[str, Any] = {"direct_write_count": 0, "direct_read_count": 0}

        def hook(body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            if body.code_off != M40_CODE_OFF:
                return
            if off == PRE_F8_READ_PC:
                result["direct_read_count"] += 1
            elif off == PRE_F8_WRITE_PC:
                result["direct_write_count"] += 1
            elif off == NESTED_M11_PC:
                result["m11_arg0"] = u32(regs[13])
                result["m11_arg1"] = u32(regs[14])
                result["f8_before_m11_hex"] = bytes(obj.fields[ids["f8xa5a7934"]]).hex()
                raise StopAtNestedM11()

        try:
            vm.event_hook = hook
            vm.call_alias("m40_token_round_mix", [obj, _s32(arg0), _s32(arg1)])
        except StopAtNestedM11:
            pass
        finally:
            vm.event_hook = old_hook
        return result


    def trace_direct_dependencies(vm: hs.HiddenDexVM, obj: hs.JavaObj, arg0: int, arg1: int) -> dict[str, Any]:
        """Trace object field accesses up to and including the last direct f8 write."""
        old_hook = vm.event_hook
        reads: list[dict[str, Any]] = []
        writes: list[dict[str, Any]] = []
        array_reads = 0
        array_writes = 0

        def hook(body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            nonlocal array_reads, array_writes
            if body.code_off != M40_CODE_OFF:
                return
            name = ins.get_name()
            ops = ins.get_operands()
            if name.startswith("iget"):
                field_id = ops[-1][1]
                reads.append({"pc": f"0x{off:x}", "field": vm.field_alias.get(field_id, f"field_{field_id}")})
            elif name.startswith("iput"):
                field_id = ops[-1][1]
                writes.append({"pc": f"0x{off:x}", "field": vm.field_alias.get(field_id, f"field_{field_id}")})
            elif off == PRE_F8_READ_PC:
                array_reads += 1
            elif off == PRE_F8_WRITE_PC:
                array_writes += 1
                if array_writes == M40_PRE_ROUNDS:
                    raise StopAtNestedM11()

        try:
            vm.event_hook = hook
            vm.call_alias("m40_token_round_mix", [obj, _s32(arg0), _s32(arg1)])
        except StopAtNestedM11:
            pass
        finally:
            vm.event_hook = old_hook

        return {
            "object_field_reads_until_last_direct_write": reads,
            "object_field_writes_until_last_direct_write": writes,
            "direct_f8_array_reads": array_reads,
            "direct_f8_array_writes": array_writes,
        }


    def run_selftests(seed: int = 0x40F8, case_count: int = 8) -> dict[str, Any]:
        rng = random.Random(seed)
        vm = _vm()
        ids = prim.alias_to_id(vm)
        cases: list[dict[str, Any]] = []

        fixed = [
            ("affine", 0x4F769386, 0xA9BDA034),
            ("counting", 0x97B8F05D, 0xD6F27F83),
            ("edge", 0xFB19EC69, 0x8E4C5A95),
        ]
        while len(fixed) < case_count:
            fixed.append(("random", rng.getrandbits(32), rng.getrandbits(32)))

        for idx, (kind, arg0, arg1) in enumerate(fixed[:case_count]):
            obj = make_case_obj(vm, rng, kind)
            before = bytearray(obj.fields[ids["f8xa5a7934"]])
            expected = forward_pre_m40_f8(before, arg0, arg1, vm)
            real_obj = _clone_obj(obj)
            real = run_real_m40_until_m11(vm, real_obj, arg0, arg1)
            actual = bytearray.fromhex(real["f8_before_m11_hex"])
            inv = inverse_pre_m40_f8(actual, arg0, arg1, vm)
            changed = [i for i, (a, b) in enumerate(zip(before, actual)) if a != b]
            cases.append(
                {
                    "case": idx,
                    "kind": kind,
                    "arg0": f"0x{arg0 & MASK32:08x}",
                    "arg1": f"0x{arg1 & MASK32:08x}",
                    "forward_matches_vm": expected == actual,
                    "inverse_restores_entry_f8": inv == before,
                    "direct_read_count": real["direct_read_count"],
                    "direct_write_count": real["direct_write_count"],
                    "changed_index_count": len(changed),
                    "changed_indices": changed,
                    "m11_arg0": f"0x{real['m11_arg0']:08x}",
                    "m11_arg1": f"0x{real['m11_arg1']:08x}",
                }
            )

        dep_obj = make_case_obj(vm, random.Random(seed ^ 0x55AA), "affine")
        dependencies = trace_direct_dependencies(vm, dep_obj, 0x4F769386, 0xA9BDA034)
        base, chain0, rounds = m40_pre_schedule(vm, 0x4F769386, 0xA9BDA034)
        m4_ok = all(
            (vm.call_alias("m4", [_s32(x), _s32(key)]) & 0xFF) == m4_byte(x, key)
            for key in range(16)
            for x in (0, 1, 2, 3, 0x55, 0x80, 0xAA, 0xFF)
        )
        return {
            "seed": f"0x{seed:x}",
            "case_count": len(cases),
            "all_ok": all(c["forward_matches_vm"] and c["inverse_restores_entry_f8"] for c in cases) and m4_ok,
            "m4_rol8_matches_vm_samples": m4_ok,
            "cases": cases,
            "sample_schedule_arg0": "0x4f769386",
            "sample_schedule_arg1": "0xa9bda034",
            "sample_base": f"0x{base:08x}",
            "sample_initial_chain": f"0x{chain0:08x}",
            "sample_rounds": [
                {
                    "i": rec.i,
                    "mix_byte": f"0x{rec.mix_byte:02x}",
                    "chain_key": f"0x{rec.chain_key:08x}",
                    "chain": f"0x{rec.chain:08x}",
                    "index": rec.index,
                    "mask_byte": f"0x{rec.mask_byte:02x}",
                    "m4_key": f"0x{rec.m4_key:08x}",
                }
                for rec in rounds
            ],
            "dependencies": dependencies,
        }


    def build_model(test_result: dict[str, Any]) -> dict[str, Any]:
        return {
            "method": "C0000.m40_token_round_mix",
            "method_code_offset": "0x124a74",
            "scope": "direct f8 writes before nested m11_state_mix only",
            "pcs": {
                "direct_f8_read_aget_byte": "0x3928",
                "direct_f8_write_aput_byte": "0x4f60",
                "nested_m11_invoke": "0xe114",
            },
            "loop_count": M40_PRE_ROUNDS,
            "dependencies": {
                "object_scalar_fields_read_by_direct_f8_transform": [],
                "object_arrays_read_by_direct_f8_transform": ["f8xa5a7934"],
                "depends_on_m40_parameters": True,
                "parameter_dependency": ["m2(arg0,arg1)", "m7(arg0,arg1)", "m3(arg0,arg1,i,chain)"],
            },
            "formula": {
                "base": "m2(arg0,arg1)",
                "initial_chain": "m7(arg0,arg1)",
                "round": [
                    "mix_i = m3(arg0,arg1,i,chain_{i-1}) & 0xff",
                    "chain_key_i = arg0 ^ arg1 ^ mix_i ^ i",
                    "chain_i = m21_rot(chain_{i-1}, chain_key_i)",
                    "idx_i = (chain_i + base + 17*i) & 63",
                    "mask_i = m17(chain_i ^ base, i & 3, idx_i) & 0xff",
                    "tmp_i = f8[idx_i] ^ mix_i ^ mask_i",
                    "key_i = base ^ mask_i ^ i",
                    "f8[idx_i] = rol8(tmp_i, key_i & 7)",
                ],
                "inverse_round": [
                    "process i=27..0",
                    "tmp_i = ror8(f8[idx_i], key_i & 7)",
                    "f8[idx_i] = tmp_i ^ mix_i ^ mask_i",
                ],
            },
            "validation": test_result,
        }


    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_solve_f8_final_module() -> types.ModuleType:
    _module_name = "solve_f8_final"
    """Final f8-only inverse/forward verifier for the corrected GuardMaster chain."""


    import unicodedata
    from dataclasses import asdict, dataclass
    from typing import Any

    import c0000_primitives as prim  # noqa: E402
    import recover_hidden_state as hs  # noqa: E402
    import m40_f8_pre  # noqa: E402


    MASK32 = 0xFFFFFFFF
    NORMALIZED_LEN = 64

    INIT = 0x494E4954
    BSTP = 0x42535450
    FAUL = 0x4641554C
    DIG1 = 0x44494731
    STEP = 0x53544550
    PULL = 0x50554C4C
    FIN1 = 0x46494E31
    NORM = 0x4E4F524D
    PERM = 0x5045524D
    COMM = 0x434F4D4D
    LOOP = 0x4C4F4F50

    VISIBLE_FAUL_ARGS = [
        0xF68E0847,
        0xCAE622D2,
        0xEF22DD3B,
        0xEAA7BC61,
        0xD058667D,
        0x0668A3D0,
        0xCC87B0E7,
        0x2F8C554B,
    ]

    M40_ARGS: dict[tuple[int, int], tuple[int, int]] = {
        (BSTP, 0): (0x4F769386, 0xA9BDA034),
        (STEP, 0): (0xE444B15C, 0xB332CA1F),
        (STEP, 1): (0xDB7468EC, 0x4F269682),
        (STEP, 2): (0x47E3DDFB, 0x5E982E64),
        (STEP, 3): (0xB6934E0B, 0xC97C69F2),
        (STEP, 4): (0xA885639D, 0x24C7F9FD),
        (STEP, 5): (0x9FB6B62E, 0xC0434770),
        (STEP, 6): (0x0A251A3D, 0x2D2E7286),
        (STEP, 7): (0x79D5174D, 0xDCDF5FB8),
        (PULL, 0): (0x97B8F05D, 0xD6F27F83),
        (PULL, 1): (0xC568010D, 0x1389826A),
        (PULL, 2): (0x71C7DD22, 0x61005985),
        (PULL, 3): (0xA088A9ED, 0x1D690008),
        (PULL, 4): (0xD3662283, 0x60A48E9C),
        (PULL, 5): (0x02174C72, 0x7AAFD275),
        (PULL, 6): (0x8E86B863, 0x25B8E119),
        (PULL, 7): (0xFDB66ED3, 0xF44B74D8),
        (COMM, 0): (0x4D85A6F5, 0x7B5524E5),
        (COMM, 1): (0x1ED59025, 0x35E21CF7),
        (COMM, 2): (0x2F251F55, 0x73353760),
        (COMM, 3): (0xF8742B84, 0x54EBEF79),
        (COMM, 4): (0x8944FC34, 0xF90B0D15),
        (COMM, 5): (0x5B944364, 0x250D37BC),
        (COMM, 6): (0x64E3DE93, 0x6E78A09D),
        (COMM, 7): (0x353368C3, 0xA239879E),
        (COMM, 8): (0xFB19EC69, 0x8E4C5A95),
    }

    @dataclass(frozen=True)
    class Op:
        i: int
        phase: str
        wrapper: str
        arg0: int
        arg1: int
        f14: int
        f22: int
        f7: int
        m40_entry_arg0: int | None = None
        m40_entry_arg1: int | None = None


    def u32(x: int) -> int:
        return x & MASK32


    def hx(x: int) -> str:
        return f"0x{u32(x):08x}"


    def ascii_tag(x: int) -> str:
        try:
            raw = u32(x).to_bytes(4, "big")
            if all(32 <= b <= 126 for b in raw):
                return raw.decode("ascii")
        except Exception:
            pass
        return ""


    def add_op(
        ops: list[Op],
        phase: str,
        wrapper: str,
        arg0: int,
        arg1: int,
        f14: int,
        f22: int,
        f7: int,
        m40_entry_arg0: int | None = None,
        m40_entry_arg1: int | None = None,
    ) -> None:
        ops.append(
            Op(
                len(ops),
                phase,
                wrapper,
                u32(arg0),
                u32(arg1),
                u32(f14),
                u32(f22),
                u32(f7),
                None if m40_entry_arg0 is None else u32(m40_entry_arg0),
                None if m40_entry_arg1 is None else u32(m40_entry_arg1),
            )
        )


    def add_m40_op(ops: list[Op], phase: str, tag: int, index: int, f14: int, f22: int, f7: int) -> None:
        arg0, arg1 = M40_ARGS[(tag, index)]
        tag_name = ascii_tag(tag)
        add_op(
            ops,
            phase,
            f"m40({tag_name},{index})",
            arg0,
            arg1,
            f14,
            f22,
            f7,
            m40_entry_arg0=tag,
            m40_entry_arg1=index,
        )


    def build_ops(post_pull_f22: int = 17) -> list[Op]:
        """Build the Dispatcher-confirmed f8 rows from constructor INIT through final COMM."""
        ops: list[Op] = []
        f14 = 0
        f22 = 0
        f7 = 0

        add_op(ops, "constructor", "m11(INIT,64)", INIT, NORMALIZED_LEN, f14, f22, f7)
        add_op(ops, "bootstrap", "m41 -> m11(BSTP,0)", BSTP, 0, f14, f22, f7)
        add_m40_op(ops, "bootstrap", BSTP, 0, f14, f22, f7)

        for round_i in range(8):
            if (f14, f22, f7) != (round_i, 0, round_i):
                raise AssertionError(f"bad round handoff {round_i}: {(f14, f22, f7)}")

            add_op(ops, f"round[{round_i}]", "m37 -> m11(NORM,16)", NORM, 16, f14, f22, f7)
            f22 = 1

            add_m40_op(ops, f"round[{round_i}]", PULL, round_i, f14, f22, f7)
            f7 += 1
            add_op(
                ops,
                f"round[{round_i}]",
                "C0002.m62 -> m39 -> m11(PULL,f7_after)",
                PULL,
                f7,
                f14,
                f22,
                f7,
            )
            f22 = 2

            add_op(ops, f"round[{round_i}]", "m47 -> m11(PERM,16)", PERM, 16, f14, f22, f7)
            f22 = 3

            add_op(ops, f"round[{round_i}]", "m25 -> m11(DIG1,3)", DIG1, f22, f14, f22, f7)
            f22 = 4

            add_m40_op(ops, f"round[{round_i}]", STEP, round_i, f14, f22, f7)
            add_op(ops, f"round[{round_i}]", "m34 -> m11(STEP,4)", STEP, f22, f14, f22, f7)
            f22 = 5

            add_m40_op(ops, f"round[{round_i}]", COMM, round_i, f14, f22, f7)
            f14 += 1
            f22 = 0
            add_op(
                ops,
                f"round[{round_i}]",
                f"m49(true) -> m11(COMM,{f14})",
                COMM,
                f14,
                f14,
                f22,
                f7,
            )

        if (f14, f22, f7) != (8, 0, 8):
            raise AssertionError(f"bad final handoff {(f14, f22, f7)}")

        f22 = 6
        add_op(ops, "final_signal", "m29 -> m11(FIN1,8)", FIN1, f14, f14, f22, f7)
        add_m40_op(ops, "final_commit", COMM, 8, f14, f22, f7)

        return ops


    def java_trim(s: str) -> str:
        start = 0
        end = len(s)
        while start < end and ord(s[start]) <= 0x20:
            start += 1
        while end > start and ord(s[end - 1]) <= 0x20:
            end -= 1
        return s[start:end]


    def java_constructor_normalize(text: str) -> bytes:
        normalized = unicodedata.normalize("NFKC", text)
        trimmed = java_trim(normalized)
        stripped_lines = trimmed.replace("\r", "").replace("\n", "")
        return stripped_lines.encode("utf-8")


    def op_json(op: Op) -> dict[str, Any]:
        d = asdict(op)
        d["arg0_hex"] = hx(op.arg0)
        d["arg1_hex"] = hx(op.arg1)
        d["arg0_ascii"] = ascii_tag(op.arg0)
        d["arg1_ascii"] = ascii_tag(op.arg1)
        if op.m40_entry_arg0 is not None and op.m40_entry_arg1 is not None:
            d["m40_entry_arg0_hex"] = hx(op.m40_entry_arg0)
            d["m40_entry_arg1_hex"] = hx(op.m40_entry_arg1)
            d["m40_entry_arg0_ascii"] = ascii_tag(op.m40_entry_arg0)
        return d


    def apply_inverse(vm: hs.HiddenDexVM, final_state: bytes, ops: list[Op]) -> tuple[bytes, list[dict[str, Any]]]:
        state = bytearray(final_state)
        steps: list[dict[str, Any]] = []
        for op in reversed(ops):
            before = bytes(state)
            state = prim.inverse_m11_state_mix_bytes(vm, state, op.arg0, op.arg1, op.f14, op.f22, op.f7)
            after_m11_inverse = bytes(state)
            if op.m40_entry_arg0 is not None and op.m40_entry_arg1 is not None:
                state = m40_f8_pre.inverse_pre_m40_f8(state, op.m40_entry_arg0, op.m40_entry_arg1, vm)
            steps.append(
                {
                    "op_i": op.i,
                    "phase": op.phase,
                    "wrapper": op.wrapper,
                    "arg0": hx(op.arg0),
                    "arg1": hx(op.arg1),
                    "f14": op.f14,
                    "f22": op.f22,
                    "f7": op.f7,
                    "has_m40_pre_inverse": op.m40_entry_arg0 is not None,
                    "m40_entry_arg0": hx(op.m40_entry_arg0) if op.m40_entry_arg0 is not None else None,
                    "m40_entry_arg1": hx(op.m40_entry_arg1) if op.m40_entry_arg1 is not None else None,
                    "input_hex": before.hex(),
                    "after_m11_inverse_hex": after_m11_inverse.hex(),
                    "output_hex": bytes(state).hex(),
                }
            )
        return bytes(state), steps


    def apply_forward(vm: hs.HiddenDexVM, candidate: bytes, ops: list[Op]) -> tuple[bytes, list[dict[str, Any]]]:
        state = bytearray(candidate)
        steps: list[dict[str, Any]] = []
        for op in ops:
            before = bytes(state)
            after_m40_pre = None
            if op.m40_entry_arg0 is not None and op.m40_entry_arg1 is not None:
                state = m40_f8_pre.forward_pre_m40_f8(state, op.m40_entry_arg0, op.m40_entry_arg1, vm)
                after_m40_pre = bytes(state)
            state = prim.m11_state_mix_forward_bytes(vm, state, op.arg0, op.arg1, op.f14, op.f22, op.f7)
            steps.append(
                {
                    "op_i": op.i,
                    "phase": op.phase,
                    "wrapper": op.wrapper,
                    "arg0": hx(op.arg0),
                    "arg1": hx(op.arg1),
                    "f14": op.f14,
                    "f22": op.f22,
                    "f7": op.f7,
                    "has_m40_pre_forward": op.m40_entry_arg0 is not None,
                    "m40_entry_arg0": hx(op.m40_entry_arg0) if op.m40_entry_arg0 is not None else None,
                    "m40_entry_arg1": hx(op.m40_entry_arg1) if op.m40_entry_arg1 is not None else None,
                    "input_hex": before.hex(),
                    "after_m40_pre_hex": after_m40_pre.hex() if after_m40_pre is not None else None,
                    "output_hex": bytes(state).hex(),
                }
            )
        return bytes(state), steps


    def validate_candidate(candidate: bytes, final_state: bytes, forward_state: bytes) -> tuple[bool, list[str], dict[str, Any]]:
        errors: list[str] = []
        info: dict[str, Any] = {
            "candidate_len": len(candidate),
            "candidate_hex": candidate.hex(),
            "forward_state_hex": forward_state.hex(),
            "final_state_hex": final_state.hex(),
            "forward_matches_final": forward_state == final_state,
        }
        try:
            text = candidate.decode("utf-8")
            info["candidate_text"] = text
            normalized_again = java_constructor_normalize(text)
            info["normalization_stable"] = normalized_again == candidate
            info["normalized_again_hex"] = normalized_again.hex()
            if normalized_again != candidate:
                errors.append("candidate bytes are not stable under Java-equivalent constructor normalization")
        except UnicodeDecodeError as exc:
            info["utf8_error"] = str(exc)
            errors.append(f"candidate is not valid UTF-8: {exc}")

        if len(candidate) != NORMALIZED_LEN:
            errors.append(f"candidate length is {len(candidate)}, expected {NORMALIZED_LEN}")
        if forward_state != final_state:
            errors.append("forward f8 chain did not reproduce final_state.bin")

        return not errors, errors, info


    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_invert_final_check_module(so_path: Path, work_dir: Path) -> types.ModuleType:
    _module_name = "invert_final_check"
    import hashlib
    import json
    import struct
    from dataclasses import dataclass
    from pathlib import Path
    from typing import Callable

    import lief
    from unicorn import Uc
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR,
        UC_ARM64_REG_PC,
        UC_ARM64_REG_SP,
        UC_ARM64_REG_TPIDR_EL0,
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X6,
        UC_ARM64_REG_X7,
        UC_ARM64_REG_X8,
    )
    from unicorn.unicorn_const import (
        UC_ARCH_ARM64,
        UC_HOOK_CODE,
        UC_HOOK_MEM_INVALID,
        UC_MEM_FETCH_UNMAPPED,
        UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_UNMAPPED,
        UC_MODE_ARM,
        UC_PROT_ALL,
    )


    BASE = 0x10000000
    STACK_BASE = 0x70000000
    STACK_SIZE = 0x02000000
    HEAP_BASE = 0x50000000
    HEAP_SIZE = 0x18000000
    TLS_BASE = 0x74000000
    TLS_SIZE = 0x1000
    STUB_BASE = 0x20000000
    STUB_STRIDE = 0x100
    RET_SENTINEL = 0x7FFF0000

    ADDR_TARGET = 0x40800
    ADDR_PAD_SEED = 0x408C0
    ADDR_TABLE = 0x40900
    ADDR_TARGET_CRC = 0x40940

    FN_FINAL_EXPAND_ENCODE = 0x3846220
    FN_STREAM_CTX = 0x38484D4
    FN_SM4_CORE = 0x3848F94
    FN_VM_MATERIAL = 0x3849480
    FN_WBAES_DESC = 0x380D31C
    FN_WBAES_TRANSFORM = 0x380D948
    FN_ROUND_MATERIAL = 0x3848340

    REGS_X0_X8 = (
        UC_ARM64_REG_X0,
        UC_ARM64_REG_X1,
        UC_ARM64_REG_X2,
        UC_ARM64_REG_X3,
        UC_ARM64_REG_X4,
        UC_ARM64_REG_X5,
        UC_ARM64_REG_X6,
        UC_ARM64_REG_X7,
        UC_ARM64_REG_X8,
    )


    def align_down(value: int, align: int = 0x1000) -> int:
        return value & ~(align - 1)


    def align_up(value: int, align: int = 0x1000) -> int:
        return (value + align - 1) & ~(align - 1)


    def u32(value: int) -> int:
        return value & 0xFFFFFFFF


    def u64(value: int) -> int:
        return value & 0xFFFFFFFFFFFFFFFF


    def le32(data: bytes, offset: int = 0) -> int:
        return struct.unpack_from("<I", data, offset)[0]


    def le64(data: bytes, offset: int = 0) -> int:
        return struct.unpack_from("<Q", data, offset)[0]


    def rol32(value: int, shift: int) -> int:
        shift &= 31
        value &= 0xFFFFFFFF
        return u32((value << shift) | (value >> ((32 - shift) & 31)))


    def rol64(value: int, shift: int) -> int:
        shift &= 63
        value &= 0xFFFFFFFFFFFFFFFF
        return u64((value << shift) | (value >> ((64 - shift) & 63)))


    def ror64(value: int, shift: int) -> int:
        shift &= 63
        value &= 0xFFFFFFFFFFFFFFFF
        return u64((value >> shift) | (value << ((64 - shift) & 63)))


    def rotl8(value: int, shift: int) -> int:
        value &= 0xFF
        shift &= 7
        if shift == 0:
            return value
        return ((value << shift) | (value >> (8 - shift))) & 0xFF


    def rotr8(value: int, shift: int) -> int:
        value &= 0xFF
        shift &= 7
        if shift == 0:
            return value
        return ((value >> shift) | (value << (8 - shift))) & 0xFF


    def mix64(a1: int, a2: int, a3: int) -> int:
        v6 = u64(a2 ^ 0xD1B54A32D192ED03)
        v5 = u64(a3 - 0x6B2FB644ECCEEE15)
        v8 = u64(0xBF58476D1CE4E5B9 * (u64(a1 - 0x61C8864680B583EB) ^ rol64(v6, 17)))
        v7 = u64(0x94D049BB133111EB * u64(v6 + ror64(v5, 23)))
        v4 = u64(v8 ^ v7 ^ v5 ^ rol64(u64(v8 + v7), 31))
        return u64(v4 ^ ror64(v8, 29))


    def native_crc(data: bytes, seed: int) -> int:
        value = u32(seed ^ 0xA53C5A5C)
        for idx, byte in enumerate(data):
            x = u32(value ^ ((byte & 0xFF) << (8 * (idx & 3))))
            for _ in range(8):
                x = u32((-(x & 1) & 0x82F63B78) ^ (x >> 1))
            value = rol32(x, 5)
        return u32(value ^ 0x5C3AC3A5)


    def kdf(label: str, context: bytes, out_len: int) -> bytes:
        out = bytearray()
        counter = 1
        label_b = label.encode("ascii")
        while len(out) < out_len:
            h = hashlib.sha256()
            h.update(label_b)
            h.update(b"\x00")
            h.update(struct.pack("<I", len(context)))
            h.update(context)
            h.update(struct.pack("<I", counter))
            out.extend(h.digest())
            counter += 1
        return bytes(out[:out_len])


    @dataclass
    class Stub:
        name: str
        addr: int


    class NativeEmu:
        def __init__(self, lib_path: Path):
            self.binary = lief.parse(str(lib_path))
            if self.binary is None:
                raise RuntimeError(f"failed to parse {lib_path}")
            self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            self.stubs_by_addr: dict[int, Stub] = {}
            self.stub_impls: dict[str, Callable[[], None]] = {}
            self.heap_cur = HEAP_BASE
            self.allocs: dict[int, int] = {}
            self.tls_errno = TLS_BASE + 0x200
            self._map_binary()
            self._apply_relocations()
            self._map_runtime()
            self._install_stubs()
            self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
            self.mu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)

        def _map_binary(self) -> None:
            for seg in self.binary.segments:
                if seg.type.name != "LOAD":
                    continue
                vaddr = BASE + seg.virtual_address
                start = align_down(vaddr)
                end = align_up(vaddr + max(seg.virtual_size, len(seg.content)))
                self.mu.mem_map(start, end - start, UC_PROT_ALL)
                if seg.content:
                    self.mu.mem_write(vaddr, bytes(seg.content))

        def _apply_relocations(self) -> None:
            for reloc in self.binary.dynamic_relocations:
                type_name = getattr(reloc.type, "name", str(reloc.type))
                write_addr = BASE + reloc.address
                if type_name == "AARCH64_RELATIVE":
                    self.mu.mem_write(write_addr, struct.pack("<Q", BASE + reloc.addend))
                    continue
                if type_name not in {"AARCH64_ABS64", "AARCH64_GLOB_DAT"}:
                    continue
                symbol = reloc.symbol
                if symbol is None or symbol.value == 0:
                    continue
                self.mu.mem_write(write_addr, struct.pack("<Q", BASE + symbol.value + reloc.addend))

        def _map_runtime(self) -> None:
            self.mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
            self.mu.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
            self.mu.mem_map(TLS_BASE, TLS_SIZE, UC_PROT_ALL)
            self.mu.mem_map(STUB_BASE, 0x100000, UC_PROT_ALL)
            self.mu.mem_map(RET_SENTINEL & ~0xFFF, 0x1000, UC_PROT_ALL)
            self.mu.mem_write(TLS_BASE + 0x28, struct.pack("<Q", 0x1122334455667788))

        def _install_stubs(self) -> None:
            for idx, reloc in enumerate(self.binary.pltgot_relocations):
                symbol = reloc.symbol
                if symbol is None:
                    continue
                name = symbol.name
                stub_addr = STUB_BASE + idx * STUB_STRIDE
                self.stubs_by_addr[stub_addr] = Stub(name=name, addr=stub_addr)
                self.mu.mem_write(stub_addr, b"\xC0\x03\x5F\xD6")
                self.mu.mem_write(BASE + reloc.address, struct.pack("<Q", stub_addr))

            self.stub_impls.update(
                {
                    "__cxa_atexit": self._stub_ret0,
                    "__cxa_finalize": self._stub_ret0,
                    "__register_atfork": self._stub_ret0,
                    "__stack_chk_fail": self._stub_abort,
                    "abort": self._stub_abort,
                    "__errno": self._stub_errno,
                    "malloc": self._stub_malloc,
                    "calloc": self._stub_calloc,
                    "free": self._stub_free,
                    "realloc": self._stub_realloc,
                    "_Znwm": self._stub_malloc,
                    "_Znam": self._stub_malloc,
                    "_ZnwmSt11align_val_t": self._stub_aligned_new,
                    "_ZnamSt11align_val_t": self._stub_aligned_new,
                    "_ZdlPv": self._stub_free,
                    "_ZdaPv": self._stub_free,
                    "_ZdlPvSt11align_val_t": self._stub_free,
                    "_ZdaPvSt11align_val_t": self._stub_free,
                    "__cxa_allocate_exception": self._stub_malloc,
                    "__cxa_free_exception": self._stub_free,
                    "_ZNSt20bad_array_new_lengthC1Ev": self._stub_ret0,
                    "_ZNSt20bad_array_new_lengthD1Ev": self._stub_ret0,
                    "_ZNSt6__ndk19to_stringEm": self._stub_string_to_string_u64,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev": self._stub_string_dtor,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_": self._stub_string_copy_ctor,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm": self._stub_string_init_ptr_len,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_": self._stub_string_assign_string,
                    "_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm": self._stub_string_find_char,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc": self._stub_string_push_back,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5eraseEmm": self._stub_string_erase,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc": self._stub_string_resize,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc": self._stub_string_assign_cstr,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKc": self._stub_string_insert_cstr,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm": self._stub_string_insert_ptr_len,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmmc": self._stub_string_insert_fill,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc": self._stub_string_append_cstr,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEmc": self._stub_string_append_fill,
                    "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7replaceEmmPKcm": self._stub_string_replace_ptr_len,
                    "posix_memalign": self._stub_posix_memalign,
                    "memcpy": self._stub_memcpy,
                    "__memcpy_chk": self._stub_memcpy,
                    "memmove": self._stub_memmove,
                    "memset": self._stub_memset,
                    "__memset_chk": self._stub_memset,
                    "memcmp": self._stub_memcmp,
                    "memchr": self._stub_memchr,
                    "strlen": self._stub_strlen,
                    "__strlen_chk": self._stub_strlen,
                    "strcmp": self._stub_strcmp,
                    "strncmp": self._stub_strncmp,
                    "pthread_once": self._stub_pthread_once,
                    "pthread_mutex_lock": self._stub_ret0,
                    "pthread_mutex_unlock": self._stub_ret0,
                    "pthread_rwlock_rdlock": self._stub_ret0,
                    "pthread_rwlock_wrlock": self._stub_ret0,
                    "pthread_rwlock_unlock": self._stub_ret0,
                    "pthread_cond_wait": self._stub_ret0,
                    "pthread_cond_broadcast": self._stub_ret0,
                    "pthread_key_create": self._stub_pthread_key_create,
                    "pthread_key_delete": self._stub_ret0,
                    "pthread_getspecific": self._stub_ret0,
                    "pthread_setspecific": self._stub_ret0,
                    "sysconf": self._stub_sysconf,
                    "mprotect": self._stub_ret0,
                    "getauxval": self._stub_ret0,
                    "__system_property_get": self._stub_system_property_get,
                    "dlsym": self._stub_ret0,
                    "dl_iterate_phdr": self._stub_ret0,
                    "syscall": self._stub_ret0,
                    "android_set_abort_message": self._stub_ret0,
                }
            )

        def _hook_code(self, mu: Uc, address: int, _size: int, _user_data: object) -> None:
            if address == RET_SENTINEL:
                mu.emu_stop()
                return
            stub = self.stubs_by_addr.get(address)
            if stub is None:
                return
            impl = self.stub_impls.get(stub.name, self._stub_ret0)
            impl()
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))

        def _hook_mem_invalid(self, _mu: Uc, access: int, address: int, size: int, value: int, _user_data: object) -> bool:
            kind = {
                UC_MEM_READ_UNMAPPED: "read",
                UC_MEM_WRITE_UNMAPPED: "write",
                UC_MEM_FETCH_UNMAPPED: "exec",
            }.get(access, str(access))
            raise RuntimeError(f"unmapped {kind} at 0x{address:x} size=0x{size:x} value=0x{value:x}")

        def _read_cstr(self, addr: int) -> bytes:
            out = bytearray()
            while True:
                ch = bytes(self.mu.mem_read(addr, 1))
                if ch == b"\x00":
                    return bytes(out)
                out += ch
                addr += 1

        def _string_read(self, obj: int) -> bytes:
            if obj == 0:
                return b""
            raw = bytes(self.mu.mem_read(obj, 24))
            if raw[0] & 1:
                size = le64(raw, 8)
                ptr = le64(raw, 16)
                if ptr == 0 or size == 0:
                    return b""
                return bytes(self.mu.mem_read(ptr, size))
            size = raw[0] >> 1
            return raw[1 : 1 + size]

        def _string_write(self, obj: int, value: bytes) -> None:
            if obj == 0:
                return
            value = bytes(value)
            if len(value) <= 22:
                raw = bytearray(24)
                raw[0] = (len(value) << 1) & 0xFF
                raw[1 : 1 + len(value)] = value
                self.mu.mem_write(obj, bytes(raw))
                return
            cap = align_up(len(value) + 1, 16)
            ptr = self._malloc(cap)
            self.mu.mem_write(ptr, value + b"\x00" * (cap - len(value)))
            raw = struct.pack("<QQQ", cap | 1, len(value), ptr)
            self.mu.mem_write(obj, raw)

        def _stub_string_to_string_u64(self) -> None:
            value = self.mu.reg_read(UC_ARM64_REG_X0)
            dst = self.mu.reg_read(UC_ARM64_REG_X8)
            self._string_write(dst, str(value).encode("ascii"))
            self._set_ret(dst)

        def _stub_string_dtor(self) -> None:
            self._set_ret(0)

        def _stub_string_copy_ctor(self) -> None:
            dst = self.mu.reg_read(UC_ARM64_REG_X0)
            src = self.mu.reg_read(UC_ARM64_REG_X1)
            self._string_write(dst, self._string_read(src))
            self._set_ret(dst)

        def _stub_string_init_ptr_len(self) -> None:
            dst = self.mu.reg_read(UC_ARM64_REG_X0)
            ptr = self.mu.reg_read(UC_ARM64_REG_X1)
            size = self.mu.reg_read(UC_ARM64_REG_X2)
            self._string_write(dst, bytes(self.mu.mem_read(ptr, size)) if ptr else b"")
            self._set_ret(dst)

        def _stub_string_assign_string(self) -> None:
            dst = self.mu.reg_read(UC_ARM64_REG_X0)
            src = self.mu.reg_read(UC_ARM64_REG_X1)
            self._string_write(dst, self._string_read(src))
            self._set_ret(dst)

        def _stub_string_find_char(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            ch = self.mu.reg_read(UC_ARM64_REG_X1) & 0xFF
            pos = self.mu.reg_read(UC_ARM64_REG_X2)
            idx = self._string_read(obj).find(bytes([ch]), pos)
            self._set_ret(0xFFFFFFFFFFFFFFFF if idx < 0 else idx)

        def _stub_string_push_back(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            ch = self.mu.reg_read(UC_ARM64_REG_X1) & 0xFF
            self._string_write(obj, self._string_read(obj) + bytes([ch]))
            self._set_ret(obj)

        def _stub_string_erase(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            pos = self.mu.reg_read(UC_ARM64_REG_X1)
            count = self.mu.reg_read(UC_ARM64_REG_X2)
            s = self._string_read(obj)
            if count == 0xFFFFFFFFFFFFFFFF:
                count = len(s) - min(pos, len(s))
            self._string_write(obj, s[:pos] + s[pos + count :])
            self._set_ret(obj)

        def _stub_string_resize(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            size = self.mu.reg_read(UC_ARM64_REG_X1)
            ch = self.mu.reg_read(UC_ARM64_REG_X2) & 0xFF
            s = self._string_read(obj)
            if len(s) < size:
                s += bytes([ch]) * (size - len(s))
            else:
                s = s[:size]
            self._string_write(obj, s)
            self._set_ret(obj)

        def _stub_string_assign_cstr(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            ptr = self.mu.reg_read(UC_ARM64_REG_X1)
            self._string_write(obj, self._read_cstr(ptr) if ptr else b"")
            self._set_ret(obj)

        def _stub_string_insert_cstr(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            pos = self.mu.reg_read(UC_ARM64_REG_X1)
            ptr = self.mu.reg_read(UC_ARM64_REG_X2)
            insert = self._read_cstr(ptr) if ptr else b""
            s = self._string_read(obj)
            pos = min(pos, len(s))
            self._string_write(obj, s[:pos] + insert + s[pos:])
            self._set_ret(obj)

        def _stub_string_insert_ptr_len(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            pos = self.mu.reg_read(UC_ARM64_REG_X1)
            ptr = self.mu.reg_read(UC_ARM64_REG_X2)
            size = self.mu.reg_read(UC_ARM64_REG_X3)
            insert = bytes(self.mu.mem_read(ptr, size)) if ptr else b""
            s = self._string_read(obj)
            pos = min(pos, len(s))
            self._string_write(obj, s[:pos] + insert + s[pos:])
            self._set_ret(obj)

        def _stub_string_insert_fill(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            pos = self.mu.reg_read(UC_ARM64_REG_X1)
            count = self.mu.reg_read(UC_ARM64_REG_X2)
            ch = self.mu.reg_read(UC_ARM64_REG_X3) & 0xFF
            s = self._string_read(obj)
            pos = min(pos, len(s))
            self._string_write(obj, s[:pos] + bytes([ch]) * count + s[pos:])
            self._set_ret(obj)

        def _stub_string_append_cstr(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            ptr = self.mu.reg_read(UC_ARM64_REG_X1)
            self._string_write(obj, self._string_read(obj) + (self._read_cstr(ptr) if ptr else b""))
            self._set_ret(obj)

        def _stub_string_append_fill(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            count = self.mu.reg_read(UC_ARM64_REG_X1)
            ch = self.mu.reg_read(UC_ARM64_REG_X2) & 0xFF
            self._string_write(obj, self._string_read(obj) + bytes([ch]) * count)
            self._set_ret(obj)

        def _stub_string_replace_ptr_len(self) -> None:
            obj = self.mu.reg_read(UC_ARM64_REG_X0)
            pos = self.mu.reg_read(UC_ARM64_REG_X1)
            count = self.mu.reg_read(UC_ARM64_REG_X2)
            ptr = self.mu.reg_read(UC_ARM64_REG_X3)
            size = self.mu.reg_read(UC_ARM64_REG_X4)
            repl = bytes(self.mu.mem_read(ptr, size)) if ptr else b""
            s = self._string_read(obj)
            pos = min(pos, len(s))
            self._string_write(obj, s[:pos] + repl + s[pos + count :])
            self._set_ret(obj)

        def _malloc(self, size: int, align: int = 0x10) -> int:
            size = max(size, 1)
            cur = align_up(self.heap_cur, align)
            end = cur + align_up(size, 0x10)
            if end > HEAP_BASE + HEAP_SIZE:
                raise MemoryError("emulated heap exhausted")
            self.heap_cur = end
            self.allocs[cur] = size
            self.mu.mem_write(cur, b"\x00" * align_up(size, 0x10))
            return cur

        def _set_ret(self, value: int) -> None:
            self.mu.reg_write(UC_ARM64_REG_X0, u64(value))

        def _stub_ret0(self) -> None:
            self._set_ret(0)

        def _stub_abort(self) -> None:
            raise RuntimeError("abort/__stack_chk_fail reached")

        def _stub_errno(self) -> None:
            self._set_ret(self.tls_errno)

        def _stub_malloc(self) -> None:
            self._set_ret(self._malloc(self.mu.reg_read(UC_ARM64_REG_X0)))

        def _stub_calloc(self) -> None:
            nmemb = self.mu.reg_read(UC_ARM64_REG_X0)
            size = self.mu.reg_read(UC_ARM64_REG_X1)
            self._set_ret(self._malloc(nmemb * size))

        def _stub_aligned_new(self) -> None:
            size = self.mu.reg_read(UC_ARM64_REG_X0)
            align = self.mu.reg_read(UC_ARM64_REG_X1)
            self._set_ret(self._malloc(size, align=max(align, 0x10)))

        def _stub_free(self) -> None:
            self._set_ret(0)

        def _stub_realloc(self) -> None:
            ptr = self.mu.reg_read(UC_ARM64_REG_X0)
            size = self.mu.reg_read(UC_ARM64_REG_X1)
            new_ptr = self._malloc(size)
            if ptr:
                old_size = self.allocs.get(ptr, 0)
                copy_len = min(old_size, size)
                if copy_len:
                    self.mu.mem_write(new_ptr, bytes(self.mu.mem_read(ptr, copy_len)))
            self._set_ret(new_ptr)

        def _stub_posix_memalign(self) -> None:
            memptr = self.mu.reg_read(UC_ARM64_REG_X0)
            align = self.mu.reg_read(UC_ARM64_REG_X1)
            size = self.mu.reg_read(UC_ARM64_REG_X2)
            ptr = self._malloc(size, align=max(align, 0x10))
            self.mu.mem_write(memptr, struct.pack("<Q", ptr))
            self._set_ret(0)

        def _stub_memcpy(self) -> None:
            dst = self.mu.reg_read(UC_ARM64_REG_X0)
            src = self.mu.reg_read(UC_ARM64_REG_X1)
            n = self.mu.reg_read(UC_ARM64_REG_X2)
            self.mu.mem_write(dst, bytes(self.mu.mem_read(src, n)))
            self._set_ret(dst)

        def _stub_memmove(self) -> None:
            self._stub_memcpy()

        def _stub_memset(self) -> None:
            dst = self.mu.reg_read(UC_ARM64_REG_X0)
            value = self.mu.reg_read(UC_ARM64_REG_X1) & 0xFF
            n = self.mu.reg_read(UC_ARM64_REG_X2)
            self.mu.mem_write(dst, bytes([value]) * n)
            self._set_ret(dst)

        def _stub_memcmp(self) -> None:
            a = self.mu.reg_read(UC_ARM64_REG_X0)
            b = self.mu.reg_read(UC_ARM64_REG_X1)
            n = self.mu.reg_read(UC_ARM64_REG_X2)
            av = self.mu.mem_read(a, n)
            bv = self.mu.mem_read(b, n)
            self._set_ret(0 if av == bv else ((av > bv) - (av < bv)))

        def _stub_memchr(self) -> None:
            src = self.mu.reg_read(UC_ARM64_REG_X0)
            c = self.mu.reg_read(UC_ARM64_REG_X1) & 0xFF
            n = self.mu.reg_read(UC_ARM64_REG_X2)
            idx = self.mu.mem_read(src, n).find(bytes([c]))
            self._set_ret(0 if idx < 0 else src + idx)

        def _stub_strlen(self) -> None:
            self._set_ret(len(self._read_cstr(self.mu.reg_read(UC_ARM64_REG_X0))))

        def _stub_strcmp(self) -> None:
            a = self._read_cstr(self.mu.reg_read(UC_ARM64_REG_X0))
            b = self._read_cstr(self.mu.reg_read(UC_ARM64_REG_X1))
            self._set_ret((a > b) - (a < b))

        def _stub_strncmp(self) -> None:
            a = self.mu.reg_read(UC_ARM64_REG_X0)
            b = self.mu.reg_read(UC_ARM64_REG_X1)
            n = self.mu.reg_read(UC_ARM64_REG_X2)
            av = self.mu.mem_read(a, n)
            bv = self.mu.mem_read(b, n)
            self._set_ret((av > bv) - (av < bv))

        def _stub_pthread_once(self) -> None:
            once_ptr = self.mu.reg_read(UC_ARM64_REG_X0)
            init_routine = self.mu.reg_read(UC_ARM64_REG_X1)
            value = le32(self.mu.mem_read(once_ptr, 4))
            if value == 0:
                self.mu.mem_write(once_ptr, struct.pack("<I", 1))
                saved_lr = self.mu.reg_read(UC_ARM64_REG_LR)
                self.mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
                self.mu.emu_start(init_routine, RET_SENTINEL)
                self.mu.reg_write(UC_ARM64_REG_LR, saved_lr)
            self._set_ret(0)

        def _stub_pthread_key_create(self) -> None:
            key_ptr = self.mu.reg_read(UC_ARM64_REG_X0)
            self.mu.mem_write(key_ptr, struct.pack("<I", 1))
            self._set_ret(0)

        def _stub_sysconf(self) -> None:
            self._set_ret(4096)

        def _stub_getauxval(self) -> None:
            self._set_ret(0)

        def _stub_system_property_get(self) -> None:
            dst = self.mu.reg_read(UC_ARM64_REG_X1)
            self.mu.mem_write(dst, b"\x00")
            self._set_ret(0)

        def alloc(self, size: int, align: int = 0x10) -> int:
            return self._malloc(size, align)

        def write(self, addr: int, data: bytes) -> None:
            self.mu.mem_write(addr, data)

        def read(self, addr: int, size: int) -> bytes:
            return bytes(self.mu.mem_read(addr, size))

        def read_ro(self, addr: int, size: int) -> bytes:
            return self.read(BASE + addr, size)

        def call(self, addr: int, regs: dict[int, int] | None = None, count: int = 50_000_000) -> int:
            regs = regs or {}
            sp = STACK_BASE + STACK_SIZE - 0x10000
            self.mu.reg_write(UC_ARM64_REG_SP, sp)
            self.mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
            self.mu.reg_write(UC_ARM64_REG_TPIDR_EL0, TLS_BASE)
            for reg in REGS_X0_X8:
                self.mu.reg_write(reg, 0)
            for reg, val in regs.items():
                self.mu.reg_write(reg, u64(val))
            self.mu.reg_write(UC_ARM64_REG_PC, BASE + addr)
            self.mu.emu_start(BASE + addr, RET_SENTINEL, count=count)
            return self.mu.reg_read(UC_ARM64_REG_X0)


    class NativeFinalInverter:
        def __init__(self) -> None:
            self.emu = NativeEmu(LIB_PATH)
            self.target = self.emu.read_ro(ADDR_TARGET, 192)
            self.pad_seed = self.emu.read_ro(ADDR_PAD_SEED, 64)
            self.table = self.emu.read_ro(ADDR_TABLE, 64)
            self.target_crc = le32(self.emu.read_ro(ADDR_TARGET_CRC, 4))
            self.dummy_packet = self.emu.alloc(184)
            self.emu.write(self.dummy_packet, b"\x00" * 184)
            self.stream_ctx: dict[int, tuple[bytes, int]] = {}
            self.vm_ctx: dict[int, tuple[bytes, bytes, bytes, int, int, int]] = {}

        def derive_stream_ctx(self, phase: int) -> tuple[bytes, int]:
            cached = self.stream_ctx.get(phase)
            if cached is not None:
                return cached
            ptr = self.emu.alloc(0x400)
            self.emu.write(ptr, b"\x00" * 0x400)
            ret = self.emu.call(
                FN_STREAM_CTX,
                {
                    UC_ARM64_REG_X0: self.dummy_packet,
                    UC_ARM64_REG_X1: 184,
                    UC_ARM64_REG_X2: phase,
                    UC_ARM64_REG_X3: ptr,
                },
            )
            if (ret & 1) == 0:
                raise RuntimeError(f"sub_38484D4 failed for phase {phase}")
            raw = self.emu.read(ptr, 924)
            self.stream_ctx[phase] = (raw, ptr)
            return raw, ptr

        def sm4_core(self, ctx_ptr: int, data16: bytes) -> bytes:
            if len(data16) != 16:
                raise ValueError("sm4_core input must be 16 bytes")
            in_ptr = self.emu.alloc(16)
            out_ptr = self.emu.alloc(16)
            self.emu.write(in_ptr, data16)
            self.emu.write(out_ptr, b"\x00" * 16)
            self.emu.call(
                FN_SM4_CORE,
                {
                    UC_ARM64_REG_X0: ctx_ptr,
                    UC_ARM64_REG_X1: in_ptr,
                    UC_ARM64_REG_X2: out_ptr,
                },
            )
            return self.emu.read(out_ptr, 16)

        def derive_vm_ctx(self, phase: int) -> tuple[bytes, bytes, bytes, int, int, int]:
            cached = self.vm_ctx.get(phase)
            if cached is not None:
                return cached
            mat_ptr = self.emu.alloc(48)
            self.emu.write(mat_ptr, b"\x00" * 48)
            self.emu.call(
                FN_VM_MATERIAL,
                {
                    UC_ARM64_REG_X0: phase,
                    UC_ARM64_REG_X8: mat_ptr,
                },
            )
            mat = self.emu.read(mat_ptr, 48)
            mat32 = mat[:32]
            v40 = le64(mat, 32)
            v41 = le64(mat, 40)
            seed96 = bytearray(self.table + mat32)
            for idx in range(96):
                h = mix64(v40, u64(v41 + idx), phase ^ 0x574246494E564D30)
                seed96[idx] = rotl8(seed96[idx] ^ ((h >> (8 * (idx & 7))) & 0xFF), phase + idx)

            desc_seed = u32(native_crc(mat32, phase ^ 0x564D5742) ^ (v40 >> 32))
            seed_ptr = self.emu.alloc(96)
            desc_ptr = self.emu.alloc(36)
            self.emu.write(seed_ptr, bytes(seed96))
            self.emu.write(desc_ptr, b"\x00" * 36)
            ret = self.emu.call(
                FN_WBAES_DESC,
                {
                    UC_ARM64_REG_X0: seed_ptr,
                    UC_ARM64_REG_X1: 96,
                    UC_ARM64_REG_X2: desc_seed,
                    UC_ARM64_REG_X3: desc_ptr,
                },
            )
            if (ret & 1) == 0:
                raise RuntimeError(f"sub_380D31C failed for VM phase {phase}")
            desc = self.emu.read(desc_ptr, 36)
            cached = (mat, bytes(seed96), desc, seed_ptr, desc_ptr, desc_seed)
            self.vm_ctx[phase] = cached
            return cached

        def wbaes_transform(self, seed_ptr: int, desc_ptr: int, data16: bytes, tweak: int, decrypt: bool) -> tuple[bytes, int]:
            in_ptr = self.emu.alloc(16)
            out_ptr = self.emu.alloc(16)
            feedback_ptr = self.emu.alloc(4)
            self.emu.write(in_ptr, data16)
            self.emu.write(out_ptr, b"\x00" * 16)
            self.emu.write(feedback_ptr, b"\x00" * 4)
            ret = self.emu.call(
                FN_WBAES_TRANSFORM,
                {
                    UC_ARM64_REG_X0: seed_ptr,
                    UC_ARM64_REG_X1: 96,
                    UC_ARM64_REG_X2: desc_ptr,
                    UC_ARM64_REG_X3: in_ptr,
                    UC_ARM64_REG_X4: tweak,
                    UC_ARM64_REG_X5: 1 if decrypt else 0,
                    UC_ARM64_REG_X6: out_ptr,
                    UC_ARM64_REG_X7: feedback_ptr,
                },
            )
            if (ret & 1) == 0:
                raise RuntimeError("sub_380D948 failed")
            return self.emu.read(out_ptr, 16), le32(self.emu.read(feedback_ptr, 4))

        def round_material(self, right32: bytes, round_index: int, block_index: int) -> bytes:
            if len(right32) != 32:
                raise ValueError("round material input must be 32 bytes")
            right_ptr = self.emu.alloc(32)
            out_ptr = self.emu.alloc(32)
            self.emu.write(right_ptr, right32)
            self.emu.write(out_ptr, b"\x00" * 32)
            seed = (round_index | (block_index << 32)) ^ 0x46494E5245563031
            self.emu.call(
                FN_ROUND_MATERIAL,
                {
                    UC_ARM64_REG_X0: right_ptr,
                    UC_ARM64_REG_X1: 32,
                    UC_ARM64_REG_X2: round_index,
                    UC_ARM64_REG_X3: seed,
                    UC_ARM64_REG_X8: out_ptr,
                },
            )
            return self.emu.read(out_ptr, 32)

        def invert_stream_layer(self, block: bytes, phase: int) -> bytes:
            if len(block) != 64:
                raise ValueError("stream block must be 64 bytes")
            ctx, ctx_ptr = self.derive_stream_ctx(phase)
            perm = ctx[640:704]
            whiten = ctx[704:768]
            iv = ctx[768:784]
            feedback = ctx[784:904]
            ck_words = [le32(ctx, 384 + 4 * i) for i in range(32)]
            mode = le32(ctx, 920)

            out = bytearray(64)
            v33 = bytearray(iv)
            for group in range(4):
                v32 = bytearray(16)
                for j in range(16):
                    p = j + 16 * group
                    value = v33[j] ^ self.table[(9 * p + phase + j) & 0x3F]
                    value ^= whiten[(5 * p + group) & 0x3F]
                    value ^= feedback[(j + 16 * group + 17 * phase + 11 * group) % 120]
                    value ^= (61 * phase + 41 * group + j) & 0xFF
                    v32[j] = value & 0xFF
                v32[group & 0xF] ^= (-89 * group + phase) & 0xFF
                v31 = self.sm4_core(ctx_ptr, bytes(v32))

                next_v33 = bytearray(16)
                for k in range(16):
                    p = k + 16 * group
                    v24 = block[perm[p]]
                    before_rot = rotr8(v24, whiten[(3 * p + phase) & 0x3F] + k)
                    old_p = before_rot ^ v31[k] ^ whiten[(p + 13 * phase) & 0x3F]
                    old_p ^= feedback[(phase - 16 * group + 8 * p) % 120]
                    old_p &= 0xFF
                    out[p] = old_p
                    if mode == 0:
                        v23 = old_p
                    elif mode == 1:
                        v23 = v24 ^ v31[(k + 5) & 0xF]
                    elif mode == 2:
                        v23 = (old_p + v31[(15 - k) & 0xF]) & 0xFF
                    else:
                        v23 = v24
                    word = ck_words[(k - group + 8 * group) & 0x1F]
                    next_v33[k] = (
                        v23
                        ^ iv[(k + group + phase) & 0xF]
                        ^ feedback[(5 * k + 16 * group + phase) % 120]
                        ^ ((word >> (8 * (k & 3))) & 0xFF)
                    ) & 0xFF
                v33 = next_v33
            return bytes(out)

        def invert_vm_layer(self, block: bytes, phase: int) -> bytes:
            if len(block) != 64:
                raise ValueError("VM block must be 64 bytes")
            mat, seed96, desc, seed_ptr, desc_ptr, _desc_seed = self.derive_vm_ctx(phase)
            mat32 = mat[:32]
            v40 = le64(mat, 32)
            v41 = le64(mat, 40)
            feedback_word = le32(desc, 32)
            out = bytearray(64)
            for group in range(4):
                v29 = bytearray(16)
                for m in range(16):
                    pos = (desc[16 + ((m + phase + group) & 0xF)] + 16 * group) & 0x3F
                    value = rotr8(block[pos], m + group + phase)
                    value ^= mat32[(3 * m + group + phase) & 0x1F]
                    value ^= (feedback_word >> (8 * (m & 3))) & 0xFF
                    v29[m] = value & 0xFF
                tweak = v40 ^ v41 ^ ((phase & 0xFFFFFFFF) << 56) ^ group
                v30, got_feedback = self.wbaes_transform(seed_ptr, desc_ptr, bytes(v29), tweak, decrypt=True)
                if got_feedback != feedback_word:
                    raise RuntimeError(f"WBAES feedback mismatch for phase={phase} group={group}")
                for k in range(16):
                    p = k + 16 * group
                    out[p] = v30[k] ^ mat32[(5 * p + phase) & 0x1F] ^ seed96[(group - p + 8 * p) % 96]
            return bytes(out)

        def invert_feistel(self, block: bytes, block_index: int) -> bytes:
            if len(block) != 64:
                raise ValueError("Feistel block must be 64 bytes")
            cur = bytes(block)
            for round_index in range(15, -1, -1):
                tmp = bytearray(64)
                for m in range(64):
                    v19 = (self.table[(5 * m + round_index + 13 * block_index) & 0x3F] ^ (29 * round_index + m + 81 * block_index)) & 0xFF
                    tmp[m] = (rotr8(cur[m], v19 >> 4) - v19) & 0xFF
                old_right = bytes(tmp[:32])
                material = self.round_material(old_right, round_index, block_index)
                old_left = bytearray(32)
                for k in range(32):
                    v21 = rotl8(self.table[(k - round_index + 8 * round_index) & 0x3F], round_index + k)
                    old_left[k] = tmp[32 + k] ^ material[k] ^ v21
                cur = bytes(old_left + bytearray(old_right))
            return cur

        def invert_block(self, cipher_block: bytes, block_index: int) -> bytes:
            if len(cipher_block) != 64:
                raise ValueError("cipher block must be 64 bytes")
            cur = bytearray(cipher_block)
            for n in range(64):
                v17 = (self.table[(11 * n - block_index + 8 * block_index + 9) & 0x3F] ^ (23 * n + 107 * block_index + 61)) & 0xFF
                cur[n] = rotr8((cur[n] - v17) & 0xFF, v17 ^ n ^ block_index) ^ v17

            cur = bytearray(self.invert_stream_layer(bytes(cur), 3))
            cur = bytearray(self.invert_vm_layer(bytes(cur), 1))
            cur = bytearray(self.invert_stream_layer(bytes(cur), 2))
            cur = bytearray(self.invert_feistel(bytes(cur), block_index))
            cur = bytearray(self.invert_stream_layer(bytes(cur), 1))
            cur = bytearray(self.invert_vm_layer(bytes(cur), 0))
            cur = bytearray(self.invert_stream_layer(bytes(cur), 0))

            for i in range(64):
                v26 = (self.table[(13 * i + 19 * block_index + 7) & 0x3F] ^ (17 * i + 61 * block_index - 91)) & 0xFF
                shift = self.table[(i + 11 * block_index) & 0x3F] + i + block_index
                cur[i] = rotr8(cur[i], shift) ^ v26
            return bytes(cur)

        def forward_native(self, packet184: bytes) -> bytes:
            in_ptr = self.emu.alloc(184)
            out_ptr = self.emu.alloc(192)
            self.emu.write(in_ptr, packet184)
            self.emu.write(out_ptr, b"\x00" * 192)
            self.emu.call(
                FN_FINAL_EXPAND_ENCODE,
                {
                    UC_ARM64_REG_X0: in_ptr,
                    UC_ARM64_REG_X1: 184,
                    UC_ARM64_REG_X8: out_ptr,
                },
                count=200_000_000,
            )
            return self.emu.read(out_ptr, 192)

        def invert(self) -> tuple[bytes, bytes, bytes]:
            if kdf("GM-FINAL-TARGET-SEED", self.pad_seed + b"\x02", 64) != self.table:
                raise RuntimeError("target seed KDF check failed")
            if native_crc(self.target, 0x46494E31) != self.target_crc:
                raise RuntimeError("target ciphertext CRC check failed")

            expanded = bytearray()
            for block_index in range(3):
                expanded.extend(self.invert_block(self.target[64 * block_index : 64 * (block_index + 1)], block_index))
            packet = bytes(expanded[:184])
            pad = kdf("GM-FINAL-PACKET-PAD", packet + self.table + struct.pack("<I", 184), 8)
            if bytes(expanded[184:192]) != pad:
                raise RuntimeError(
                    "padding check failed: "
                    f"got={bytes(expanded[184:192]).hex()} expected={pad.hex()}"
                )
            encoded = self.forward_native(packet)
            if encoded != self.target:
                for idx, (a, b) in enumerate(zip(encoded, self.target)):
                    if a != b:
                        raise RuntimeError(f"native forward check failed at byte {idx}: {a:02x}!={b:02x}")
                raise RuntimeError("native forward check failed with length mismatch")
            return bytes(expanded), packet, pad


    LIB_PATH = so_path

    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module

def build_trace_dispatcher_module() -> types.ModuleType:
    _module_name = "trace_dispatcher"
    """Trace Dispatcher.check f8-affecting C0000 events and diff build_ops()."""


    import copy
    import hashlib
    import json
    import struct
    import traceback
    from dataclasses import asdict
    from typing import Any

    import bridge_semantics as bridge  # noqa: E402
    import recover_hidden_state as hs  # noqa: E402
    import solve_f8_final as f8_model  # noqa: E402


    DEFAULT_INPUT = "A" * 64
    DEFAULT_SDK_INT = 35

    DISPATCHER_OFF = 0x64BB4
    C0001_M51_OFF = 0x149594
    C0001_M52_OFF = 0x14AFC8
    C0001_M53_OFF = 0x14BE5C
    C0001_M54_OFF = 0x14CADC
    C0001_M55_OFF = 0x14D724

    C0002_ALIASES: dict[int, str] = {
        0x14E4C0: "C0002.<clinit>",
        0x156DB8: "C0002.<init>",
        0x1580A8: "C0002.m56_core_signal",
        0x15B508: "C0002.m57_bytebuffer_to_bytes",
        0x15D98C: "C0002.m58_table_pull_signal",
        0x160BD0: "C0002.m60_fixed_signal",
        0x163A9C: "C0002.m61_direct_merge",
        0x16C7F0: "C0002.m62_buffer_merge",
        0x1745F4: "C0002.m63_int_selector",
        0x179BD4: "C0002.m64_state_feed",
        0x160670: "C0002.m59_unsigned_byte",
        0x17E1AC: "C0002.m65_counter_signal",
    }

    C0003_ALIASES: dict[int, str] = {
        0x1824A0: "C0003.m66_checksum",
        0x185DD8: "C0003.m67_packet",
        0x18A308: "C0003.m68_packet",
        0x18F734: "C0003.m69_step_bridge",
        0x195B30: "C0003.m70_step_packet",
        0x19CE84: "C0003.m71_long_mix",
    }

    EXTRA_ALIASES: dict[int, str] = {
        DISPATCHER_OFF: "Dispatcher.check",
        C0001_M51_OFF: "C0001.m51_final_wrapper",
        C0001_M52_OFF: "C0001.m52_step_wrapper",
        C0001_M53_OFF: "C0001.m53_commit_wrapper",
        C0001_M54_OFF: "C0001.m54_bootstrap_wrapper",
        C0001_M55_OFF: "C0001.m55_pull_wrapper",
        **C0002_ALIASES,
        **C0003_ALIASES,
    }

    M11_OFF = hs.METHOD_ALIASES["m11_state_mix"]
    M24_OFF = hs.METHOD_ALIASES["m24_final_packet"]
    M40_OFF = hs.METHOD_ALIASES["m40_token_round_mix"]


    class TraceStop(RuntimeError):
        """Internal early stop once the requested trace boundary is reached."""


    def u32(x: int) -> int:
        return x & 0xFFFFFFFF


    def h32(x: int | None) -> str | None:
        if x is None:
            return None
        return f"0x{u32(x):08x}"


    def h64(x: int | None) -> str | None:
        if x is None:
            return None
        return f"0x{x & 0xFFFFFFFFFFFFFFFF:016x}"


    def ascii_tag(x: int | None) -> str:
        if x is None:
            return ""
        raw = u32(x).to_bytes(4, "big")
        return raw.decode("ascii") if all(32 <= b <= 126 for b in raw) else ""


    def jsonable(value: Any) -> Any:
        if isinstance(value, hs.JavaObj):
            return {"type": "JavaObj", "class": value.cls}
        if isinstance(value, hs.ByteBuffer):
            return {"type": "ByteBuffer", "len": len(value.buf), "pos": value.pos, "head": bytes(value.buf[:16]).hex()}
        if isinstance(value, (bytes, bytearray)):
            return {"type": "bytes", "len": len(value), "hex": bytes(value).hex()}
        if isinstance(value, list):
            return [jsonable(v) for v in value]
        if isinstance(value, dict):
            return {str(k): jsonable(v) for k, v in value.items()}
        if isinstance(value, (str, int, bool)) or value is None:
            return value
        return repr(value)


    def method_alias(code_off: int | None) -> str:
        if code_off is None:
            return ""
        if code_off in EXTRA_ALIASES:
            return EXTRA_ALIASES[code_off]
        for alias, off in hs.METHOD_ALIASES.items():
            if off == code_off:
                return alias
        return f"code_{code_off:#x}"


    def method_info(vm: hs.HiddenDexVM, method_idx: int) -> dict[str, Any]:
        method_id = vm.dex.get_methods()[method_idx]
        body = vm.methods_by_ref.get(method_idx)
        code_off = None if body is None else body.code_off
        return {
            "method_idx": method_idx,
            "class": method_id.get_class_name(),
            "name": method_id.get_name(),
            "desc": method_id.get_descriptor(),
            "code_off": None if code_off is None else f"0x{code_off:x}",
            "alias": method_alias(code_off),
        }


    def ensure_bytebuffer_methods() -> None:
        if not hasattr(hs.ByteBuffer, "put_long"):
            def put_long(self: hs.ByteBuffer, x: int) -> hs.ByteBuffer:
                self.buf[self.pos : self.pos + 8] = hs.le64(x)
                self.pos += 8
                return self

            hs.ByteBuffer.put_long = put_long  # type: ignore[attr-defined]

        if not hasattr(hs.ByteBuffer, "wrap"):
            @classmethod
            def wrap(cls: type[hs.ByteBuffer], data: bytes | bytearray) -> hs.ByteBuffer:
                return cls(bytearray(data))

            hs.ByteBuffer.wrap = wrap  # type: ignore[attr-defined]

        if not hasattr(hs.ByteBuffer, "duplicate"):
            def duplicate(self: hs.ByteBuffer) -> hs.ByteBuffer:
                return hs.ByteBuffer(self.buf, self.pos)

            hs.ByteBuffer.duplicate = duplicate  # type: ignore[attr-defined]

        if not hasattr(hs.ByteBuffer, "remaining"):
            def remaining(self: hs.ByteBuffer) -> int:
                return len(self.buf) - self.pos

            hs.ByteBuffer.remaining = remaining  # type: ignore[attr-defined]

        if not hasattr(hs.ByteBuffer, "get"):
            def get(self: hs.ByteBuffer, out: bytearray) -> hs.ByteBuffer:
                n = len(out)
                out[:] = self.buf[self.pos : self.pos + n]
                self.pos += n
                return self

            hs.ByteBuffer.get = get  # type: ignore[attr-defined]

        if not hasattr(hs.ByteBuffer, "get_long"):
            def get_long(self: hs.ByteBuffer) -> int:
                val = hs.get64(self.buf, self.pos)
                self.pos += 8
                return hs.s64(val)

            hs.ByteBuffer.get_long = get_long  # type: ignore[attr-defined]


    class NativeBridgeStub:
        """Valid-path JNI shim. Status is forced to zero for path tracing."""

        def __init__(self, mode: str = "semantic", cl_seed: int | None = None, sdk_int: int = DEFAULT_SDK_INT) -> None:
            self.mode = mode
            if mode == "semantic" and cl_seed is None:
                raise ValueError("semantic native trace requires a loader seed")
            self.cl_seed = 0 if cl_seed is None else cl_seed
            self.sdk_int = sdk_int
            self.state = bridge.BridgeState()
            self.events: list[dict[str, Any]] = []
            if mode == "semantic":
                try:
                    loaded = self.state.load()
                    class_seed = self.state.cl(sdk_int, self.cl_seed)
                    self.events.append(
                        {
                            "kind": "native_bootstrap",
                            "mode": mode,
                            "load": bool(loaded),
                            "sdk_int": sdk_int,
                            "loader_m22_seed": h64(cl_seed),
                            "cl_seed": h64(class_seed),
                            "flags": h32(self.state.flags),
                        }
                    )
                except Exception as exc:
                    self.events.append({"kind": "native_bootstrap_error", "mode": mode, "error": repr(exc)})

        def _code_for_packet(self, name: str, data: bytes) -> tuple[int, int]:
            if self.mode == "semantic":
                record = self.state.step(data) if name == "step" else self.state.run(data)
                return bridge.run_record_value(record)
            digest = bridge.digest64(data, 0x47554D4453545542 ^ len(data))
            return digest, 0

        def run_or_step(self, name: str, data_arg: Any) -> bytearray:
            data = bytes(data_arg or b"")
            try:
                code, raw_status = self._code_for_packet(name, data)
                error = None
            except Exception as exc:
                code = bridge.digest64(data, 0x4552525354554230)
                raw_status = None
                error = repr(exc)
            out = bridge.le64(code) + bridge.le32(0)
            self.events.append(
                {
                    "kind": f"native_{name}",
                    "input_len": len(data),
                    "input_head": data[:16].hex(),
                    "code": h64(code),
                    "raw_status": h32(raw_status),
                    "returned_status": h32(0),
                    "error": error,
                }
            )
            return bytearray(out)

        def pull_or_rp(self, name: str, a: int, index: int) -> hs.ByteBuffer:
            try:
                if self.mode == "semantic":
                    data = self.state.pull(a, index) if name == "pull" else self.state.rp(a, index)
                else:
                    seed = bridge.digest64(bridge.le32(a) + bridge.le32(index), 0x50554C4C53545542)
                    stream = seed
                    out = bytearray()
                    for i in range(64):
                        if (i & 7) == 0:
                            stream = bridge.splitmix64_final(stream + i + u32(a))
                        out.append((stream >> (8 * (i & 7))) & 0xFF)
                    data = bytes(out)
                error = None
            except Exception as exc:
                data = bytes(64)
                error = repr(exc)
            self.events.append(
                {
                    "kind": f"native_{name}",
                    "arg0": h32(a),
                    "arg1": h32(index),
                    "return_len": len(data),
                    "return_head": data[:16].hex(),
                    "error": error,
                }
            )
            return hs.ByteBuffer(bytearray(data), 0)

        def bool_call(self, name: str, packet: Any) -> bool:
            data = bytes(packet or b"")
            self.events.append(
                {
                    "kind": f"native_{name}",
                    "packet_len": len(data),
                    "packet_head": data[:16].hex(),
                    "return": True,
                }
            )
            return True


    class FullTraceVM(hs.HiddenDexVM):
        def __init__(self, native_mode: str = "semantic", cl_seed: int | None = None, sdk_int: int = DEFAULT_SDK_INT) -> None:
            ensure_bytebuffer_methods()
            super().__init__()
            self.native = NativeBridgeStub(native_mode, cl_seed=cl_seed, sdk_int=sdk_int)
            self.clinit_by_class: dict[str, int] = {
                body.cls_name: body.code_off
                for body in self.methods_by_ref.values()
                if body.name == "<clinit>"
            }
            self.class_clinit_done: set[str] = set()

        def ensure_class_clinit(self, cls: str) -> None:
            if cls == self.c0000_cls:
                self.ensure_clinit()
                self.class_clinit_done.add(cls)
                return
            code_off = self.clinit_by_class.get(cls)
            if code_off is None or cls in self.class_clinit_done:
                return
            self.class_clinit_done.add(cls)
            self.call_offset(code_off, [])

        def _invoke_regs(self, ins: Any) -> tuple[list[int], int]:
            ops = ins.get_operands()
            method_idx = ops[-1][1]
            method_id = self.dex.get_methods()[method_idx]
            include_this = not ins.get_name().startswith("invoke-static")
            types = hs.parse_method_slots(method_id.get_descriptor(), include_this)
            if ins.get_name().endswith("/range"):
                r = ops[0][1]
                out: list[int] = []
                for t in types:
                    out.append(r)
                    r += hs.slot_width(t)
                return out, method_idx
            raw_regs = [op[1] for op in ops[:-1]]
            out = []
            pos = 0
            for t in types:
                if pos >= len(raw_regs):
                    raise RuntimeError(f"bad invoke operands for {ins.get_output()}")
                out.append(raw_regs[pos])
                pos += hs.slot_width(t)
            return out, method_idx

        def _setup_registers(self, body: hs.MethodBody, args: list[Any], include_this: bool | None = None) -> list[Any]:
            if include_this is None:
                flags = body.encoded.get_access_flags_string().split()
                include_this = "static" not in flags
            return super()._setup_registers(body, args, include_this)

        def _new_instance(self, type_desc: str) -> hs.JavaObj:
            self.ensure_class_clinit(type_desc)
            if type_desc == self.c0000_cls:
                return self.new_c0000()
            return hs.JavaObj(type_desc)

        def method_args_from_regs(self, body: hs.MethodBody, regs: list[Any]) -> list[Any]:
            include_this = "static" not in body.encoded.get_access_flags_string().split()
            types = hs.parse_method_slots(body.desc, include_this)
            slots = sum(hs.slot_width(t) for t in types)
            start = body.registers_size - slots
            out: list[Any] = []
            r = start
            for t in types:
                out.append(regs[r])
                r += hs.slot_width(t)
            return out

        def sparse_switch_target(self, body: hs.MethodBody, off: int, ins: Any, value: int) -> int | None:
            payload_off = self._branch_target(off, ins)
            idx = body.off_to_index[payload_off]
            raw = body.instructions[idx].get_raw()
            _, size = struct.unpack_from("<HH", raw, 0)
            key_off = 4
            target_off = key_off + 4 * size
            value = hs.s32(value)
            for i in range(size):
                key = struct.unpack_from("<i", raw, key_off + 4 * i)[0]
                if key == value:
                    rel = struct.unpack_from("<i", raw, target_off + 4 * i)[0]
                    return off + rel * 2
            return None

        def _java_invoke(self, method_idx: int, args: list[Any], invoke_name: str) -> tuple[bool, Any]:
            method_id = self.dex.get_methods()[method_idx]
            cls = method_id.get_class_name()
            name = method_id.get_name()

            if cls == "Lcom/guardmaster/ctf/GuardJni;":
                if name in {"run", "step"}:
                    return True, self.native.run_or_step(name, args[0] if args else None)
                if name in {"rp", "pull"}:
                    return True, self.native.pull_or_rp(name, args[0], args[1])
                if name in {"commit", "finalizeCheck"}:
                    return True, self.native.bool_call(name, args[0] if args else None)

            if cls == "Ljava/nio/ByteBuffer;":
                if name == "wrap":
                    return True, hs.ByteBuffer.wrap(args[0])  # type: ignore[attr-defined]
                if name == "duplicate":
                    return True, args[0].duplicate()
                if name == "remaining":
                    return True, args[0].remaining()
                if name == "get":
                    return True, args[0].get(args[1])
                if name == "getLong":
                    return True, args[0].get_long()
                if name == "putLong":
                    return True, args[0].put_long(args[1])

            body = self.methods_by_ref.get(method_idx)
            if body is not None and name != "<clinit>" and "static" in body.encoded.get_access_flags_string().split():
                self.ensure_class_clinit(cls)

            return super()._java_invoke(method_idx, args, invoke_name)

        def _exec(self, body: hs.MethodBody, args: list[Any]) -> Any:
            regs = self._setup_registers(body, args)
            pc = 0
            last_result: Any = None
            steps = 0
            while True:
                if steps > 2_000_000:
                    raise RuntimeError(f"step limit in method off {body.code_off:#x} pc {pc:#x}")
                steps += 1
                idx = body.off_to_index.get(pc)
                if idx is None:
                    raise RuntimeError(f"bad pc {pc:#x} in method {body.code_off:#x}")
                ins = body.instructions[idx]
                off = body.offsets[idx]
                name = ins.get_name()
                ops = ins.get_operands()
                next_pc = off + ins.get_length()
                if self.event_hook is not None:
                    self.event_hook(body, off, regs, ins)
                if body.code_off in self.trace_code_offsets:
                    self.trace_log.append(f"{body.code_off:#x}+{off:#06x} {name} {ins.get_output()}")
                if self.trace_predicate is not None and self.trace_predicate(body, off, regs, ins):
                    def trace_value(v: Any) -> Any:
                        if isinstance(v, (bytes, bytearray)):
                            return bytes(v).hex()
                        if isinstance(v, list):
                            return [trace_value(x) for x in v]
                        if isinstance(v, hs.JavaObj):
                            return f"<{v.cls} fields={len(v.fields)}>"
                        return v

                    snap = {f"v{i}": trace_value(v) for i, v in enumerate(regs) if i < self.trace_register_limit}
                    self.trace_log.append(
                        f"PRED {body.code_off:#x}+{off:#06x} {name} {ins.get_output()} "
                        f"{json.dumps(snap, ensure_ascii=False)}"
                    )
                if (body.code_off, off) in self.trace_detail_offsets:
                    def trace_value(v: Any) -> Any:
                        if isinstance(v, (bytes, bytearray)):
                            return bytes(v).hex()
                        if isinstance(v, list):
                            return [trace_value(x) for x in v]
                        if isinstance(v, hs.JavaObj):
                            return f"<{v.cls} fields={len(v.fields)}>"
                        return v

                    snap = {f"v{i}": trace_value(v) for i, v in enumerate(regs) if i < self.trace_register_limit}
                    self.trace_log.append(f"DETAIL {body.code_off:#x}+{off:#06x} {name} {json.dumps(snap, ensure_ascii=False)}")

                if name == "nop" or name.endswith("-payload"):
                    pass
                elif name in ("const/4", "const/16", "const"):
                    regs[ops[0][1]] = hs.s32(ops[1][1])
                elif name in ("const-wide/16", "const-wide"):
                    regs[ops[0][1]] = hs.s64(ops[1][1])
                elif name == "const/high16":
                    regs[ops[0][1]] = hs.s32(ops[1][1])
                elif name == "const-string":
                    regs[ops[0][1]] = ops[1][2]
                elif name in ("move", "move/from16", "move-object", "move-object/from16", "move-wide/from16"):
                    regs[ops[0][1]] = regs[ops[1][1]]
                elif name == "move-result" or name == "move-result-object" or name == "move-result-wide":
                    regs[ops[0][1]] = last_result
                elif name == "move-exception":
                    regs[ops[0][1]] = None
                elif name == "goto/32":
                    next_pc = self._branch_target(off, ins)
                elif name == "sparse-switch":
                    target = self.sparse_switch_target(body, off, ins, regs[ops[0][1]])
                    if target is not None:
                        next_pc = target
                elif name.startswith("if-"):
                    vals = [regs[op[1]] for op in ops if op[0].name == "REGISTER"]
                    take = False
                    if name == "if-eqz":
                        take = vals[0] == 0 or vals[0] is False or vals[0] is None
                    elif name == "if-nez":
                        take = not (vals[0] == 0 or vals[0] is False or vals[0] is None)
                    elif name == "if-gtz":
                        take = hs.s32(vals[0]) > 0
                    elif name == "if-gez":
                        take = hs.s32(vals[0]) >= 0
                    elif name == "if-ltz":
                        take = hs.s32(vals[0]) < 0
                    elif name == "if-lez":
                        take = hs.s32(vals[0]) <= 0
                    elif name == "if-eq":
                        take = vals[0] == vals[1]
                    elif name == "if-ne":
                        take = vals[0] != vals[1]
                    elif name == "if-lt":
                        take = hs.s32(vals[0]) < hs.s32(vals[1])
                    elif name == "if-ge":
                        take = hs.s32(vals[0]) >= hs.s32(vals[1])
                    elif name == "if-gt":
                        take = hs.s32(vals[0]) > hs.s32(vals[1])
                    else:
                        raise NotImplementedError(name)
                    if take:
                        next_pc = self._branch_target(off, ins)
                elif name == "add-int":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] + regs[ops[2][1]])
                elif name == "add-int/2addr":
                    regs[ops[0][1]] = hs.s32(regs[ops[0][1]] + regs[ops[1][1]])
                elif name == "add-int/lit8":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] + ops[2][1])
                elif name == "sub-int":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] - regs[ops[2][1]])
                elif name == "sub-int/2addr":
                    regs[ops[0][1]] = hs.s32(regs[ops[0][1]] - regs[ops[1][1]])
                elif name == "rsub-int/lit8":
                    regs[ops[0][1]] = hs.s32(ops[2][1] - regs[ops[1][1]])
                elif name == "mul-int":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] * regs[ops[2][1]])
                elif name == "mul-int/2addr":
                    regs[ops[0][1]] = hs.s32(regs[ops[0][1]] * regs[ops[1][1]])
                elif name == "mul-int/lit8":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] * ops[2][1])
                elif name == "div-int/lit8":
                    regs[ops[0][1]] = hs.s32(int(hs.s32(regs[ops[1][1]]) / ops[2][1]))
                elif name == "rem-int":
                    regs[ops[0][1]] = hs.s32(hs.s32(regs[ops[1][1]]) % hs.s32(regs[ops[2][1]]))
                elif name == "rem-int/2addr":
                    regs[ops[0][1]] = hs.s32(hs.s32(regs[ops[0][1]]) % hs.s32(regs[ops[1][1]]))
                elif name == "xor-int":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] ^ regs[ops[2][1]])
                elif name == "xor-int/2addr":
                    regs[ops[0][1]] = hs.s32(regs[ops[0][1]] ^ regs[ops[1][1]])
                elif name == "xor-int/lit8":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] ^ ops[2][1])
                elif name == "and-int/lit8":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] & ops[2][1])
                elif name == "and-int/lit16":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] & ops[2][1])
                elif name == "or-int/2addr":
                    regs[ops[0][1]] = hs.s32(regs[ops[0][1]] | regs[ops[1][1]])
                elif name == "or-int/lit8":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] | ops[2][1])
                elif name == "shl-int":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] << (regs[ops[2][1]] & 31))
                elif name == "shl-int/lit8":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]] << (ops[2][1] & 31))
                elif name == "ushr-int":
                    regs[ops[0][1]] = hs.s32((regs[ops[1][1]] & hs.MASK32) >> (regs[ops[2][1]] & 31))
                elif name == "ushr-int/2addr":
                    regs[ops[0][1]] = hs.s32((regs[ops[0][1]] & hs.MASK32) >> (regs[ops[1][1]] & 31))
                elif name == "ushr-int/lit8":
                    regs[ops[0][1]] = hs.s32((regs[ops[1][1]] & hs.MASK32) >> (ops[2][1] & 31))
                elif name == "xor-long/2addr":
                    regs[ops[0][1]] = hs.s64(regs[ops[0][1]] ^ regs[ops[1][1]])
                elif name == "and-long/2addr":
                    regs[ops[0][1]] = hs.s64(regs[ops[0][1]] & regs[ops[1][1]])
                elif name == "shl-long":
                    regs[ops[0][1]] = hs.s64(regs[ops[1][1]] << (regs[ops[2][1]] & 63))
                elif name == "shl-long/2addr":
                    regs[ops[0][1]] = hs.s64(regs[ops[0][1]] << (regs[ops[1][1]] & 63))
                elif name == "ushr-long":
                    regs[ops[0][1]] = hs.s64((regs[ops[1][1]] & hs.MASK64) >> (regs[ops[2][1]] & 63))
                elif name == "ushr-long/2addr":
                    regs[ops[0][1]] = hs.s64((regs[ops[0][1]] & hs.MASK64) >> (regs[ops[1][1]] & 63))
                elif name == "cmp-long":
                    a = hs.s64(regs[ops[1][1]])
                    b = hs.s64(regs[ops[2][1]])
                    regs[ops[0][1]] = (a > b) - (a < b)
                elif name == "int-to-byte":
                    regs[ops[0][1]] = hs.s8(regs[ops[1][1]])
                elif name == "int-to-long":
                    regs[ops[0][1]] = hs.s64(hs.s32(regs[ops[1][1]]))
                elif name == "long-to-int":
                    regs[ops[0][1]] = hs.s32(regs[ops[1][1]])
                elif name == "new-instance":
                    regs[ops[0][1]] = self._new_instance(ops[1][2])
                elif name == "new-array":
                    regs[ops[0][1]] = self._array_new(ops[2][2], regs[ops[1][1]])
                elif name in ("filled-new-array", "filled-new-array/range"):
                    type_desc = ops[-1][2]
                    vals = [regs[op[1]] for op in ops[:-1]]
                    arr = bytearray((hs.s32(v) & 0xFF) for v in vals) if type_desc == "[B" else list(vals)
                    last_result = arr
                elif name == "array-length":
                    regs[ops[0][1]] = len(regs[ops[1][1]])
                elif name == "aget":
                    regs[ops[0][1]] = self._array_get(regs[ops[1][1]], regs[ops[2][1]])
                elif name == "aget-byte":
                    regs[ops[0][1]] = self._array_get(regs[ops[1][1]], regs[ops[2][1]], signed_byte=True)
                elif name == "aget-object":
                    regs[ops[0][1]] = self._array_get(regs[ops[1][1]], regs[ops[2][1]])
                elif name == "aput":
                    self._array_put(regs[ops[1][1]], regs[ops[2][1]], regs[ops[0][1]])
                elif name == "aput-byte":
                    self._array_put(regs[ops[1][1]], regs[ops[2][1]], regs[ops[0][1]], byte=True)
                elif name == "aput-object":
                    self._array_put(regs[ops[1][1]], regs[ops[2][1]], regs[ops[0][1]])
                elif name == "fill-array-data":
                    arr = regs[ops[0][1]]
                    target = self._branch_target(off, ins)
                    payload = body.payloads[target]
                    if isinstance(arr, bytearray):
                        arr[: len(payload)] = payload
                    else:
                        width = 4
                        for i in range(0, len(payload), width):
                            arr[i // width] = hs.s32(int.from_bytes(payload[i : i + width], "little"))
                elif name in ("iget", "iget-object", "iget-boolean", "iget-wide"):
                    regs[ops[0][1]] = regs[ops[1][1]].fields.get(self._field_id(ins), 0)
                elif name in ("iput", "iput-object", "iput-boolean", "iput-wide"):
                    regs[ops[1][1]].fields[self._field_id(ins)] = regs[ops[0][1]]
                elif name in ("sget", "sget-boolean", "sget-wide", "sget-object"):
                    regs[ops[0][1]] = self.static_fields.get(self._field_id(ins))
                elif name in ("sput", "sput-boolean", "sput-wide", "sput-object"):
                    self.static_fields[self._field_id(ins)] = regs[ops[0][1]]
                elif name.startswith("invoke-"):
                    reg_ids, method_idx = self._invoke_regs(ins)
                    call_args = [regs[r] for r in reg_ids]
                    handled, last_result = self._java_invoke(method_idx, call_args, name)
                    if not handled:
                        raise NotImplementedError(ins.get_output())
                elif name == "return":
                    return regs[ops[0][1]]
                elif name == "return-object":
                    return regs[ops[0][1]]
                elif name == "return-wide":
                    return regs[ops[0][1]]
                elif name == "return-void":
                    return None
                else:
                    raise NotImplementedError(f"{name} at {body.code_off:#x}+{off:#x}")

                pc = next_pc


    class TraceCollector:
        def __init__(self, vm: FullTraceVM, model: list[dict[str, Any]], stop_on_first_diff: bool = False) -> None:
            self.vm = vm
            self.model = model
            self.stop_on_first_diff = stop_on_first_diff
            self.stop_reason: str | None = None
            self.ids = {alias: idx for idx, alias in vm.field_alias.items()}
            self.events: list[dict[str, Any]] = []
            self.operation_rows: list[dict[str, Any]] = []
            self.direct_f8_writes: list[dict[str, Any]] = []
            self.m40_entries: list[dict[str, Any]] = []
            self.m24_packets: list[dict[str, Any]] = []

        def field_value(self, obj: hs.JavaObj, alias: str) -> Any:
            return obj.fields[self.ids[alias]]

        def scalar_snapshot(self, obj: hs.JavaObj | None) -> dict[str, int | None]:
            if not isinstance(obj, hs.JavaObj):
                return {"f14": None, "f22": None, "f7": None}
            return {
                "f14": int(obj.fields.get(self.ids["f14x69ab180b"], 0)),
                "f22": int(obj.fields.get(self.ids["f22x73e78f8b"], 0)),
                "f7": int(obj.fields.get(self.ids["f7"], 0)),
            }

        def alias_for_value(self, obj: hs.JavaObj, value: Any) -> str | None:
            for idx, alias in self.vm.field_alias.items():
                if obj.fields.get(idx) is value:
                    return alias
            return None

        def _invoke_event(self, body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            reg_ids, method_idx = self.vm._invoke_regs(ins)
            call_args = [regs[r] for r in reg_ids]
            info = method_info(self.vm, method_idx)
            code_off = None if info["code_off"] is None else int(info["code_off"], 16)
            if code_off == M11_OFF:
                obj = call_args[0] if call_args else None
                m40_entry_arg0 = None
                m40_entry_arg1 = None
                if body.code_off == M40_OFF:
                    entry_args = self.vm.method_args_from_regs(body, regs)
                    m40_entry_arg0 = entry_args[-2]
                    m40_entry_arg1 = entry_args[-1]
                row = {
                    "i": len(self.operation_rows),
                    "kind": "m11",
                    "caller": method_alias(body.code_off),
                    "caller_code_off": f"0x{body.code_off:x}",
                    "pc": f"0x{off:x}",
                    "arg0": u32(call_args[-2]),
                    "arg1": u32(call_args[-1]),
                    "arg0_hex": h32(call_args[-2]),
                    "arg1_hex": h32(call_args[-1]),
                    "arg0_ascii": ascii_tag(call_args[-2]),
                    "arg1_ascii": ascii_tag(call_args[-1]),
                    "f14": self.scalar_snapshot(obj)["f14"],
                    "f22": self.scalar_snapshot(obj)["f22"],
                    "f7": self.scalar_snapshot(obj)["f7"],
                    "m40_entry_arg0": None if m40_entry_arg0 is None else u32(m40_entry_arg0),
                    "m40_entry_arg1": None if m40_entry_arg1 is None else u32(m40_entry_arg1),
                    "m40_entry_arg0_hex": h32(m40_entry_arg0),
                    "m40_entry_arg1_hex": h32(m40_entry_arg1),
                    "m40_entry_arg0_ascii": ascii_tag(m40_entry_arg0),
                }
                self.operation_rows.append(row)
                self.events.append({"event": "m11_call", **row})
                if self.stop_on_first_diff and row["i"] < len(self.model):
                    real_cmp = comparable(row)
                    model_cmp = comparable(self.model[row["i"]])
                    if real_cmp != model_cmp:
                        self.stop_reason = f"first operation diff at index {row['i']}"
                        raise TraceStop(self.stop_reason)
            elif code_off == M24_OFF:
                obj = call_args[0] if call_args else None
                f8 = bytes(self.field_value(obj, "f8xa5a7934")) if isinstance(obj, hs.JavaObj) else b""
                ev = {
                    "event": "m24_invoke",
                    "caller": method_alias(body.code_off),
                    "caller_code_off": f"0x{body.code_off:x}",
                    "pc": f"0x{off:x}",
                    "scalars": self.scalar_snapshot(obj),
                    "direct_f8_len": len(f8),
                    "direct_f8_hex": f8.hex(),
                }
                self.events.append(ev)
            elif info["class"] == "Lcom/guardmaster/ctf/GuardJni;":
                self.events.append(
                    {
                        "event": "native_invoke",
                        "method": info["name"],
                        "caller": method_alias(body.code_off),
                        "caller_code_off": f"0x{body.code_off:x}",
                        "pc": f"0x{off:x}",
                        "args": jsonable(call_args),
                    }
                )

        def _m40_event(self, body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            entry_args = self.vm.method_args_from_regs(body, regs)
            obj = entry_args[0] if entry_args else None
            entry_arg0 = entry_args[-2] if len(entry_args) >= 3 else None
            entry_arg1 = entry_args[-1] if len(entry_args) >= 3 else None
            if off == 0:
                ev = {
                    "event": "m40_entry",
                    "caller": method_alias(body.code_off),
                    "pc": f"0x{off:x}",
                    "entry_arg0": h32(entry_arg0),
                    "entry_arg1": h32(entry_arg1),
                    "entry_arg0_ascii": ascii_tag(entry_arg0),
                    "scalars": self.scalar_snapshot(obj),
                }
                self.m40_entries.append(ev)
                self.events.append(ev)
            if ins.get_name() != "aput-byte" or not isinstance(obj, hs.JavaObj):
                return
            ops = ins.get_operands()
            arr = regs[ops[1][1]]
            if self.alias_for_value(obj, arr) != "f8xa5a7934":
                return
            ev = {
                "event": "m40_direct_f8_write",
                "caller": method_alias(body.code_off),
                "pc": f"0x{off:x}",
                "entry_arg0": h32(entry_arg0),
                "entry_arg1": h32(entry_arg1),
                "entry_arg0_ascii": ascii_tag(entry_arg0),
                "index": hs.s32(regs[ops[2][1]]),
                "value": hs.s32(regs[ops[0][1]]) & 0xFF,
                "scalars": self.scalar_snapshot(obj),
            }
            self.direct_f8_writes.append(ev)
            self.events.append(ev)

        def _m24_return_event(self, body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            if ins.get_name() != "return-object":
                return
            ret_reg = ins.get_operands()[0][1]
            packet = bytes(regs[ret_reg])
            entry_args = self.vm.method_args_from_regs(body, regs)
            obj = entry_args[0] if entry_args else None
            f8 = bytes(self.field_value(obj, "f8xa5a7934")) if isinstance(obj, hs.JavaObj) else b""
            ev = {
                "event": "m24_packet",
                "caller": method_alias(body.code_off),
                "pc": f"0x{off:x}",
                "packet_len": len(packet),
                "packet_head": packet[:16].hex(),
                "packet_f8_hex": packet[120:184].hex() if len(packet) >= 184 else "",
                "direct_f8_hex": f8.hex(),
                "packet_f8_matches_direct": len(packet) >= 184 and packet[120:184] == f8,
                "scalars": self.scalar_snapshot(obj),
            }
            self.m24_packets.append(ev)
            self.events.append(ev)

        def hook(self, body: hs.MethodBody, off: int, regs: list[Any], ins: Any) -> None:
            name = ins.get_name()
            if name.startswith("invoke-"):
                self._invoke_event(body, off, regs, ins)
            if body.code_off == M40_OFF:
                self._m40_event(body, off, regs, ins)
            if body.code_off == M24_OFF:
                self._m24_return_event(body, off, regs, ins)


    def model_rows() -> list[dict[str, Any]]:
        rows = []
        for op in f8_model.build_ops():
            row = asdict(op)
            row["arg0_hex"] = h32(op.arg0)
            row["arg1_hex"] = h32(op.arg1)
            row["arg0_ascii"] = ascii_tag(op.arg0)
            row["arg1_ascii"] = ascii_tag(op.arg1)
            row["m40_entry_arg0_hex"] = h32(op.m40_entry_arg0)
            row["m40_entry_arg1_hex"] = h32(op.m40_entry_arg1)
            row["m40_entry_arg0_ascii"] = ascii_tag(op.m40_entry_arg0)
            rows.append(row)
        return rows


    def comparable(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "arg0": u32(row["arg0"]),
            "arg1": u32(row["arg1"]),
            "f14": row["f14"],
            "f22": row["f22"],
            "f7": row["f7"],
            "m40_entry_arg0": None if row.get("m40_entry_arg0") is None else u32(row["m40_entry_arg0"]),
            "m40_entry_arg1": None if row.get("m40_entry_arg1") is None else u32(row["m40_entry_arg1"]),
        }


    def diff_rows(real: list[dict[str, Any]], model: list[dict[str, Any]]) -> dict[str, Any]:
        n = min(len(real), len(model))
        for i in range(n):
            r = comparable(real[i])
            m = comparable(model[i])
            if r == m:
                continue
            if (r["m40_entry_arg0"] is None) != (m["m40_entry_arg0"] is None):
                diff_type = "structure_difference"
            elif r["arg0"] != m["arg0"] or r["arg1"] != m["arg1"] or r["m40_entry_arg0"] != m["m40_entry_arg0"] or r["m40_entry_arg1"] != m["m40_entry_arg1"]:
                diff_type = "argument_difference"
            else:
                diff_type = "scalar_difference"
            return {
                "status": "different",
                "type": diff_type,
                "index": i,
                "real": real[i],
                "model": model[i],
                "real_comparable": r,
                "model_comparable": m,
            }
        if len(real) < len(model):
            return {
                "status": "different",
                "type": "missing_real_row_or_partial_execution",
                "index": len(real),
                "real": None,
                "model": model[len(real)],
            }
        if len(real) > len(model):
            return {
                "status": "different",
                "type": "extra_real_row",
                "index": len(model),
                "real": real[len(model)],
                "model": None,
            }
        return {"status": "same", "type": "none", "index": None, "real": None, "model": None}


    def minimal_fix_from_diff(diff: dict[str, Any], trusted_valid_path: bool) -> list[dict[str, Any]]:
        if not trusted_valid_path:
            return []
        if diff["status"] == "same":
            return []
        if diff["type"] in {"structure_difference", "argument_difference", "scalar_difference", "extra_real_row"}:
            return [diff["real"]] if diff.get("real") is not None else []
        return []


    def branch_assessment(run_status: str, diff: dict[str, Any], counts: dict[str, Any]) -> dict[str, Any]:
        trusted = run_status == "complete" and counts["m24_packets"] > 0
        warning = None
        if not trusted:
            warning = "未执行到 final packet m24；当前差异只能定位 native-stub 路径的首个偏离点，不能直接作为 build_ops() 修正。"
            real = diff.get("real") or {}
            model = diff.get("model") or {}
            if diff.get("index") == 3 and real.get("arg0_ascii") == "NORM" and model.get("arg0_ascii") == "FAUL":
                warning = (
                    "BSTP 后直接进入 NORM/digest 路径，而模型期望进入 FAUL/DIG1 可见循环；"
                    "这说明当前 GuardJni stub 的 native pre-state/返回材料未把 Dispatcher 驱动到目标有效分支。"
                )
        return {
            "trusted_valid_path": trusted,
            "warning": warning,
            "total_operation_rows_known": trusted,
        }


    def run_trace(input_text: str, native_mode: str, cl_seed: int, sdk_int: int, stop_on_first_diff: bool = False) -> dict[str, Any]:
        vm = FullTraceVM(native_mode, cl_seed=cl_seed, sdk_int=sdk_int)
        vm.ensure_clinit()
        model = model_rows()
        collector = TraceCollector(vm, model, stop_on_first_diff=stop_on_first_diff)
        old_hook = vm.event_hook
        vm.event_hook = collector.hook
        result: Any = None
        error: BaseException | None = None
        tb = ""
        try:
            result = vm.call_offset(DISPATCHER_OFF, [input_text])
        except BaseException as exc:
            error = exc
            tb = traceback.format_exc()
        finally:
            vm.event_hook = old_hook

        diff = diff_rows(collector.operation_rows, model)
        run_status = "complete" if error is None else ("stopped_first_diff" if isinstance(error, TraceStop) else "partial")
        counts = {
            "operation_rows": len(collector.operation_rows),
            "model_rows": len(model),
            "m40_operation_rows": sum(1 for row in collector.operation_rows if row.get("m40_entry_arg0") is not None),
            "m40_entries": len(collector.m40_entries),
            "m40_direct_f8_writes": len(collector.direct_f8_writes),
            "m24_packets": len(collector.m24_packets),
            "native_events": len(vm.native.events),
        }
        assessment = branch_assessment(run_status, diff, counts)
        trace = {
            "task": "dispatcher_full_trace_diff_gpt55",
            "input": {
                "description": "fixed 64-byte ASCII test input",
                "length": len(input_text.encode("utf-8")),
                "sha256": hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
            },
            "native_stub_config": {
                "mode": native_mode,
                "sdk_int": sdk_int,
                "loader_m22_seed": h64(cl_seed),
                "force_run_step_status_zero": True,
                "commit_finalize_return": True,
                "stop_on_first_diff": stop_on_first_diff,
            },
            "run": {
                "status": run_status,
                "dispatcher_result": result if isinstance(result, (bool, int, str)) or result is None else repr(result),
                "error_type": type(error).__name__ if error is not None else None,
                "error": str(error) if error is not None else None,
                "stop_reason": collector.stop_reason,
                "traceback": tb,
            },
            "counts": counts,
            "branch_assessment": assessment,
            "operation_rows": collector.operation_rows,
            "model_rows": model,
            "diff": diff,
            "minimal_fix_rows": minimal_fix_from_diff(diff, assessment["trusted_valid_path"]),
            "m40_entries": collector.m40_entries,
            "m40_direct_f8_writes": collector.direct_f8_writes,
            "m24_packets": collector.m24_packets,
            "native_events": vm.native.events,
            "events": collector.events,
        }
        return json.loads(json.dumps(jsonable(trace), ensure_ascii=False))


    _module = types.ModuleType(_module_name)
    _skip = {"_module", "_skip", "_name", "_value", "_module_name"}
    for _name, _value in list(locals().items()):
        if _name in _skip:
            continue
        setattr(_module, _name, _value)
    return _module


def extract_original_files() -> tuple[Path, Path, Path]:
    if not APK_PATH.exists():
        raise FileNotFoundError(APK_PATH)
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    classes_path = WORK / "classes.dex"
    gmx_path = WORK / "guard.gmx"
    so_path = WORK / "libguardmaster.so"
    with zipfile.ZipFile(APK_PATH, "r") as zf:
        classes_path.write_bytes(zf.read("classes.dex"))
        gmx_path.write_bytes(zf.read("assets/guard.gmx"))
        so_path.write_bytes(zf.read("lib/arm64-v8a/libguardmaster.so"))
    return classes_path, gmx_path, so_path


def register_module(module: types.ModuleType) -> types.ModuleType:
    sys.modules[module.__name__] = module
    return module


def rows_to_ops(rows: list[dict], f8_model: types.ModuleType) -> list:
    ops = []
    for row in rows:
        ops.append(
            f8_model.Op(
                row["i"],
                "dispatcher",
                row["caller"],
                row["arg0"],
                row["arg1"],
                row["f14"],
                row["f22"],
                row["f7"],
                row.get("m40_entry_arg0"),
                row.get("m40_entry_arg1"),
            )
        )
    return ops


def main() -> int:
    classes_path, gmx_path, so_path = extract_original_files()
    recovered_path = WORK / "recovered.dex"

    recover_gmx = register_module(build_recover_gmx_module(classes_path, gmx_path, recovered_path))
    gmx_info = recover_gmx.recover_gmx(trace=False)
    if not recovered_path.exists():
        raise RuntimeError("hidden dex recovery did not produce recovered.dex")
    _payload, loader_key = recover_gmx.load_app_payload_and_key()
    loader_seed = derive_loader_m22_seed(loader_key)

    bridge_semantics = register_module(build_bridge_semantics_module())
    hidden = register_module(build_recover_hidden_state_module(recovered_path, WORK, FIELD_ALIASES))
    prim = register_module(build_c0000_primitives_module())
    m40_pre = register_module(build_m40_f8_pre_module())
    f8_model = register_module(build_solve_f8_final_module())
    native = register_module(build_invert_final_check_module(so_path, WORK))
    tracer = register_module(build_trace_dispatcher_module())

    inverter = native.NativeFinalInverter()
    expanded, packet, pad = inverter.invert()
    final_state = packet[0x78:0xB8]

    trace = tracer.run_trace(
        DUMMY_INPUT,
        native_mode="semantic",
        cl_seed=loader_seed,
        sdk_int=tracer.DEFAULT_SDK_INT,
        stop_on_first_diff=False,
    )
    if trace["run"]["status"] != "complete" or trace["counts"]["operation_rows"] != 77:
        raise RuntimeError(json.dumps(trace["run"], ensure_ascii=False))
    if not trace["m24_packets"]:
        raise RuntimeError("Dispatcher trace did not reach final packet serialization")

    vm = hidden.HiddenDexVM(recovered_path, WORK / "unused_C0000.java")
    vm.ensure_clinit()
    ops = rows_to_ops(trace["operation_rows"], f8_model)
    candidate, _inverse_steps = f8_model.apply_inverse(vm, final_state, ops)
    replay, _forward_steps = f8_model.apply_forward(vm, candidate, ops)
    ok, errors, info = f8_model.validate_candidate(candidate, final_state, replay)
    if not ok:
        raise RuntimeError("; ".join(errors))

    OUT_FLAG.write_bytes(candidate + b"\n")
    print(candidate.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

```
