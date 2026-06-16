# Alice
动态解密链的大致结构如下：

1. `Alice.app/Contents/MacOS/Alice` 负责读取输入 PNG，检查尺寸和 RGB 数据长度，然后定位 `libalice_stage0.dylib`。
2. `libalice_stage0.dylib` 定位 `Resources/core.dat`，用基于 LCG 的字节流和 XOR 对其解密。
3. 解密结果是新的 Mach-O dylib，`stage0` 将其写到 `/tmp/.cXXXXXX.dylib` 一类的临时路径，再通过 `dlopen/dlsym` 进入下一阶段。
4. 下一阶段继续读取 `Resources/alice.dat`，其中包含真正的校验逻辑和 QR 相关的数据 blob。
5. 最终恢复出来的核心约束不是原图像本身，而是 QR Code 的一部分数据码字和 RS 校验码字。

恢复出的 QR 参数为：

```text
QR Code Version: 5
ECC level: M
Mask pattern: 4
```

Version 5、纠错等级 M 的 QR 码会拆成 RS block。这里用到的是第一个 RS block：

```text
data codewords: 43 bytes
RS parity:      24 bytes
```

从动态阶段中可以恢复出第一块的 24 字节 RS parity：

```python
KNOWN_EC = [
    0x4F, 0xF9, 0xB2, 0x3E, 0x24, 0xAC, 0xB5, 0x98,
    0x69, 0xBD, 0xCB, 0xAF, 0xAB, 0xCC, 0x1F, 0xAA,
    0x6E, 0x01, 0x2E, 0xC4, 0x58, 0xCE, 0xFD, 0x61,
]
```

同时 QR padding 也能确定。第一块共有 43 个 data codewords，其中末尾 8 字节已经固定为 QR padding：

```python
KNOWN_TAIL = [0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11]
```

因此未知量只剩下前 35 字节，也就是 `35 * 8 = 280` 个 bit。直接爆破显然不现实，但 RS parity 对这些 bit 的影响可以转成 GF(2) 线性方程，这是本题最关键的降维。


QR 使用的 Reed-Solomon 运算在 GF(256) 上进行，常见 primitive polynomial 为 `0x11d`。表面上看，RS 是 GF(256) 上的多项式运算，好像不容易直接消元；但这里未知量是每个输入 bit，而 GF(256) 里的加法本质是 XOR，乘以固定常数对 8 个 bit 来说是一个 GF(2) 线性映射。因此每一个未知 bit 对最终 24 字节 parity 的影响都是线性的。

构造线性方程的方法如下：

1. 先构造一个 base data block，前 35 字节全部置 0，末尾 8 字节填入 `KNOWN_TAIL`。
2. 用正常 QR RS 算法计算 base block 的 parity，记为 `base_ec`。
3. 对每一个未知 bit 单独翻转一次，重新计算 parity，并和 `base_ec` 做 XOR，得到这个 bit 对最终 parity 的贡献。
4. 目标 parity 是 `KNOWN_EC`，所以 `KNOWN_EC ^ base_ec` 就是所有未知 bit 贡献的总和。
5. 24 字节 parity 一共是 `24 * 8 = 192` 个 bit，因此可以得到 192 条 GF(2) 方程。

这一步只利用了 RS 校验，还没有利用 QR 的数据格式。由于未知 bit 有 280 个，192 条方程还不足以唯一确定答案，需要继续叠加 QR byte mode 的结构约束。

QR byte mode 的数据结构为：

```text
mode indicator: 0100
length field:   8 bits, because version 5 uses 8-bit byte-mode length
payload:        length bytes
terminator:     up to 4 zero bits
padding:        byte alignment, then 0xEC, 0x11 alternating
```

题目 flag 格式为 `SCTF{...}`，所以 payload 还满足：

```text
payload starts with b"SCTF{"
payload ends with b"}"
```

最终求解时枚举可能的 payload 长度，对每个长度加入以下约束：

```text
mode = 0100
length = 当前枚举长度
prefix = SCTF{
suffix = }
terminator = 0000
padding = 0xEC, 0x11, 0xEC, 0x11, ...
```

这样就能把 QR 结构约束和 RS parity 约束合在同一个 GF(2) 线性系统中。对每个长度做高斯消元后，只有长度 29 的解是满秩、可打印且满足所有校验的。长度 30、31、32 也会因为方程欠定得到形式上的解，但 payload 中包含大量不可打印字节，不符合 flag 格式。

长度 29 的数据码字为：

```text
41 d5 34 35 44 67 b6 63 07 27 47 56 e6 55 f6 64
07 63 07 27 35 f7 46 83 35 f6 26 c6 f6 47 d0 ec
11 ec 11
```

按 QR byte mode 解析：

```text
0x4        -> byte mode
0x1d       -> payload length = 29
payload    -> SCTF{f0rtune_f@v0rs_th3_blod}
terminator -> 0000
padding    -> EC 11 EC 11 ...
```

exp.py
```python

EC_COUNT = 24
DATA_COUNT = 43
NVAR_BYTES = 35
NVAR_BITS = NVAR_BYTES * 8

KNOWN_TAIL = [0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11]

KNOWN_EC = [
    0x4F, 0xF9, 0xB2, 0x3E, 0x24, 0xAC, 0xB5, 0x98,
    0x69, 0xBD, 0xCB, 0xAF, 0xAB, 0xCC, 0x1F, 0xAA,
    0x6E, 0x01, 0x2E, 0xC4, 0x58, 0xCE, 0xFD, 0x61,
]

PRIMITIVE = 0x11D
GF_EXP = [0] * 512
GF_LOG = [0] * 256


def init_gf256():
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= PRIMITIVE
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]


def poly_mul(p, q):
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a == 0:
            continue
        for j, b in enumerate(q):
            if b:
                out[i + j] ^= gf_mul(a, b)
    return out


def rs_generator(degree):
    gen = [1]
    for i in range(degree):
        gen = poly_mul(gen, [1, GF_EXP[i]])
    return gen


def ec_for_data(data):
    gen = rs_generator(EC_COUNT)
    ec = [0] * EC_COUNT
    for byte in data:
        factor = byte ^ ec[0]
        ec = ec[1:] + [0]
        if factor:
            for i in range(EC_COUNT):
                ec[i] ^= gf_mul(gen[i + 1], factor)
    return ec


def bit_index(byte_pos, bit_pos):
    return byte_pos * 8 + bit_pos


def add_bit(rows, pos, value):
    if pos < NVAR_BITS:
        rows.append((1 << pos, value & 1))


def add_byte(rows, byte_pos, value):
    for i in range(8):
        add_bit(rows, bit_index(byte_pos, i), (value >> (7 - i)) & 1)


def build_parity_rows():
    base = [0] * DATA_COUNT
    base[35:43] = KNOWN_TAIL
    base_ec = ec_for_data(base)

    contributions = []
    for var in range(NVAR_BITS):
        data = base[:]
        data[var // 8] ^= 1 << (7 - (var % 8))
        diff = [a ^ b for a, b in zip(ec_for_data(data), base_ec)]
        contributions.append(diff)

    rows = []
    target = [a ^ b for a, b in zip(KNOWN_EC, base_ec)]
    for ec_i in range(EC_COUNT):
        for bit in range(8):
            mask = 0
            for var, diff in enumerate(contributions):
                if (diff[ec_i] >> (7 - bit)) & 1:
                    mask |= 1 << var
            rows.append((mask, (target[ec_i] >> (7 - bit)) & 1))
    return rows


def add_qr_payload_constraints(rows, length, prefix=b"SCTF{", suffix=b"}"):
    for i, bit in enumerate([0, 1, 0, 0]):
        add_bit(rows, i, bit)

    for i in range(8):
        add_bit(rows, 4 + i, (length >> (7 - i)) & 1)

    for k, ch in enumerate(prefix[:length]):
        for i in range(8):
            add_bit(rows, 12 + 8 * k + i, (ch >> (7 - i)) & 1)

    if length >= len(suffix):
        for s_i, ch in enumerate(suffix):
            k = length - len(suffix) + s_i
            for i in range(8):
                add_bit(rows, 12 + 8 * k + i, (ch >> (7 - i)) & 1)

    term_start = 12 + 8 * length
    for i in range(4):
        add_bit(rows, term_start + i, 0)

    pad_start = length + 2
    for pos in range(pad_start, NVAR_BYTES):
        add_byte(rows, pos, 0xEC if (pos - pad_start) % 2 == 0 else 0x11)


def solve_gf2(rows, nbits=NVAR_BITS):
    basis = {}
    rhs = {}
    for mask, val in rows:
        m = mask
        v = val
        while m:
            pivot = m.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = m
                rhs[pivot] = v
                break
            m ^= basis[pivot]
            v ^= rhs[pivot]
        else:
            if v:
                return None

    sol = 0
    for pivot in sorted(basis):
        parity = (basis[pivot] & sol).bit_count() & 1
        if parity ^ rhs[pivot]:
            sol |= 1 << pivot

    for mask, val in rows:
        if ((mask & sol).bit_count() & 1) != val:
            return None
    return sol, len(basis)


def bits_to_data(sol):
    out = [0] * NVAR_BYTES
    for var in range(NVAR_BITS):
        if (sol >> var) & 1:
            out[var // 8] |= 1 << (7 - (var % 8))
    return out


def extract_payload(data):
    bits = []
    for byte in data:
        bits.extend((byte >> (7 - i)) & 1 for i in range(8))

    mode = int("".join(map(str, bits[:4])), 2)
    length = int("".join(map(str, bits[4:12])), 2)
    payload = bytearray()
    off = 12
    for _ in range(length):
        val = 0
        for bit in bits[off:off + 8]:
            val = (val << 1) | bit
        payload.append(val)
        off += 8
    return mode, length, bytes(payload)


def build_qr_data(payload):
    bits = [0, 1, 0, 0]
    bits.extend((len(payload) >> (7 - i)) & 1 for i in range(8))
    for ch in payload:
        bits.extend((ch >> (7 - i)) & 1 for i in range(8))
    bits.extend([0, 0, 0, 0])
    while len(bits) % 8:
        bits.append(0)

    data = []
    for off in range(0, len(bits), 8):
        val = 0
        for bit in bits[off:off + 8]:
            val = (val << 1) | bit
        data.append(val)

    while len(data) < DATA_COUNT:
        data.append(0xEC if (len(data) - (len(payload) + 2)) % 2 == 0 else 0x11)
    return data


def printable_payload(payload):
    return all(32 <= c <= 126 for c in payload)


def main():
    init_gf256()
    parity_rows = build_parity_rows()
    candidates = []

    for length in range(1, 33):
        rows = parity_rows[:]
        add_qr_payload_constraints(rows, length)
        result = solve_gf2(rows)
        if result is None:
            continue

        sol, rank = result
        data = bits_to_data(sol)
        full_data = data + KNOWN_TAIL
        if ec_for_data(full_data) != KNOWN_EC:
            continue

        mode, qlen, payload = extract_payload(data)
        if mode == 4 and qlen == length and payload.startswith(b"SCTF{") and payload.endswith(b"}"):
            candidates.append((length, rank, payload, data))

    for length, rank, payload, data in candidates:
        status = "printable" if printable_payload(payload) else "non-printable"
    good = [
        item for item in candidates
        if item[1] == NVAR_BITS and printable_payload(item[2])
    ]
    if len(good) != 1:
        raise SystemExit(f"expected exactly one printable full-rank solution, got {len(good)}")

    flag = good[0][2]
    print("flag：", flag.decode())



if __name__ == "__main__":
    main()

# SCTF{f0rtune_f@v0rs_th3_blod}
```
