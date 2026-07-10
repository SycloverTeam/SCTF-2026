---
title: SCTF-2026-invisile
date: 2026-6-16 12:00:00
tags:
  - crypto
categories: crypto
banner_img: /img/R-C.jpg
banner_img_height: 150px
---



这次我是出invisble这个题目的人,时间比较紧只有两周所以质量可能不是很能提,多多担待
如果有任何题目或者其他题目的疑问可以找我
ps:怎么没人看我的无敌少侠,而是直接拿ai放个链接梭了,伤心...
参考论文:https://eprint.iacr.org/2019/861.pdf
cve:https://github.com/HugoBond/CVE-2024-31497-POC
# Invincible

这里是一个web端有jwt校验的题目,我们的思路是想办法获得admin权限.
值得注意的是,这个,他限制注册账户.并且你反复清空cookie状态 也不会 重新生成新的jwt .so我们怎么办呢
回顾一下ecdsa的流程.设定 有限域p下的 
私钥 d, 公钥 Q,消息m. 椭圆曲线 E 生成元点G
nonce k= xxx 在有限域p下(0,p)的一个随机数.
R=k*G, r=X(R) 
$s=k^{-1}(e+r*d) Mod~p$
e= hash(m)

最终获得签名 (r,s)
验证签名 ,已经知道 消息m ,签名(r,s),公钥 Q
$k=s^{-1}(e+r*d)$
所以$s^{-1}eG+s^{-1}rQ=R_{1}$
由此得到$X(R_{1})=r$
这个题泄漏了什么信息呢?
我们的k 是用foxhash生成的
```python
#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
from random import Random, getrandbits

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, isPrime, long_to_bytes, sieve_base


HASH_WORD_BITS = 16
HASH_WORDS = 32

def generate_prime(bits: int, a: int) -> int:
    while True:
        p_sub = 2
        for prime in sieve_base:
            p_sub *= prime
            if p_sub.bit_length() > bits - 2:
                break

        for k in range(2, a, 2):
            p = p_sub * k + 1
            if isPrime(p):
                return p
class FoxHash:
    def __init__(self):
        self.key = getrandbits(128)
        self.iv = getrandbits(128)
        self.key_bytes = long_to_bytes(self.key, 16)
        self.iv_bytes = long_to_bytes(self.iv, 16)

    def _to_bytes(self, x):
        if isinstance(x, int):
            x = long_to_bytes(x)
        elif isinstance(x, str):
            x = x.encode()
        elif isinstance(x, bytearray):
            x = bytes(x)
        return x[-16:].rjust(16, b"\x00")

    def _to_int(self, x):
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            x = x.encode()
        elif isinstance(x, bytearray):
            x = bytes(x)
        return bytes_to_long(x or b"\x00")

    def hash(self, m):
        m = sha256(m).digest()
        c1 = AES.new(self.key_bytes, AES.MODE_CBC, iv=self.iv_bytes).encrypt(m)
        c2 = AES.new(c1, AES.MODE_CBC, iv=self.iv_bytes).encrypt(self.key_bytes)
        c1 = sha256(c1).digest()
        c2 = sha256(c2).digest()
        h = []
        r1 = Random(bytes_to_long(c2))
        for _ in range(32):
            h.append(r1.getrandbits(16))

        r2 = Random(self.key)
        n = generate_prime(int(int.from_bytes(m, "big")) % 512, max(500, r2.getrandbits(15)))

        r3 = Random(n)
        pos = r3.getrandbits(5)
        value = r3.getrandbits(16)
        h[pos] = value
        res = 0
        for x in h:
            res = (res << 16) | x

        return res

```


测试过的话会发现,
``` python
def generate_prime(bits: int, a: int) -> int:
    while True:
        p_sub = 2
        for prime in sieve_base:
            p_sub *= prime
            if p_sub.bit_length() > bits - 2:
                break

        for k in range(2, a, 2):
            p = p_sub * k + 1
            if isPrime(p):
                return p
```
 这个函数的只要 相同bit 位次,输出的素数是一样的
 我们之后得到的 pos和value其实都是可预测的泄漏连续16bit
 由此我们就可以构造一个lattice

$k_{i}=s^{-1}_{i}*\{h_{i}+r_{i}*d\}$
$k_{i}=konw_{i}+high_{i}+low_{i}$
$k_{i}=konw*2^{p}+low+high*2^{p+16}$

所以low 有明确的边界:
$0\le low_{i}<2^{p_{i}},~~~~~~0\le high_{i}\le 2^{512-p_{i}-16}$
代入
$s_{i}*konw_{i}*2^{p}+ s_{i}*low_{i}+s_{i}*high_{i}2^{p_{i}+16}\equiv h_{i}+r_{i}*d$

化简 一下:
$$
c_i \equiv s_i kown_i 2^{p_i} - h_i \pmod q, \qquad
a_i \equiv -s_i \pmod q, \qquad
b_i \equiv -s_i 2^{p_i + 16} \pmod q
$$
所以
$r_{i}d=c_{i}-b_{i}high_{i}-a_{i}low_{i}$
由于high和low都是不知道的
设$z_{i}=(u_{i},v_{i})$,
所以$L_{i}(Z_{i})=a_{i}u_{i}+b_{i}v_{i}$
所以$r_{i}d\equiv c_{i}-L_{i}(Z_{i})$
参考传统的 hnp计算方法
我们先把d 这个参数消去,我们用第一个来带入
$r_{0}(c_{i}-L_i(Z_{i}))-r_{i}(C_{0}-L_{0}(Z_{0}))\equiv 0(Mod q)$


  $$
  r_0 \bigl(c_i - L_i(z_i)\bigr) - r_i \bigl(c_0 - L_0(z_0)\bigr) \equiv 0 \pmod q
  $$

  因为前面已经定义了

  $$
  L_i(z_i)=a_i u_i+b_i v_i
  $$

  所以直接展开就是

  $$
  r_0 c_i - r_0 a_i u_i - r_0 b_i v_i - r_i c_0 + r_i a_0 u_0 + r_i b_0 v_0 \equiv 0 \pmod q
  $$

  把常数项和变量项分开：

  $$
  (r_0 c_i - r_i c_0)

  - (r_i a_0)u_0 + (r_i b_0)v_0

  - (r_0 a_i)u_i - (r_0 b_i)v_i
    \equiv 0 \pmod q
    $$

  这时候就可以定义

  $$
  \gamma_i \equiv r_0 c_i - r_i c_0 \pmod q
  $$

  于是式子变成

  $$
  \gamma_i

  - (r_i a_0)u_0 + (r_i b_0)v_0

  - (r_0 a_i)u_i - (r_0 b_i)v_i
    \equiv 0 \pmod q
    $$


  $$
  x_1, x_2, \dots, x_n
  $$
由此,我们依次定义未知数据

  $$
  x_1=u_0,\quad x_2=v_0,\quad x_3=u_1,\quad x_4=v_1,\quad \dots
  $$

  当然如果某个样本没有 u_i 或没有 v_i，那对应变量就不存在，不编号。

  这样一来，上面这条方程里的系数就都可以统一记成 $\alpha_{i,j}$，于是它就改写成

  $$
  \gamma_i + \sum_j \alpha_{i,j} x_j \equiv 0 \pmod q
  $$

于是我们得到.....
  $$
  \gamma_i + \sum_j \alpha_{i,j} x_j = t_i q
  $$
  $$
  A_{i,j}=\alpha_{i,j}
  $$
  之后我们可以由此放缩构造矩阵,已经差不多快半年没看密码了,后面放缩这些全是让ai搞的了哈哈哈..

假设现在排除第一个一共有m个样本.可以构成 
我们构造一个
$$
\dim(B) = m + n + 1
$$
一个这样维度大小的矩阵在这里n=2*n

最后一行前 `m` 列放的是每个方程的常数项：

$$
s \gamma_i
$$
  后面的变量列和最后一列统一放：
$$
A = (\alpha_{i,j}) \in \mathbb{Z}^{m \times n},
\qquad
D = \operatorname{diag}(2^{\mu_{\max}-\mu_1}, \dots, 2^{\mu_{\max}-\mu_n}),
\qquad
\mathbf{1} = (1,\dots,1)^\top
$$
构造如下矩阵
$$
B =
\begin{pmatrix}
s q I_m & 0 & 0 \\
s A^\top & D & 0 \\
s \gamma^\top & c \mathbf{1}^\top & c
\end{pmatrix}
$$
如果足够幸运就能规约出如下
$$
(t_1,\dots,t_m,x_1,\dots,x_n,-1)\,B
=
\bigl(
0,\dots,0,\,
x_1 2^{\mu_{\max}-\mu_1} - c,\,
\dots,\,
x_n 2^{\mu_{\max}-\mu_n} - c,\,
-c
\bigr)
$$
由此我们便能计算私钥d


exp
```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sage.all import Matrix, ZZ

from foxhash import LEAK_BITS, NONCE_BITS, known_window


Q = int(
    "00aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308"
    "70553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
    16,
)
JWT_ALG = "BP512VULN"
TOKEN_COOKIE = "demo_access_token"
MAX_REGISTRATIONS = 40
REDUCTION_PLANS = [("balanced", 36)]
BKZ_BLOCK_SIZES = (36,)


@dataclass(frozen=True)
class Sample:
    index: int
    r: int
    s: int
    h: int
    pos: int
    leak: int


@dataclass(frozen=True)
class Var:
    sample: int
    kind: str
    mu: int
    coeff: int


@dataclass(frozen=True)
class Equation:
    r: int
    c: int
    vars: list[Var]


@dataclass(frozen=True)
class Meta:
    eqs: list[Equation]
    vars: list[Var]
    eq_count: int
    mu_max: int
    center: int


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def center_mod(x: int, q: int) -> int:
    x %= q
    return x - q if x > q // 2 else x


def build_nonce_material(payload: dict[str, Any], signing_input: bytes) -> bytes:
    uid = payload.get("uid", payload.get("id", ""))
    username = payload.get("username", payload.get("sub", ""))
    return f"{uid}:{username}:".encode("utf-8") + signing_input


class Oracle:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.cookies = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))

    def request(self, path: str, method: str = "GET", form: dict[str, str] | None = None) -> bytes:
        data = None
        headers = {}
        if form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        with self.opener.open(req) as resp:
            return resp.read()

    def register(self, username: str, password: str) -> None:
        self.request("/register", method="POST", form={"username": username, "password": password})

    def current_token(self) -> str:
        for cookie in self.cookies:
            if cookie.name == TOKEN_COOKIE:
                return cookie.value
        raise RuntimeError("no auth cookie present")

    def fetch_flag(self, token: str) -> str:
        req = urllib.request.Request(
            f"{self.base_url}/api/admin/flag",
            headers={"Cookie": f"{TOKEN_COOKIE}={token}"},
            method="GET",
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))["flag"]


def parse_token(index: int, token: str) -> Sample:
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    payload = json.loads(b64url_decode(payload_b64))
    r, s = decode_dss_signature(b64url_decode(sig_b64))
    h = int.from_bytes(hashlib.sha512(signing_input).digest(), "big") % Q
    window = known_window(build_nonce_material(payload, signing_input))
    return Sample(index=index, r=r, s=s, h=h, pos=window["nonce_lsb_pos"], leak=window["leak_word"])


def collect_samples(oracle: Oracle, count: int, password: str) -> list[Sample]:
    samples: list[Sample] = []
    for i in range(count):
        username = f"u{int(time.time())}_{i:02d}_{secrets.token_hex(3)}"
        oracle.register(username, password)
        samples.append(parse_token(i, oracle.current_token()))
    return samples


def sample_summary(samples: list[Sample]) -> None:
    positions = len({sample.pos for sample in samples})
    print(
        f"registered {len(samples)} users and collected {len(samples)} jwt signatures across {positions} leak positions",
        flush=True,
    )


def sample_to_equation(sample: Sample) -> Equation:
    shift = sample.pos + LEAK_BITS
    vars: list[Var] = []
    if sample.pos > 0:
        vars.append(Var(sample=sample.index, kind="low", mu=sample.pos, coeff=(-sample.s) % Q))
    if shift < NONCE_BITS:
        vars.append(
            Var(
                sample=sample.index,
                kind="high",
                mu=NONCE_BITS - shift,
                coeff=(-(sample.s * (1 << shift))) % Q,
            )
        )
    c = (sample.s * (sample.leak << sample.pos) - sample.h) % Q
    return Equation(r=sample.r, c=c, vars=vars)


def choose_reference(equations: list[Equation], strategy: str) -> int:
    if strategy == "first":
        return 0
    return min(
        range(len(equations)),
        key=lambda i: (
            max((var.mu for var in equations[i].vars), default=0),
            len(equations[i].vars),
        ),
    )


def build_lattice(samples: list[Sample], strategy: str) -> tuple[Matrix, Meta]:
    eqs = [sample_to_equation(sample) for sample in samples]
    ref_idx = choose_reference(eqs, strategy)
    ref_eq = eqs[ref_idx]
    other = [i for i in range(len(eqs)) if i != ref_idx]

    ordered_vars = list(ref_eq.vars)
    for i in other:
        ordered_vars.extend(eqs[i].vars)

    mu_max = max(var.mu for var in ordered_vars)
    eq_count = len(other)
    dimension = eq_count + len(ordered_vars) + 1
    scale = 1 << mu_max
    rows = [[0] * dimension for _ in range(dimension)]

    for col in range(eq_count):
        rows[col][col] = scale * Q

    eq_col = {eq_idx: col for col, eq_idx in enumerate(other)}
    var_col = eq_count

    for var in ref_eq.vars:
        row = rows[var_col]
        for eq_idx in other:
            coeff = center_mod((-eqs[eq_idx].r * var.coeff) % Q, Q)
            row[eq_col[eq_idx]] = scale * coeff
        row[var_col] = 1 << (mu_max - var.mu)
        var_col += 1

    for eq_idx in other:
        for var in eqs[eq_idx].vars:
            row = rows[var_col]
            coeff = center_mod((ref_eq.r * var.coeff) % Q, Q)
            row[eq_col[eq_idx]] = scale * coeff
            row[var_col] = 1 << (mu_max - var.mu)
            var_col += 1

    center = 1 << (mu_max - 1)
    last = rows[-1]
    for eq_idx in other:
        gamma = center_mod((ref_eq.r * eqs[eq_idx].c - eqs[eq_idx].r * ref_eq.c) % Q, Q)
        last[eq_col[eq_idx]] = scale * gamma
    for col in range(eq_count, dimension):
        last[col] = center

    return Matrix(ZZ, rows), Meta(eqs=eqs, vars=ordered_vars, eq_count=eq_count, mu_max=mu_max, center=center)


def decode_row(row: list[int], meta: Meta) -> dict[tuple[int, str], int] | None:
    if any(int(value) != 0 for value in row[: meta.eq_count]):
        return None
    if row[-1] == -meta.center:
        sign = 1
    elif row[-1] == meta.center:
        sign = -1
    else:
        return None

    recovered: dict[tuple[int, str], int] = {}
    for i, var in enumerate(meta.vars):
        coord = int(row[meta.eq_count + i])
        step = 1 << (meta.mu_max - var.mu)
        num = coord + meta.center if sign == 1 else meta.center - coord
        if num % step != 0:
            return None
        value = num // step
        if not (0 <= value < (1 << var.mu)):
            return None
        recovered[(var.sample, var.kind)] = value
    return recovered


def recover_scalar(meta: Meta, recovered: dict[tuple[int, str], int]) -> int | None:
    guesses: list[int] = []
    for eq in meta.eqs:
        rhs = eq.c
        for var in eq.vars:
            rhs = (rhs - var.coeff * recovered[(var.sample, var.kind)]) % Q
        guesses.append((rhs * pow(eq.r, -1, Q)) % Q)
    return guesses[0] if all(x == guesses[0] for x in guesses) else None


def rank_samples(samples: list[Sample]) -> list[Sample]:
    edge = NONCE_BITS - LEAK_BITS
    return sorted(
        samples,
        key=lambda sample: (
            0 if sample.pos in (0, edge) else 1,
            min(sample.pos, edge - sample.pos),
            sample.index,
        ),
    )


def reduce_and_recover(samples: list[Sample]) -> list[int]:
    ranked = rank_samples(samples)
    found: list[int] = []
    seen: set[int] = set()

    for strategy, subset_size in REDUCTION_PLANS:
        if subset_size > len(ranked):
            continue
        subset = ranked[:subset_size]
        lattice, meta = build_lattice(subset, strategy)
        basis = lattice.LLL()

        for block_size in BKZ_BLOCK_SIZES:
            print(f"interval-ehnp samples={len(subset)} reference={strategy} bkz={block_size}", flush=True)
            reduced = basis.BKZ(block_size=block_size)
            rows = [[int(x) for x in row] for row in reduced.rows()]
            rows.sort(key=lambda row: sum(x * x for x in row))

            for row in rows:
                for candidate in (row, [-x for x in row]):
                    decoded = decode_row(candidate, meta)
                    if decoded is None:
                        continue
                    d = recover_scalar(meta, decoded)
                    if d is None or d in seen:
                        continue
                    seen.add(d)
                    found.append(d)
    return found


def forge_admin_token(d: int, username: str) -> str:
    now = int(time.time())
    header = {"alg": JWT_ALG, "typ": "JWT"}
    payload = {
        "uid": 1,
        "id": 1,
        "sub": username,
        "username": username,
        "role": "admin",
        "created_at": now,
        "iat": now,
        "exp": now + 3600,
        "jti": secrets.token_hex(8),
    }
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = ec.derive_private_key(d, ec.BrainpoolP512R1()).sign(signing_input, ec.ECDSA(hashes.SHA512()))
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


def solve(base_url: str, count: int, password: str, admin_username: str) -> None:
    oracle = Oracle(base_url)
    samples = collect_samples(oracle, count, password)
    sample_summary(samples)

    for d in reduce_and_recover(samples):
        token = forge_admin_token(d, admin_username)
        try:
            flag = oracle.fetch_flag(token)
        except urllib.error.HTTPError:
            continue
        print(f"recovered private key: {d:x}")
        print(f"forged token: {token}")
        print(f"flag: {flag}")
        return

    raise SystemExit("failed to validate recovered private key")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compact SageMath exploit for the 36x16 EHNP JWT challenge.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--count", type=int, default=36)
    parser.add_argument("--password", default="userpass123")
    parser.add_argument("--admin-username", default="admin")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.count > MAX_REGISTRATIONS:
        raise SystemExit(f"refusing to exceed the registration cap ({MAX_REGISTRATIONS})")
    solve(args.base_url, args.count, args.password, args.admin_username)


if __name__ == "__main__":
    main()

```


