# Cuneiform — Writeup

## 题目

`output.txt` 给出 4 个对称矩阵 $C_0,\dots,C_3\in\mathrm{GF}(3^{51})^{9\times9}$(base36 打包)、公开目标向量 $\mathbf p\in\mathrm{GF}(3^{51})^4$、`seal_nonce` 与密文 `vault`。本质是一道**小参数 UOV**($n=9,\,m=4$,油维 $o=4$,醋维 $v=5$)密钥恢复题:`chall.py` 内部固定了一个隐藏 4 维子空间 $V$,使全部公开二次型及其极形式在 $V$ 上消没:
$$
z^\top C_k\,z=0,\qquad z^\top(C_k+C_k^\top)\,z'=0,\qquad \forall\,z,z'\in V,\ k=0,1,2,3 .
$$

flag 经 $V$ 的不变量封印,故**恢复 $V$ 是充要条件**。

## 解题思路

###  恢复隐藏子空间 V(Beullens 交集攻击)

记极形式 $B_k=C_k+C_k^\top$。对 $v\in V$ 与任意 $w\in V$,有 $(B_kv)^\top w=v^\top B_kw=0$,即

$$
B_k\,V\subseteq \mathrm{ann}(V),\qquad \dim\mathrm{ann}(V)=n-o=5 .
$$

取两个**可逆**极形式 $B_i,B_j$,则 $B_iV,B_jV$ 是 5 维空间里的两个 4 维子空间,因 $n<3o$($9<12$)其交非平凡:

$$
\dim\big(B_iV\cap B_jV\big)\;\ge\;2o-(n-o)\;=\;3\;>\;0 .
$$

对交中的 $x$,令 $y_i=B_i^{-1}x,\ y_j=B_j^{-1}x$,则 $y_i,y_j\in V$。于是“求 $V$ 中向量”化为对 $x$ 解 $3m=12$ 个二次方程:

$$
y_i^\top C_k\,y_i=0,\qquad y_j^\top C_k\,y_j=0,\qquad y_i^\top C_k\,y_j=0,\qquad k=0,\dots,3 .
$$

固定 3 个坐标 $x_0,x_1,x_2$(射影归一并切成 0 维),剩 **6 变量 0 维理想**;`degrevlex` 算 Gröbner 基后转 `lex` 求 variety,即得 $V$ 中向量。拿到 2 个线性无关向量 $x_1,x_2\in V$。

**切核交补全 $V$**:把 $B_kx_1,\,B_kx_2$($k=0..3$,共 8 行)堆成 $8\times9$ 矩阵,其行全落在 5 维的 $\mathrm{ann}(V)$ 中故秩为 5,由双零化定理其右核**恰为** $V$:
$$
V=\ker\Big(\,\mathrm{stack}_{k}\big(B_kx_1,\ B_kx_2\big)\,\Big),\qquad \dim=9-5=4 .
$$

### 标定向量 $s^\*$(确定化签名)

封印需要生成器那个唯一解 $s^\*$。对 $V$ 取**“首非零为主元”RREF**得规范基 $Q$ 与自由列集 $\mathcal F$。对 $\mathrm{ctr}=0,1,\dots$,用 $\mathrm{SHAKE256}(\text{nonce}\|\mathrm{ctr})$ 填向量 $w$ 的自由坐标,则目标条件展开:

$$
(w+cQ)^\top C_k\,(w+cQ)=\underbrace{w^\top C_k w}_{\text{常数}}+\underbrace{w^\top B_k(cQ)}_{\text{对 }c\text{ 线性}}+\underbrace{(cQ)^\top C_k(cQ)}_{=0,\ \because\,cQ\in V}=p_k ,
$$

得 $4\times4$ 线性方程组 $\,L\,c=\big(p_k-w^\top C_kw\big)_k$。$L$ 可逆则解出 $c$,$s^\*=w+cQ$。本实例 $\mathrm{ctr}=0$ 命中。这与 UOV 签名同构:固定醋变量后,二次型对油变量退化为线性,解线性系统即可。

###  Plücker 不变量 + 解封

$V$ 的归一化 Plücker 坐标:取 $4\times9$ 基矩阵全部 $\binom94=126$ 个 $4\times4$ 极大子式,再除以首个非零坐标。换基只整体乘标量,故归一后是 $V$ 的**基无关唯一不变量**(保证不同解题者算出同一封印)。

$$
\text{seal}=\mathrm{SHA256}\big(\text{domain}\,\|\,\mathrm{WB}(s^\*)\,\|\,\mathrm{WB}(\mathbf p)\,\|\,\mathrm{WB}(\mathrm{Pl}_{\text{norm}}(V))\,\|\,\text{“}3^{51}\text{”}\big),
$$
$$
\text{flag}=\text{vault}\ \oplus\ \mathrm{SHAKE256}(\text{“seal|”}\,\|\,\text{seal}),
$$

其中 $\mathrm{WB}(\cdot)$ 将每个域元素编为定宽 $\lceil80.83/8\rceil=11$ 字节大端整数。

$$
\boxed{\ \texttt{SCTF\{d71b0c45-d382-42dc-ba68-5780ae1f6e6a\}}\ }
$$

全流程在 Sage 中约 **7 秒**完成。

---

## exp.sage

```python
#!/usr/bin/env sage
"""exp.sage — Cuneiform solution (intersection attack + Plucker seal)."""
import sys, ast, hashlib, time
from itertools import combinations

SEAL_DOMAIN = b"sctf-ur-v7|seal|"
SEAL_STREAM = b"seal|"

def parse_output(path):
    d = {"C": []}
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, _, v = line.partition("="); k, v = k.strip(), v.strip()
        if k in ("p", "w", "N", "M"): d[k] = int(v)
        elif k == "modulus": d["modulus"] = ast.literal_eval(v)
        elif k == "profile": d["profile"] = ast.literal_eval(v)
        elif k == "seal_nonce": d["seal_nonce"] = bytes.fromhex(v)
        elif k == "vault": d["vault"] = bytes.fromhex(v)
        elif k and k[0] == "C" and k[1:].isdigit(): d["C"].append((int(k[1:]), v))
    d["C"] = [b for _, b in sorted(d["C"])]
    return d

def build_field(p, w, coeffs):
    Fp = GF(p); Rx = PolynomialRing(Fp, 'X'); X = Rx.gen()
    g = sum(Fp(coeffs[i]) * X**i for i in range(len(coeffs)))
    return GF(p**w, name='z', modulus=g)

def int_to_K(K, p, w, code):
    d = []
    for _ in range(w):
        d.append(code % p)
        code //= p
    return K(d)

def K_to_int(K, p, w, elt):
    c = elt.polynomial().list(); c += [0]*(w - len(c))
    return sum(int(c[i])*(p**i) for i in range(w))

def unpack_coupling(K, p, w, blob, N):
    inv2 = K(2)**(-1); order = [(i, j) for i in range(N) for j in range(i, N)]
    val = Integer(int(blob, 36)); C = matrix(K, N, N)
    for (i, j) in order:
        val, c = val.quo_rem(p**w)
        if c == 0: continue
        elt = int_to_K(K, p, w, int(c))
        if i == j: C[i, i] = elt
        else: v = elt * inv2; C[i, j] = v; C[j, i] = v
    return C

def rref_first_pivot(M):
    R = M.__copy__(); rows, cols = R.nrows(), R.ncols(); pivots = []; r = 0
    for c in range(cols):
        if r >= rows: break
        piv = None
        for i in range(r, rows):
            if R[i, c] != 0: piv = i; break
        if piv is None: continue
        if piv != r: R.swap_rows(r, piv)
        R[r] = R[r] * (R[r, c]**(-1))
        for i in range(rows):
            if i != r and R[i, c] != 0: R[i] = R[i] - R[i, c] * R[r]
        pivots.append(c); r += 1
    return R, pivots

def quad(C, x):
    xv = vector(C.base_ring(), x) if not hasattr(x, 'parent') else x; return xv * C * xv

def bilin(C, x, y):
    xv = vector(C.base_ring(), x) if not hasattr(x, 'parent') else x
    yv = vector(C.base_ring(), y) if not hasattr(y, 'parent') else y; return xv * C * yv

def main():
    d = parse_output(sys.argv[1] if len(sys.argv) > 1 else "output.txt")
    p, w, N, M = d["p"], d["w"], d["N"], d["M"]
    print(f"[*] GF({p}^{w}), N={N}, M={M}")

    K = build_field(p, w, d["modulus"])
    couplings = [unpack_coupling(K, p, w, b, N) for b in d["C"]]
    profile_K = [int_to_K(K, p, w, int(t) % (p**w)) for t in d["profile"]]
    polars = [C + C.transpose() for C in couplings]

    i, j = next((a,b) for a in range(M) for b in range(a+1,M)
                if polars[a].is_invertible() and polars[b].is_invertible())
    Mi_inv, Mj_inv = polars[i].inverse(), polars[j].inverse()
    NV = N - 3
    trial = [K(0), K(1), K(2), K.gen(), K.gen()+1, K.gen()+2, 2*K.gen(), 2*K.gen()+1, 2*K.gen()+2]
    trial = list(dict.fromkeys(trial))
    print(f"[*] {NV} variables, {len(trial)} trials")

    hits, t0 = [], time.time()
    for a in trial:
        if len(hits) >= 2: break
        for b in trial:
            if len(hits) >= 2: break
            for c in trial:
                if a==0 and b==0 and c==0: continue
                if len(hits) >= 2: break
                R = PolynomialRing(K, [f"x{t}" for t in range(NV)], order="degrevlex")
                xs = list(R.gens()); x = vector(R, [a,b,c]+xs); yi = Mi_inv*x; yj = Mj_inv*x
                eqs = [quad(Ck,yi) for Ck in couplings] + [quad(Ck,yj) for Ck in couplings] + [bilin(Ck,yi,yj) for Ck in couplings]
                I = R.ideal(eqs)
                if I.dimension() != 0: continue
                Rlex = PolynomialRing(K, [f"x{t}" for t in range(NV)], order="lex")
                xs_lex = list(Rlex.gens()); x_lex = vector(Rlex, [a,b,c]+xs_lex)
                yi_lex = Mi_inv*x_lex; yj_lex = Mj_inv*x_lex
                eqs_lex = [quad(Ck,yi_lex) for Ck in couplings] + [quad(Ck,yj_lex) for Ck in couplings] + [bilin(Ck,yi_lex,yj_lex) for Ck in couplings]
                Ilex = Rlex.ideal(eqs_lex)
                for sol in Ilex.variety():
                    oi = Mi_inv * vector(K, [a,b,c]+[sol[Rlex.gen(t)] for t in range(NV)])
                    oj = Mj_inv * vector(K, [a,b,c]+[sol[Rlex.gen(t)] for t in range(NV)])
                    if oi==0 or oj==0: continue
                    if not all(quad(Ck,oi)==0 and quad(Ck,oj)==0 and bilin(Ck,oi,oj)==0 for Ck in couplings): continue
                    for v in (oi,oj):
                        if not hits or matrix(K, hits+[v]).rank() > matrix(K, hits).rank():
                            hits.append(v)
                            print(f"  vector #{len(hits)} ({time.time()-t0:.1f}s)")
    print(f"[+] {len(hits)} vectors ({time.time()-t0:.1f}s)")
    assert len(hits) >= 2

    rows = [list((C+C.transpose())*vector(K,v)) for v in hits for C in couplings]
    ker = matrix(K, rows).right_kernel()
    Kmat = ker.basis_matrix(); basis = [Kmat.row(r) for r in range(Kmat.nrows())]
    blind = [b for b in basis if all(quad(C,b)==0 for C in couplings)]
    family = None
    for subset in combinations(blind, M):
        Fam = matrix(K, list(subset))
        if Fam.rank() < M: continue
        if all((Fam*(C+C.transpose())*Fam.transpose()).is_zero() for C in couplings):
            family = [list(Fam.row(r)) for r in range(M)]; break
    assert family is not None
    print(f"[+] W recovered (dim={M})")

    Fmat = matrix(K, family); Rref, pivots = rref_first_pivot(Fmat)
    Q = Rref[:len(pivots),:]; frees = [c for c in range(N) if c not in set(pivots)]
    def sw(seed, count):
        raw = hashlib.shake_256(seed).digest(count*8)
        return [int_to_K(K,p,w,int.from_bytes(raw[8*i:8*i+8],"big")%(p**w)) for i in range(count)]
    for ctr in range(256):
        u = sw(d["seal_nonce"]+ctr.to_bytes(2,"big"), len(frees))
        wv = [K(0)]*N
        for jj, fc in enumerate(frees): wv[fc] = u[jj]
        wrow = vector(K, wv); L, rhs = [], []
        for k in range(M):
            rhs.append(profile_K[k] - quad(couplings[k], wv))
            wB = wrow * polars[k]; L.append([wB*Q.row(i) for i in range(Q.nrows())])
        Lm = matrix(K, L)
        if Lm.rank() < Q.nrows(): continue
        try: cc = Lm.solve_right(vector(K, rhs))
        except ValueError: continue
        s = wrow + cc*Q
        if all(quad(couplings[k], list(s)) == profile_K[k] for k in range(M)):
            pattern, cal_ctr = list(s), ctr; break
    print(f"[+] calibration ctr={cal_ctr}")

    Fam2 = matrix(K, family); plucker = []
    for cols_tuple in combinations(range(N), M):
        plucker.append(Fam2.matrix_from_columns(list(cols_tuple)).det())
    fn = next(i for i,v in enumerate(plucker) if v!=0)
    plucker_norm = [v * plucker[fn]**(-1) for v in plucker]
    print(f"[+] Plucker: {len(plucker)} coords")

    width = ((p**w).bit_length()+7)//8
    wb = b"".join(int(K_to_int(K,p,w,x)).to_bytes(width,"big") for x in pattern)
    pb = b"".join(int(K_to_int(K,p,w,x)).to_bytes(width,"big") for x in profile_K)
    plb = b"".join(int(K_to_int(K,p,w,x)).to_bytes(width,"big") for x in plucker_norm)
    seal = hashlib.sha256(SEAL_DOMAIN + wb + b"|" + pb + b"|" + plb + b"|" + f"{p}^{w}".encode()).digest()
    ks = hashlib.shake_256(SEAL_STREAM + seal).digest(len(d["vault"]))
    payload = bytes([a.__xor__(b) for a,b in zip(d["vault"], ks)])
    try: text = payload.decode()
    except UnicodeDecodeError: text = repr(payload)
    print(f"[+] FLAG: {text}")

if __name__ == "__main__": main()
```

**运行**:`sage exp.sage output.txt`
