#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chall.py — Cuneiform (SCTF 2026)

Four inscribed clay tablets, each encoding a quadratic scoring rule
over GF(3^51) reduced modulo g(X)=X^51+2X+1.  The tablets were fired
blind to a latent subspace.  A sealed scroll opens only for the
unique configuration whose scores match a set of target tallies.

This file documents the generation process.  The deployed instance
is in output.txt.
"""
import os, sys, hashlib
from functools import lru_cache
from itertools import product as _cartesian, combinations as _combinations

# ── parameters ──
RODS, TOKENS, TABLETS = 51, 9, 4
ARCHIVE_NONCE = bytes.fromhex("75722d76372d7363746632303235a4660366")
TARGET_TAG = b"sctf-ur-v7::target-tallies"
_CIPHER_DOMAIN = b"sctf-ur-v7|seal|"
_CIPHER_STREAM = b"seal|"
_TALLY_DOMAIN = b"ur-profile|"

# ── royal tally-field GF(3^w) ──
def _trim(a, p):
    a = [c % p for c in a]
    while len(a) > 1 and a[-1] == 0: a.pop()
    return a
def _poly_mul(a, b, p):
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b): out[i + j] = (out[i + j] + ai * bj) % p
    return _trim(out, p)
def _poly_mod(a, m, p):
    a, m = _trim(a[:], p), _trim(m[:], p)
    invl = pow(m[-1], p - 2, p)
    while len(a) >= len(m) and not (len(a) == 1 and a[0] == 0):
        f = (a[-1] * invl) % p; s = len(a) - len(m)
        for i in range(len(m)): a[s + i] = (a[s + i] - f * m[i]) % p
        a = _trim(a, p)
    return a
def _poly_gcd(a, b, p):
    a, b = _trim(a[:], p), _trim(b[:], p)
    while not (len(b) == 1 and b[0] == 0): a, b = b, _poly_mod(a, b, p)
    return _trim(a, p)
def _poly_pow(base, exp, m, p):
    r, base = [1], _poly_mod(base[:], m, p)
    while exp:
        if exp & 1: r = _poly_mod(_poly_mul(r, base, p), m, p)
        base = _poly_mod(_poly_mul(base, base, p), m, p); exp >>= 1
    return _trim(r, p)
def _prime_factors(mm):
    ds, d = set(), 2
    while d * d <= mm:
        while mm % d == 0: ds.add(d); mm //= d
        d += 1
    if mm > 1: ds.add(mm)
    return ds
def _is_irreducible(full, p, e):
    X = [0, 1]
    if _poly_pow(X, p ** e, full, p) != _trim(X[:], p): return False
    for r in _prime_factors(e):
        h = _poly_pow(X, p ** (e // r), full, p)
        h = h[:] + [0] * (2 - len(h)) if len(h) < 2 else h[:]; h[1] = (h[1] - 1) % p
        if not (len(_poly_gcd(h, full, p)) == 1 and _poly_gcd(h, full, p)[0] != 0): return False
    return True

@lru_cache(maxsize=None)
def _royal_modulus(p, e):
    if e == 1: return (0,)
    for nterms in range(e):
        for positions in _combinations(range(1, e), nterms):
            for midvals in _cartesian(range(1, p), repeat=nterms):
                for c in range(1, p):
                    tail = [0] * e; tail[0] = c
                    for pos, val in zip(positions, midvals): tail[pos] = val
                    if _is_irreducible(tail + [1], p, e): return tuple(tail)
    raise RuntimeError("no modulus")

class TallyField:
    def __init__(self, p, e):
        self.p, self.e, self.q = p, e, p ** e
        self._gtail = _royal_modulus(p, e); self._gfull = list(self._gtail) + [1]
    def _digits(self, a):
        out = []; [out.append(a % self.p) for _ in range(self.e)]; a //= self.p
        return out
    def _from_digits(self, coeffs):
        v = 0
        for c in reversed(coeffs): v = v * self.p + (c % self.p)
        return v
    def add(self, a, b):
        if self.e == 1: return (a + b) % self.p
        r, mul = 0, 1; p = self.p
        for _ in range(self.e): r += (((a % p) + (b % p)) % p) * mul; a //= p; b //= p; mul *= p
        return r
    def neg(self, a):
        if self.e == 1: return (-a) % self.p
        r, mul = 0, 1; p = self.p
        for _ in range(self.e): r += ((-(a % p)) % p) * mul; a //= p; mul *= p
        return r
    def sub(self, a, b): return self.add(a, self.neg(b))
    def mul(self, a, b):
        if self.e == 1: return (a * b) % self.p
        return self._from_digits(_poly_mod(_poly_mul(self._digits(a), self._digits(b), self.p), self._gfull, self.p))
    def inv(self, a):
        if a == 0: raise ZeroDivisionError
        if self.e == 1: return pow(a, self.p - 2, self.p)
        return self._from_digits(_poly_pow(self._digits(a), self.q - 2, self._gfull, self.p))

# ── tablet arithmetic ──
def _mat_mul(F, A, B):
    ra, ca, cb = len(A), len(A[0]), len(B[0]); out = [[0] * cb for _ in range(ra)]
    for i in range(ra):
        Ai, Oi = A[i], out[i]
        for t in range(ca):
            if Ai[t] == 0: continue
            Bt = B[t]
            for j in range(cb):
                if Bt[j]: Oi[j] = F.add(Oi[j], F.mul(Ai[t], Bt[j]))
    return out
def _mat_T(A): return [list(col) for col in zip(*A)]
def _row_reduce(F, M):
    R = [row[:] for row in M]; rows, cols = len(R), len(R[0]) if R else 0
    pivots, r = [], 0
    for c in range(cols):
        if r >= rows: break
        piv = next((i for i in range(r, rows) if R[i][c] != 0), None)
        if piv is None: continue
        R[r], R[piv] = R[piv], R[r]; inv = F.inv(R[r][c])
        R[r] = [F.mul(x, inv) for x in R[r]]
        for i in range(rows):
            if i != r and R[i][c] != 0:
                f = R[i][c]; R[i] = [F.sub(R[i][j], F.mul(f, R[r][j])) for j in range(cols)]
        pivots.append(c); r += 1
    return R, pivots
def _rank(F, M): return len(_row_reduce(F, M)[1]) if M and M[0] else 0
def _right_kernel(F, M):
    rows, cols = len(M), len(M[0]) if M else 0; R, pivots = _row_reduce(F, M)
    pset, free, basis = set(pivots), [c for c in range(cols) if c not in set(pivots)], []
    for f in free:
        v = [0] * cols; v[f] = 1
        for ri, pc in enumerate(pivots): v[pc] = F.neg(R[ri][f])
        basis.append(v)
    return basis
def _solve_linear(F, A, b):
    n = len(A[0]); aug = [A[i][:] + [b[i]] for i in range(len(A))]
    R, piv = _row_reduce(F, aug)
    if piv and piv[-1] == n: return None
    x = [0] * n
    for ri, pc in enumerate(piv):
        if pc < n: x[pc] = R[ri][n]
    return x
def _score(F, T, tokens):
    n = len(tokens); s = 0
    for i in range(n):
        if tokens[i] == 0: continue
        acc, Ti = 0, T[i]
        for j in range(n):
            if Ti[j]: acc = F.add(acc, F.mul(Ti[j], tokens[j]))
        s = F.add(s, F.mul(tokens[i], acc))
    return s
def _paired_form(F, T):
    n = len(T); return [[F.add(T[i][j], T[j][i]) for j in range(n)] for i in range(n)]
def _score_terms(F, T):
    n, two, out = len(T), 2 % F.p, {}
    for i in range(n):
        for j in range(i, n):
            c = T[i][i] if i == j else F.mul(two, T[i][j])
            if c: out[(i, j)] = c
    return out
def _token_order(n): return [(i, j) for i in range(n) for j in range(i, n)]

# ── tablet firing ──
def _random_config(F, n, rng): return [int.from_bytes(rng(8), "big") % F.q for _ in range(n)]
def _perfect_subspace(F, n, dim, rng):
    while True:
        rows = [_random_config(F, n, rng) for _ in range(dim)]
        if _rank(F, rows) == dim: return rows
def _fire_one(F, subspace, rng):
    n, dim = len(subspace[0]), len(subspace)
    order, idx_of = _token_order(n), {ij: t for t, ij in enumerate(_token_order(n))}
    nv = len(order); rows = []
    for a in range(dim):
        for b in range(a, dim):
            row = [0] * nv
            for (i, j) in order:
                coeff = F.mul(subspace[a][i], subspace[b][j])
                if i != j: coeff = F.add(coeff, F.mul(subspace[a][j], subspace[b][i]))
                if coeff: row[idx_of[(i, j)]] = F.add(row[idx_of[(i, j)]], coeff)
            rows.append(row)
    ker = _right_kernel(F, rows); vals = [0] * nv
    for bvec in ker:
        coeff = int.from_bytes(rng(8), "big") % F.q
        if coeff == 0: continue
        for t in range(nv):
            if bvec[t]: vals[t] = F.add(vals[t], F.mul(coeff, bvec[t]))
    T = [[0] * n for _ in range(n)]
    for t, (i, j) in enumerate(order): T[i][j] = vals[t]; T[j][i] = vals[t]
    return T
def _fire_tablets(F, n, m, rng):
    subspace = _perfect_subspace(F, n, m, rng)
    tablets = [_fire_one(F, subspace, rng) for _ in range(m)]
    _qa(F, tablets, subspace); return tablets, subspace
def _qa(F, tablets, subspace):
    n, m, dim = len(tablets[0]), len(tablets), len(subspace)
    assert _rank(F, subspace) == dim
    for T in tablets:
        P = _paired_form(F, T)
        for z in subspace: assert _score(F, T, z) == 0
        ZP = _mat_mul(F, _mat_mul(F, subspace, P), _mat_T(subspace))
        assert all(v == 0 for row in ZP for v in row)
    flat = [[T[i][j] for i in range(n) for j in range(i, n)] for T in tablets]
    assert _rank(F, flat) == m
    for T in tablets:
        r = _rank(F, _paired_form(F, T)); assert r >= n - 1
    paireds = [_paired_form(F, T) for T in tablets]
    assert sum(1 for P in paireds if _rank(F, P) == n) >= 2
    stacked = []; [stacked.extend(_paired_form(F, T)) for T in tablets]
    assert len(_right_kernel(F, stacked)) <= dim

def _derive_targets(F, tag, m):
    raw = hashlib.shake_256(_TALLY_DOMAIN + tag).digest(m * 8)
    return [int.from_bytes(raw[8*i:8*i+8], "big") % F.q for i in range(m)]
def _canonical_form(F, subspace):
    R, piv = _row_reduce(F, subspace); R = R[:len(piv)]
    free_cols = [c for c in range(len(subspace[0])) if c not in set(piv)]
    return R, piv, free_cols
def _stream_tallies(F, seed_bytes, count):
    raw = hashlib.shake_256(seed_bytes).digest(count * 8)
    return [int.from_bytes(raw[8*i:8*i+8], "big") % F.q for i in range(count)]
def _find_master_opening(F, tablets, subspace, target, nonce):
    n, m, dim = len(subspace[0]), len(tablets), len(subspace)
    Q, piv, free_cols = _canonical_form(F, subspace)
    paireds = [_paired_form(F, T) for T in tablets]
    for ctr in range(256):
        u = _stream_tallies(F, nonce + ctr.to_bytes(2, "big"), len(free_cols))
        w = [0] * n
        for j, fc in enumerate(free_cols): w[fc] = u[j]
        L, rhs = [[0] * dim for _ in range(m)], [0] * m
        for k in range(m):
            rhs[k] = F.sub(target[k], _score(F, tablets[k], w))
            wP = [0] * n
            for col in range(n):
                acc = 0
                for r in range(n):
                    if w[r] and paireds[k][r][col]: acc = F.add(acc, F.mul(w[r], paireds[k][r][col]))
                wP[col] = acc
            for i in range(dim):
                acc = 0
                for col in range(n):
                    if wP[col] and Q[i][col]: acc = F.add(acc, F.mul(wP[col], Q[i][col]))
                L[k][i] = acc
        if _rank(F, L) < dim: continue
        c = _solve_linear(F, L, rhs)
        if c is None: continue
        opening = w[:]
        for i in range(dim):
            if c[i]:
                for col in range(n):
                    if Q[i][col]: opening[col] = F.add(opening[col], F.mul(c[i], Q[i][col]))
        if all(_score(F, tablets[k], opening) == target[k] for k in range(m)): return opening, ctr
    raise RuntimeError("no opening")

def _word_bytes(F, words):
    wb = (F.q.bit_length() + 7) // 8
    return b"".join(int(x % F.q).to_bytes(wb, "big") for x in words)
def _det(F, A):
    n = len(A); A = [row[:] for row in A]; det = 1
    for c in range(n):
        piv = next((r for r in range(c, n) if A[r][c] != 0), None)
        if piv is None: return 0
        if piv != c: A[c], A[piv] = A[piv], A[c]; det = F.neg(det)
        det = F.mul(det, A[c][c]); inv = F.inv(A[c][c])
        for r in range(c + 1, n):
            if A[r][c]:
                f = F.mul(A[r][c], inv)
                A[r] = [F.sub(A[r][j], F.mul(f, A[c][j])) for j in range(n)]
    return det
def _plucker_norm(F, subspace):
    # Normalized Plücker embedding of the perfect-play subspace V: all C(n,m)
    # maximal minors of the m×n basis, scaled so the first non-zero coordinate
    # is 1.  Basis-independent — binds V itself (not just a basis) into the seal.
    n, m = len(subspace[0]), len(subspace)
    coords = [_det(F, [[subspace[r][c] for c in cols] for r in range(m)])
              for cols in _combinations(range(n), m)]
    fn = next(i for i, v in enumerate(coords) if v != 0)
    invf = F.inv(coords[fn])
    return [F.mul(v, invf) for v in coords]
def _royal_cipher(F, opening, target, plucker):
    spec = f"{F.p}^{F.e}".encode()
    return hashlib.sha256(_CIPHER_DOMAIN + _word_bytes(F, opening) + b"|" +
                          _word_bytes(F, target) + b"|" + _word_bytes(F, plucker) +
                          b"|" + spec).digest()
def _seal_scroll(payload, cipher):
    stream = hashlib.shake_256(_CIPHER_STREAM + cipher).digest(len(payload))
    return bytes(a ^ b for a, b in zip(payload, stream))

_B36 = "0123456789abcdefghijklmnopqrstuvwxyz"
def _to_base36(x):
    if x == 0: return "0"
    s = ""
    while x: x, r = divmod(x, 36); s = _B36[r] + s
    return s
def _pack(F, T, n):
    order, terms, val, mul = _token_order(n), _score_terms(F, T), 0, 1
    for ij in order: val += (terms.get(ij, 0) % F.q) * mul; mul *= F.q
    return _to_base36(val)

# ── generate (requires flag.txt only for sealing; output.txt is static) ──
if __name__ == "__main__":
    F = TallyField(3, RODS)
    pool = {"buf": b""}
    def rng(nbytes):
        while len(pool["buf"]) < nbytes: pool["buf"] += os.urandom(64)
        out, pool["buf"] = pool["buf"][:nbytes], pool["buf"][nbytes:]; return out
    while True:
        try: tablets, subspace = _fire_tablets(F, TOKENS, TABLETS, rng); break
        except AssertionError: continue
    target = _derive_targets(F, TARGET_TAG, TABLETS)
    opening, _ = _find_master_opening(F, tablets, subspace, target, ARCHIVE_NONCE)
    here = os.path.dirname(os.path.abspath(__file__))
    flag_path = os.path.join(here, "flag.txt")
    if os.path.exists(flag_path):
        with open(flag_path, "rb") as f: payload = f.read().strip()
    else:
        payload = b"flag_placeholder"
    plucker = _plucker_norm(F, subspace)
    cipher = _royal_cipher(F, opening, target, plucker)
    vault = _seal_scroll(payload, cipher)
    packed = [_pack(F, T, TOKENS) for T in tablets]
    with open(os.path.join(here, "output.txt"), "w") as out:
        out.write("# Cuneiform — SCTF 2026\n")
        out.write(f"p = 3\nw = {RODS}\nmodulus = {F._gfull}\nN = {TOKENS}\nM = {TABLETS}\n")
        out.write(f"directive = {TARGET_TAG.decode()!r}\nprofile = {target}\n")
        out.write(f"seal_nonce = {ARCHIVE_NONCE.hex()}\n")
        for k, blob in enumerate(packed): out.write(f"C{k} = {blob}\n")
        out.write(f"vault = {vault.hex()}\n")
