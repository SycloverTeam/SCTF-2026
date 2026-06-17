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
