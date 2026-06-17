import hashlib
import random
from pathlib import Path

P = 65537
M = 30
C = 14
W = 10
PLAIN_SEED = b"aGFjyHX1aWdadade"
RNG_SEED = 0xC0DEFACE
OUT = Path(__file__).resolve().parents[1] / "attachment" / "task1.txt"

SUPPORT = [1, 4, 5, 9, 13, 17, 20, 22, 26, 28]
SIGNS = [1, -1, 1, 1, -1, 1, -1, -1, 1, -1]


def build_instance():
    rng = random.Random(RNG_SEED)
    g = [[rng.randrange(P) for _ in range(C)] for _ in range(M)]
    pivot = SUPPORT[-1]
    pivot_sign = SIGNS[-1]

    for k in range(C):
        total = 0
        for idx, sign in zip(SUPPORT[:-1], SIGNS[:-1]):
            total = (total + sign * g[idx][k]) % P
        g[pivot][k] = (-total * pivot_sign) % P

    h = [0] * M
    for idx, sign in zip(SUPPORT, SIGNS):
        h[idx] = sign

    assert sum(1 for x in h if x) == W
    assert all(sum(h[i] * g[i][k] for i in range(M)) % P == 0 for k in range(C))
    return h, g


def stream_bytes(h, length: int) -> bytes:
    material = ("Curve_Link_Task1_Hard|P=65537|w=10|h=" + ",".join(map(str, h))).encode()
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(material + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def render_attachment(g, ciphertext: bytes) -> str:
    rows = ",\n".join("  " + repr(row) for row in g)
    return f"""Curve_Link / Task1

Let P = {P}. All vector and matrix operations are performed over GF(P).

There is a hidden vector h = (h_0, h_1, ..., h_29) with the following constraints:

    h is a ternary vector over {-1, 0, 1}.

The following side condition also holds:

    sum h_i^2 = 10 mod P

It satisfies the check equations:

    sum_{{i=0}}^{{{M - 1}}} h_i * G_{{i,k}} = 0 (mod P), for every k = 0, 1, ..., {C - 1}.

After recovering h, derive the keystream as:

    material = b"Curve_Link_Task1_Hard|P=65537|w=10|h=" + b",".join(str(h_i).encode() for h_i in h)
    stream = SHA256(material || uint32_be(0)) || SHA256(material || uint32_be(1)) || ...

The Task1 answer is:

    seed = ciphertext XOR stream[:len(ciphertext)]

This seed is the input material of Task2.

G =
[
{rows}
]

ciphertext_hex = {ciphertext.hex()}
"""


def main():
    h, g = build_instance()
    ciphertext = xor_bytes(PLAIN_SEED, stream_bytes(h, len(PLAIN_SEED)))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render_attachment(g, ciphertext), encoding="utf-8")
    print(f"Task1 attachment written to {OUT}")
    print(f"h = {h}")
    print(f"ciphertext_hex = {ciphertext.hex()}")
    print(f"seed = {PLAIN_SEED.decode()}")


if __name__ == "__main__":
    main()
