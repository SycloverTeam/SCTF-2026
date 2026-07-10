#!/usr/bin/env python3
from __future__ import annotations

from hashlib import sha256
from random import Random, getrandbits

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, isPrime, long_to_bytes, sieve_base


HASH_WORD_BITS = 16
HASH_WORDS = 32
NONCE_BITS = HASH_WORD_BITS * HASH_WORDS
LEAK_BITS = HASH_WORD_BITS


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
