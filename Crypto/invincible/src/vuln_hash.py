#!/usr/bin/env python3
from __future__ import annotations

from foxhash import FoxHash, LEAK_BITS, NONCE_BITS


Q = int(
    "00aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308"
    "70553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
    16,
)


def create_nonce_oracle() -> FoxHash:
    return FoxHash()
def nonce_int(oracle: FoxHash, payload: bytes) -> int:
    k = oracle.hash(payload) % Q
    return k or 1
