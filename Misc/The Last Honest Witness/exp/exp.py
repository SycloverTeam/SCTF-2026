#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
from math import isqrt
from pathlib import Path

from Crypto.Hash import keccak

EXTERNAL_NULLIFIER = 48879
LEAF_COUNT = 32
FR_MODULUS = 760009694642386684565581461392043895505912502559714131532944907541093903
FR_EXPONENT = 3
FR_DELTA = 1337
FR_C1 = 453597385863057272648915757216738828698620960961179478921819470254014847
FR_C2 = 453597385865721903738147200739079200525533155295038017694987515419712854
ECC_BOUND = 1 << 20
ECC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ECC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ECC_G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)
ECC_PUB = (
    58815339488302044413775644787852249409224615099495920880759980194063649848583,
    98550888334717328604002147137887649681647570376424892468560957640988111280493,
)
ECC_MESSAGE_HASH = int("99e1c9445f2a4aaed1cb39c5f061cff3410bf6faa5828abcafe330974301c838", 16)
COLLISION_BOUND = 1 << 32
COLLISION_MASK = (1 << 40) - 1
ROOT_DIR = Path(__file__).resolve().parents[1]
ZK_HELPER = ROOT_DIR / "ctf/challenges/06_last_honest_witness/handout/poseidon_helper.js"
ZK_WASM = ROOT_DIR / "ctf/challenges/06_last_honest_witness/handout/zk/LastHonestWitness.wasm"
ZK_ZKEY = ROOT_DIR / "ctf/challenges/06_last_honest_witness/handout/zk/LastHonestWitness_final.zkey"


def fermat_factor(n: int) -> tuple[int, int]:
    a = isqrt(n)
    if a * a < n:
        a += 1
    while True:
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1


def poly_trim(poly: list[int]) -> list[int]:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_divmod(a: list[int], b: list[int], modulus: int) -> tuple[list[int], list[int]]:
    a = [x % modulus for x in a]
    b = poly_trim([x % modulus for x in b])
    if b == [0]:
        raise ZeroDivisionError
    q = [0] * max(1, (len(a) - len(b) + 1))
    inv_lc = pow(b[-1], -1, modulus)
    while len(a) >= len(b) and a != [0]:
        coeff = a[-1] * inv_lc % modulus
        shift = len(a) - len(b)
        q[shift] = coeff
        for i, value in enumerate(b):
            a[shift + i] = (a[shift + i] - coeff * value) % modulus
        poly_trim(a)
    return poly_trim(q), poly_trim(a)


def poly_gcd(a: list[int], b: list[int], modulus: int) -> list[int]:
    a = poly_trim([x % modulus for x in a])
    b = poly_trim([x % modulus for x in b])
    while b != [0]:
        _, r = poly_divmod(a, b, modulus)
        a, b = b, r
    inv_lc = pow(a[-1], -1, modulus)
    return [(x * inv_lc) % modulus for x in a]


def franklin_reiter() -> int:
    d = FR_DELTA
    f = [(-FR_C1) % FR_MODULUS, 0, 0, 1]
    g = [
        (d**3 - FR_C2) % FR_MODULUS,
        (3 * d * d) % FR_MODULUS,
        (3 * d) % FR_MODULUS,
        1,
    ]
    gcd = poly_gcd(f, g, FR_MODULUS)
    if len(gcd) != 2:
        raise RuntimeError("unexpected Franklin-Reiter gcd degree")
    return (-gcd[0]) % FR_MODULUS


def ec_add(p: tuple[int, int] | None, q: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % ECC_P == 0:
        return None
    if p == q:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, ECC_P) % ECC_P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % ECC_P, -1, ECC_P) % ECC_P
    x3 = (slope * slope - x1 - x2) % ECC_P
    y3 = (slope * (x1 - x3) - y1) % ECC_P
    return x3, y3


def ec_neg(p: tuple[int, int] | None) -> tuple[int, int] | None:
    if p is None:
        return None
    return p[0], (-p[1]) % ECC_P


def ec_mul(k: int, p: tuple[int, int] = ECC_G) -> tuple[int, int] | None:
    result = None
    addend = p
    while k:
        if k & 1:
            result = ec_add(result, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return result


def ecc_discrete_log() -> int:
    m = isqrt(ECC_BOUND) + 1
    table: dict[tuple[int, int], int] = {}
    current = None
    for j in range(m):
        if current is not None:
            table[current] = j
        current = ec_add(current, ECC_G)

    step = ec_neg(ec_mul(m))
    gamma: tuple[int, int] | None = ECC_PUB
    for i in range(m + 1):
        if gamma in table:
            candidate = i * m + table[gamma]
            if candidate < ECC_BOUND and ec_mul(candidate) == ECC_PUB:
                return candidate
        gamma = ec_add(gamma, step)
    raise RuntimeError("ECC discrete log not found")


def sign_ecc_fragment(private_key: int) -> tuple[int, str, str]:
    k = 424242
    r_point = ec_mul(k)
    if r_point is None:
        raise RuntimeError("invalid ECDSA nonce")
    r = r_point[0] % ECC_N
    s = pow(k, -1, ECC_N) * (ECC_MESSAGE_HASH + r * private_key) % ECC_N
    recovery_id = r_point[1] & 1
    if s > ECC_N // 2:
        s = ECC_N - s
        recovery_id ^= 1
    return 27 + recovery_id, f"0x{r:064x}", f"0x{s:064x}"


def collision_digest(value: int) -> int:
    return h_int(tag("LAST_HONEST_WITNESS_PAGE_C"), u256(value)) & COLLISION_MASK


def find_collision() -> tuple[int, int]:
    seen: dict[int, int] = {}
    for i in range(COLLISION_BOUND):
        digest = collision_digest(i)
        if digest in seen:
            return seen[digest], i
        seen[digest] = i
    raise RuntimeError("collision not found")


def run(cmd: list[str]) -> str:
    env = os.environ.copy()
    no_proxy = {"127.0.0.1", "localhost"}
    for key in ("NO_PROXY", "no_proxy"):
        no_proxy.update(x.strip() for x in env.get(key, "").split(",") if x.strip())
    rpc_host = urllib.parse.urlparse(env.get("RPC", "")).hostname
    if rpc_host:
        no_proxy.add(rpc_host)
    env["NO_PROXY"] = ",".join(sorted(no_proxy))
    env["no_proxy"] = env["NO_PROXY"]
    result = subprocess.run(cmd, check=True, text=True, capture_output=True, env=env)
    return result.stdout.strip()


def rpc_call(rpc: str, method: str, params: list) -> object:
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode()
    request = urllib.request.Request(
        rpc,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.loads(response.read())
    if "error" in body:
        raise RuntimeError(body["error"])
    return body["result"]


def storage_uint(rpc: str, address: str, slot: int) -> int:
    value = rpc_call(rpc, "eth_getStorageAt", [address, hex(slot), "latest"])
    return int(value, 16)


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def tag(name: str) -> bytes:
    return keccak256(name.encode())


def u256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def h_int(*parts: bytes) -> int:
    return int.from_bytes(keccak256(b"".join(parts)), "big")


def generate_zk_proof(p: int, q: int, m: int, expected_root: int) -> tuple[list[str], list[list[str]], list[str], list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        input_json = Path(tmp) / "input.json"
        proof_json = Path(tmp) / "proof.json"
        public_json = Path(tmp) / "public.json"
        run(["node", str(ZK_HELPER), str(p), str(q), str(m), "--input", str(input_json)])

        with input_json.open() as f:
            input_data = json.load(f)
        if int(input_data["merkleRoot"]) != expected_root:
            raise RuntimeError("computed Poseidon Merkle root does not match deployment event")

        run([
            "npx",
            "snarkjs",
            "groth16",
            "fullprove",
            str(input_json),
            str(ZK_WASM),
            str(ZK_ZKEY),
            str(proof_json),
            str(public_json),
        ])

        with proof_json.open() as f:
            proof = json.load(f)
        with public_json.open() as f:
            public_signals = json.load(f)

    proof_a = [proof["pi_a"][0], proof["pi_a"][1]]
    proof_b = [
        [proof["pi_b"][0][1], proof["pi_b"][0][0]],
        [proof["pi_b"][1][1], proof["pi_b"][1][0]],
    ]
    proof_c = [proof["pi_c"][0], proof["pi_c"][1]]
    return proof_a, proof_b, proof_c, public_signals


def deployment_root(rpc: str, setup: str) -> int:
    topic0 = "0x" + keccak256(b"WitnessRoot(bytes32)").hex()
    logs = rpc_call(rpc, "eth_getLogs", [{
        "address": setup,
        "fromBlock": "0x0",
        "toBlock": "latest",
        "topics": [topic0],
    }])
    if not logs:
        raise RuntimeError("WitnessRoot event not found")
    return int(logs[-1]["topics"][1], 16)


def main() -> None:
    rpc = os.environ["RPC"]
    private_key = os.environ["PK"]
    setup = os.environ["SETUP"]

    n = storage_uint(rpc, setup, 1)
    e = storage_uint(rpc, setup, 2)
    c = storage_uint(rpc, setup, 3)
    merkle_root = deployment_root(rpc, setup)

    p, q = fermat_factor(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    proof_a, proof_b, proof_c, public_signals = generate_zk_proof(p, q, m, merkle_root)

    fr_plaintext = franklin_reiter()
    ecc_private_key = ecc_discrete_log()
    ecc_v, ecc_r, ecc_s = sign_ecc_fragment(ecc_private_key)
    collision_a, collision_b = find_collision()

    challenge = run(["cast", "call", setup, "challenge()(address)", "--rpc-url", rpc])
    run([
        "cast",
        "send",
        challenge,
        "claim(uint256[2],uint256[2][2],uint256[2],uint256[5],uint256,uint8,bytes32,bytes32,uint256,uint256)",
        "[" + ",".join(proof_a) + "]",
        "[[" + ",".join(proof_b[0]) + "],[" + ",".join(proof_b[1]) + "]]",
        "[" + ",".join(proof_c) + "]",
        "[" + ",".join(public_signals) + "]",
        str(fr_plaintext),
        str(ecc_v),
        ecc_r,
        ecc_s,
        str(collision_a),
        str(collision_b),
        "--rpc-url",
        rpc,
        "--private-key",
        private_key,
    ])
    print(run(["cast", "call", setup, "isSolved()(bool)", "--rpc-url", rpc]))


if __name__ == "__main__":
    main()
