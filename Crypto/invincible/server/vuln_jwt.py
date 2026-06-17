#!/usr/bin/env python3
import base64
import binascii
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from vuln_hash import LEAK_BITS, NONCE_BITS, Q, create_nonce_oracle, nonce_int


CURVE = "brainpoolP512r1"
JWT_ALG = "BP512VULN"
JWT_TYP = "JWT"


def load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(f"{path} is not an EC private key")
        if not isinstance(key.curve, ec.BrainpoolP512R1):
            raise TypeError(f"{path} is not a BrainpoolP512R1 key")
        return key

    path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.BrainpoolP512R1())
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def build_nonce_material(payload: dict[str, Any], signing_input: bytes) -> bytes:
    uid = payload.get("uid", payload.get("id", ""))
    username = payload.get("username", payload.get("sub", ""))
    return f"{uid}:{username}:".encode("utf-8") + signing_input


class VulnerableJWTSigner:
    def __init__(self, key_path: Path):
        self.key_path = Path(key_path)
        self.key = load_or_create_key(self.key_path)
        self.private_scalar = self.key.private_numbers().private_value
        self.public_key = self.key.public_key()
        self.public_numbers = self.public_key.public_numbers()
        self.nonce_oracle = create_nonce_oracle()

    def public_info(self) -> dict[str, Any]:
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return {
            "alg": JWT_ALG,
            "curve": CURVE,
            "public_x_hex": f"{self.public_numbers.x:0128x}",
            "public_y_hex": f"{self.public_numbers.y:0128x}",
            "public_pem": pem,
            "signature_encoding": "DER-encoded ECDSA signature in JWT segment 3",
            "message_hash": "SHA-512(signing_input)",
        }

    def sign_input(self, signing_input: bytes, nonce_material: bytes) -> bytes:
        k = nonce_int(self.nonce_oracle, nonce_material)
        eph = ec.derive_private_key(k, ec.BrainpoolP512R1())
        r = eph.public_key().public_numbers().x % Q
        if r == 0:
            raise RuntimeError("zero r")

        h = int.from_bytes(hashlib.sha512(signing_input).digest(), "big") % Q
        s = (pow(k, -1, Q) * (h + r * self.private_scalar)) % Q
        if s == 0:
            raise RuntimeError("zero s")

        return encode_dss_signature(r, s)

    def make_token(self, payload: dict[str, Any]) -> str:
        header = {"alg": JWT_ALG, "typ": JWT_TYP}
        header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        nonce_material = build_nonce_material(payload, signing_input)
        sig_b64 = b64url_encode(self.sign_input(signing_input, nonce_material))
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def verify_token(self, token: str) -> dict[str, Any] | None:
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
        except ValueError:
            return None

        try:
            header = json.loads(b64url_decode(header_b64))
        except Exception:
            return None

        if not isinstance(header, dict):
            return None
        if header.get("alg") != JWT_ALG or header.get("typ") != JWT_TYP:
            return None

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            signature = b64url_decode(sig_b64)
            self.public_key.verify(signature, signing_input, ec.ECDSA(hashes.SHA512()))
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            return None

        try:
            payload = json.loads(b64url_decode(payload_b64))
        except Exception:
            return None

        if not isinstance(payload, dict):
            return None
        if "nbf" in payload and int(time.time()) < int(payload["nbf"]):
            return None
        if "exp" in payload and int(time.time()) > int(payload["exp"]):
            return None
        return payload
