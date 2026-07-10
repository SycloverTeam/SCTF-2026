#!/usr/bin/env python3
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = ROOT / "server"
HOST = "127.0.0.1"


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


def wait_until_ready(server: subprocess.Popen[str], base_url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        if server.poll() is not None:
            output = ""
            if server.stdout is not None:
                output = server.stdout.read()
            raise RuntimeError(f"server exited early: {output.strip() or 'no output'}")
        try:
            with urllib.request.urlopen(f"{base_url}/ping", timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
    output = ""
    if server.stdout is not None:
        output = server.stdout.read()
    raise RuntimeError(
        f"server did not become ready: {last_error}; server output: {output.strip() or 'no output'}"
    )


def main():
    with tempfile.TemporaryDirectory(prefix="jwt-demo-validate-") as tmp:
        tmpdir = Path(tmp)
        port = reserve_port()
        base_url = f"http://{HOST}:{port}"
        env = dict(os.environ)
        env["FLAG"] = "SCTF{t1hinK_mark1_You’ll outlast every fragile, insignificant being on this planet!}"
        env["DEMO_DB_PATH"] = str(tmpdir / "app.db")
        env["DEMO_JWT_KEY_FILE"] = str(tmpdir / "jwt_signer_key.pem")

        server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "main:app",
                "--host",
                HOST,
                "--port",
                str(port),
            ],
            cwd=str(SERVER_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_until_ready(server, base_url)
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "exp.py"),
                    "--base-url",
                    base_url,
                    "--count",
                    "36",
                    "--local-key",
                    env["DEMO_JWT_KEY_FILE"],
                    "--expect-flag",
                    env["FLAG"],
                ],
                cwd=str(ROOT),
                env=env,
                check=True,
            )
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)


if __name__ == "__main__":
    main()
