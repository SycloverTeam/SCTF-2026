#!/usr/bin/env python3
"""GateCrash — Instance Manager (Static Flag + Per-Team Isolation).

Each team gets a dedicated Anvil instance with its own Setup deployment.
All players share the same static flag from /flag.

Features:
  - Private Anvil per team (127.0.0.1 only)
  - Filtered RPC proxy per team (public-facing)
  - Token-based team verification via CTF platform API
  - Instance limiting by team id (one active instance per team)
  - Auto-cleanup on timeout (default 30 min)
  - Static flag from /flag file
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

# ── Constants ─────────────────────────────────────────────────────────

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
CHALLENGE_ID = "gatecrash"
FOUNDRY_BIN = os.environ.get("FOUNDRY_BIN", "/root/.foundry/bin")
INSTANCE_TIMEOUT = int(os.environ.get("INSTANCE_TIMEOUT", 1800))  # 30 min
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "127.0.0.1")
CTF_API_URL = os.environ.get(
    "CTF_API_URL",
    "https://adworld.xctf.org.cn/api/ct/public/jeopardy_race/race/token_info/",
)

# Port ranges
ANVIL_PORT_MIN = int(os.environ.get("ANVIL_PORT_MIN", "40000"))
ANVIL_PORT_MAX = int(os.environ.get("ANVIL_PORT_MAX", "40100"))

# Anvil deterministic accounts
ANVIL_ACCOUNTS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # deployer
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",  # admin
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",  # attacker
]

ALLOWED_RPC_METHODS = {
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockReceipts",
    "eth_getCode",
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_maxPriorityFeePerGas",
    "eth_newBlockFilter",
    "eth_newFilter",
    "eth_newPendingTransactionFilter",
    "eth_sendRawTransaction",
    "eth_subscribe",
    "eth_syncing",
    "eth_uninstallFilter",
    "eth_unsubscribe",
    "net_listening",
    "net_peerCount",
    "net_version",
    "web3_clientVersion",
}

# ── Shared State ──────────────────────────────────────────────────────

_instances: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_used_ports: set[int] = set()
_port_lock = threading.Lock()

# Team ID (participant id) → instance_id mapping (one instance per team)
_team_registry: dict[str, str] = {}
_team_lock = threading.Lock()


# ── Token Verification ──────────────────────────────────────────────────

def verify_token(token: str) -> tuple[bool, Optional[dict]]:
    """Verify token via CTF platform API. Returns (is_valid, team_info)."""
    try:
        url = f"{CTF_API_URL}?enroll_token={token}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("data") is not None:
                return True, data["data"]
            return False, None
    except Exception as e:
        print(f"[!] Token verification error: {e}", flush=True)
        return False, None

# ── Port Helpers ──────────────────────────────────────────────────────

def _find_free_port() -> int:
    with _port_lock:
        for port in range(ANVIL_PORT_MIN, ANVIL_PORT_MAX + 1):
            if port in _used_ports:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("", port))
                    _used_ports.add(port)
                    return port
                except OSError:
                    continue
    raise RuntimeError(f"No free ports in range {ANVIL_PORT_MIN}-{ANVIL_PORT_MAX}")


def _find_ephemeral_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def _foundry_env() -> dict:
    env = os.environ.copy()
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    return env


# ── RPC Proxy ─────────────────────────────────────────────────────────

def _rpc_error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _filter_rpc_payload(payload: Any) -> tuple:
    if isinstance(payload, list):
        responses = []
        blocked = False
        for item in payload:
            ok, response = _filter_rpc_payload(item)
            if not ok:
                blocked = True
                responses.append(response)
        return (not blocked, responses)

    if not isinstance(payload, dict):
        return False, _rpc_error(None, -32600, "Invalid Request")

    method = payload.get("method")
    if isinstance(method, str) and method in ALLOWED_RPC_METHODS:
        return True, None

    return False, _rpc_error(payload.get("id"), -32601, "RPC method is disabled")


def _start_rpc_proxy(listen_port: int, target_rpc: str) -> ThreadingHTTPServer:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    class RpcProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: Any) -> None:
            return

        def do_POST(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length)

            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(_rpc_error(None, -32700, "Parse error"))
                return

            allowed, blocked_response = _filter_rpc_payload(payload)
            if not allowed:
                self._send_json(blocked_response)
                return

            request = urllib.request.Request(
                target_rpc,
                data=raw_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with opener.open(request, timeout=30) as upstream:
                    body = upstream.read()
                    status = upstream.status
            except urllib.error.HTTPError as exc:
                body = exc.read()
                status = exc.code
            except Exception:
                self._send_json(_rpc_error(None, -32000, "Upstream RPC unavailable"))
                return

            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("0.0.0.0", listen_port), RpcProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ── Challenge Metadata ────────────────────────────────────────────────

def _load_challenge_meta() -> dict:
    path = CHALLENGES_DIR / CHALLENGE_ID / "challenge.json"
    with open(path) as f:
        return json.load(f)


# ── Compile & Deploy ──────────────────────────────────────────────────

def _compile_challenge() -> bool:
    challenge_dir = CHALLENGES_DIR / CHALLENGE_ID
    result = subprocess.run(
        [f"{FOUNDRY_BIN}/forge", "build", "--root", str(challenge_dir)],
        capture_output=True, text=True, env=_foundry_env(),
    )
    return result.returncode == 0


def _deploy_setup(rpc_url: str, value_eth: int, admin_address: str, attacker_address: str) -> Optional[str]:
    challenge_dir = CHALLENGES_DIR / CHALLENGE_ID
    deployer_key = ANVIL_ACCOUNTS[0]

    # Validate addresses before attempting deploy
    if not admin_address.startswith("0x") or len(admin_address) != 42:
        print(f"[deploy error] Invalid admin_address: {admin_address!r}", flush=True)
        return None
    if not attacker_address.startswith("0x") or len(attacker_address) != 42:
        print(f"[deploy error] Invalid attacker_address: {attacker_address!r}", flush=True)
        return None

    value_arg = ["--value", f"{value_eth}ether"] if value_eth > 0 else []

    # NOTE: --constructor-args uses num_args(1..) in clap, greedily consuming all
    # remaining arguments. The contract path MUST come BEFORE --constructor-args.
    # Arguments are human-readable values (space-separated), not ABI-encoded hex.
    cmd = [
        f"{FOUNDRY_BIN}/forge", "create",
        "--broadcast",
        "--root", str(challenge_dir),
        "--rpc-url", rpc_url,
        "--private-key", deployer_key,
        *value_arg,
        "src/Setup.sol:Setup",
        "--constructor-args", admin_address, attacker_address,
    ]
    print(f"[deploy] forge create ... src/Setup.sol:Setup --constructor-args {admin_address} {attacker_address}", flush=True)

    result = subprocess.run(cmd, capture_output=True, text=True, env=_foundry_env())

    if result.returncode != 0:
        print(f"[deploy error] returncode={result.returncode}", flush=True)
        print(f"[deploy stdout] {result.stdout}", flush=True)
        print(f"[deploy stderr] {result.stderr}", flush=True)
        return None

    for line in result.stdout.splitlines():
        if "Deployed to:" in line:
            addr = line.split("Deployed to:")[-1].strip()
            print(f"[deploy] Setup deployed to: {addr}", flush=True)
            return addr
        if "Deployed at:" in line:
            addr = line.split("Deployed at:")[-1].strip()
            print(f"[deploy] Setup deployed to: {addr}", flush=True)
            return addr

    # Also try parsing "Contract Address:" pattern
    for line in result.stdout.splitlines():
        if "Contract Address:" in line:
            addr = line.split("Contract Address:")[-1].strip()
            print(f"[deploy] Setup deployed to: {addr}", flush=True)
            return addr

    print(f"[deploy error] Could not parse address from stdout:", flush=True)
    print(f"[deploy stdout] {result.stdout}", flush=True)
    return None


# ── Flag ──────────────────────────────────────────────────────────────

def _read_flag() -> str:
    """Read the static flag from /flag file."""
    flag_file = Path("/flag")
    if flag_file.exists():
        flag = flag_file.read_text(encoding="utf-8").strip()
        if flag:
            return flag
    return "SCTF{placeholder_static_flag}"


# ── Cleanup ───────────────────────────────────────────────────────────

def _cleanup_instance(instance_id: str) -> None:
    with _lock:
        info = _instances.pop(instance_id, None)
    if not info:
        return

    # Remove from team registry
    team_id = info.get("team_id", "")
    if team_id:
        with _team_lock:
            if _team_registry.get(team_id) == instance_id:
                del _team_registry[team_id]

    proxy = info.get("proxy")
    if proxy:
        proxy.shutdown()
        proxy.server_close()

    proc = info.get("proc")
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    with _port_lock:
        _used_ports.discard(info.get("port", 0))


def _schedule_cleanup(instance_id: str, timeout: int) -> None:
    def _run() -> None:
        time.sleep(timeout)
        _cleanup_instance(instance_id)
        print(f"[cleanup] instance {instance_id} expired after {timeout}s", flush=True)

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ── Public API ────────────────────────────────────────────────────────

def create_instance(player_ip: str, token: str) -> dict:
    """Verify token and get or create an isolated instance for a team.

    One active instance per team (identified by participant id from API).
    If the team already has an active instance, return the existing one
    (e.g. after nc disconnect/reconnect).
    """
    token = token.strip()

    # Verify token via platform API
    is_valid, team_info = verify_token(token)
    if not is_valid or not team_info:
        raise RuntimeError("Invalid CTF token — please check your token and try again")

    team_id = team_info.get("id", "")
    if not team_id:
        raise RuntimeError("Token verification returned no team id")

    team_name = team_info.get("name", "unknown")
    race_name = team_info.get("race_name", "")
    is_active = team_info.get("is_active", False)

    if not is_active:
        raise RuntimeError(f"Team '{team_name}' is not active in this competition")

    # Check if this team already has an active instance
    with _team_lock:
        existing_id = _team_registry.get(team_id)
        if existing_id:
            with _lock:
                info = _instances.get(existing_id)
                if info:
                    # Return existing instance — player is reconnecting
                    return {
                        "instance_id": existing_id,
                        "rpc_url": info["rpc_url"],
                        "setup_address": info["setup_address"],
                        "player_address": info["player_address"],
                        "player_key": info["player_key"],
                        "expires_in": int(info["expires_at"] - time.time()),
                        "created_at": info["created_at"],
                        "recovered": True,
                        "team_name": info.get("team_name", "unknown"),
                        "race_name": info.get("race_name", ""),
                    }
                else:
                    # Stale registry entry, clean up
                    del _team_registry[team_id]

    meta = _load_challenge_meta()
    public_port = _find_free_port()
    anvil_port = _find_ephemeral_local_port()
    instance_id = str(uuid.uuid4())

    player_key = ANVIL_ACCOUNTS[2]
    addr_result = subprocess.run(
        [f"{FOUNDRY_BIN}/cast", "wallet", "address", "--private-key", player_key],
        capture_output=True, text=True, env=_foundry_env(),
    )
    if addr_result.returncode != 0:
        raise RuntimeError(f"cast wallet address (player) failed: {addr_result.stderr}")
    player_address = addr_result.stdout.strip()

    # Generate random admin key (not derivable from Anvil mnemonic)
    admin_key = "0x" + secrets.token_hex(32)
    admin_addr_result = subprocess.run(
        [f"{FOUNDRY_BIN}/cast", "wallet", "address", "--private-key", admin_key],
        capture_output=True, text=True, env=_foundry_env(),
    )
    if admin_addr_result.returncode != 0:
        raise RuntimeError(f"cast wallet address (admin) failed: {admin_addr_result.stderr}")
    admin_address = admin_addr_result.stdout.strip()
    print(f"[instance] Generated random admin owner: {admin_address}", flush=True)

    # Start private Anvil
    proc = subprocess.Popen(
        [
            f"{FOUNDRY_BIN}/anvil",
            "--host", "127.0.0.1",
            "--port", str(anvil_port),
            "--chain-id", "31337",
            "--accounts", "3",
            "--balance", "1000",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    internal_rpc = f"http://127.0.0.1:{anvil_port}"
    public_rpc = f"http://{PUBLIC_HOST}:{public_port}"

    if not _wait_for_port(anvil_port):
        proc.terminate()
        with _port_lock:
            _used_ports.discard(public_port)
        raise RuntimeError("Anvil failed to start")

    # Compile (idempotent if already compiled)
    if not _compile_challenge():
        proc.terminate()
        with _port_lock:
            _used_ports.discard(public_port)
        raise RuntimeError("Contract compilation failed")

    # Deploy Setup with random admin + attacker addresses
    setup_address = _deploy_setup(internal_rpc, meta.get("setup_value_eth", 10), admin_address, player_address)
    if not setup_address:
        proc.terminate()
        with _port_lock:
            _used_ports.discard(public_port)
        raise RuntimeError("Failed to deploy Setup contract")

    # Start filtered RPC proxy
    proxy = _start_rpc_proxy(public_port, internal_rpc)

    info = {
        "instance_id": instance_id,
        "player_ip": player_ip,
        "team_id": team_id,
        "team_name": team_name,
        "race_name": race_name,
        "token": token,
        "port": public_port,
        "anvil_port": anvil_port,
        "internal_rpc": internal_rpc,
        "rpc_url": public_rpc,
        "setup_address": setup_address,
        "player_address": player_address,
        "player_key": player_key,
        "proc": proc,
        "proxy": proxy,
        "created_at": time.time(),
        "expires_at": time.time() + INSTANCE_TIMEOUT,
    }

    with _lock:
        _instances[instance_id] = info

    with _team_lock:
        _team_registry[team_id] = instance_id

    _schedule_cleanup(instance_id, INSTANCE_TIMEOUT)

    return {
        "instance_id": instance_id,
        "rpc_url": public_rpc,
        "setup_address": setup_address,
        "player_address": player_address,
        "player_key": player_key,
        "expires_in": INSTANCE_TIMEOUT,
        "created_at": time.time(),
        "recovered": False,
        "team_name": team_name,
        "race_name": race_name,
    }


def check_solved(instance_id: str) -> dict:
    """Check if the player's Setup.isSolved() returns true."""
    with _lock:
        info = _instances.get(instance_id)

    if not info:
        return {"error": "Instance not found or expired"}

    result = subprocess.run(
        [
            f"{FOUNDRY_BIN}/cast", "call",
            info["setup_address"],
            "isSolved()(bool)",
            "--rpc-url", info["internal_rpc"],
        ],
        capture_output=True, text=True, env=_foundry_env(),
    )

    if result.returncode != 0:
        return {"error": "Failed to call isSolved()"}

    solved = result.stdout.strip().lower() == "true"

    if solved:
        return {
            "solved": True,
            "flag": _read_flag(),
            "instance_id": instance_id,
        }
    return {"solved": False}


def delete_instance(instance_id: str) -> bool:
    """Kill a player's instance."""
    _cleanup_instance(instance_id)
    return True
