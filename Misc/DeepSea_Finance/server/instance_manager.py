"""
Instance Manager for DeepSea Finance CTF.

Manages per-team Anvil instances with:
  - Token-to-instance mapping (one instance per team)
  - RPC proxy filtering (block anvil_*, evm_*, debug_*, hardhat_*)
  - 30-minute auto-cleanup
  - Cancun hardfork + disabled code-size-limit
"""

import json
import os
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
import uuid

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
FOUNDRY_BIN = os.environ.get("FOUNDRY_BIN", "/usr/local/bin")
INSTANCE_TIMEOUT = int(os.environ.get("INSTANCE_TIMEOUT", "1800"))  # 30 min

# Public hostname/IP shown to players in the RPC URL
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "127.0.0.1")

# Port range for player-facing RPC proxies
ANVIL_PORT_MIN = int(os.environ.get("ANVIL_PORT_MIN", "6001"))
ANVIL_PORT_MAX = int(os.environ.get("ANVIL_PORT_MAX", "6050"))

# Anvil funded account private keys (default anvil accounts)
ANVIL_ACCOUNTS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
]

# Instance storage
_instances: dict[str, dict] = {}        # instance_id -> info
_token_instances: dict[str, str] = {}   # token -> instance_id
_lock = threading.Lock()
_used_ports: set[int] = set()
_port_lock = threading.Lock()

# RPC methods allowed through the proxy
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
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_getUncleByBlockHashAndIndex",
    "eth_getUncleByBlockNumberAndIndex",
    "eth_getUncleCountByBlockHash",
    "eth_getUncleCountByBlockNumber",
    "eth_maxPriorityFeePerGas",
    "eth_newBlockFilter",
    "eth_newFilter",
    "eth_newPendingTransactionFilter",
    "eth_protocolVersion",
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


# ── Helpers ──────────────────────────────────────────────────────────────────

def _foundry_env() -> dict:
    env = os.environ.copy()
    no_proxy_hosts = "127.0.0.1,localhost"
    env["NO_PROXY"] = no_proxy_hosts
    env["no_proxy"] = no_proxy_hosts
    env["http_proxy"] = ""
    env["https_proxy"] = ""
    env["HTTP_PROXY"] = ""
    env["HTTPS_PROXY"] = ""
    env["all_proxy"] = ""
    env["ALL_PROXY"] = ""
    return env


def _find_free_port() -> int:
    """Pick a free port from the configured public port range."""
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


def _find_ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


# ── RPC Proxy ────────────────────────────────────────────────────────────────

def _rpc_error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _method_allowed(method: object) -> bool:
    return isinstance(method, str) and method in ALLOWED_RPC_METHODS


def _filter_rpc_payload(payload: object) -> tuple[bool, object]:
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

    if _method_allowed(payload.get("method")):
        return True, None

    return False, _rpc_error(payload.get("id"), -32601, "RPC method is disabled")


def _start_rpc_proxy(listen_port: int, target_rpc: str) -> ThreadingHTTPServer:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    class RpcProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args) -> None:
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

        def _send_json(self, payload: object) -> None:
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


# ── Challenge helpers ────────────────────────────────────────────────────────

def _load_challenge_meta(challenge_id: str) -> dict:
    path = CHALLENGES_DIR / challenge_id / "challenge.json"
    with open(path) as f:
        return json.load(f)


def _deploy_setup(
    challenge_id: str, rpc_url: str, deployer_key: str, player_address: str
) -> Optional[str]:
    """Deploy Setup.sol and return its address."""
    challenge_dir = CHALLENGES_DIR / challenge_id

    cmd = [
        f"{FOUNDRY_BIN}/forge", "create",
        "--broadcast",
        "--root", str(challenge_dir),
        "--rpc-url", rpc_url,
        "--private-key", deployer_key,
        "src/Setup.sol:Setup",
        "--constructor-args", player_address,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, env=_foundry_env())
    if result.returncode != 0:
        print(f"[deploy error] {result.stderr}", flush=True)
        return None

    for line in result.stdout.splitlines():
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()
    return None


# ── Instance lifecycle ──────────────────────────────────────────────────────

def _cleanup_instance(instance_id: str):
    with _lock:
        info = _instances.pop(instance_id, None)
        if info and info.get("token") in _token_instances:
            del _token_instances[info["token"]]

    if info:
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

        print(f"[cleanup] instance {instance_id[:12]} destroyed", flush=True)


def _schedule_cleanup(instance_id: str, timeout: int):
    def _run():
        time.sleep(timeout)
        _cleanup_instance(instance_id)

    t = threading.Thread(target=_run, daemon=True)
    t.start()


# ── Public API ──────────────────────────────────────────────────────────────

def create_instance(challenge_id: str, token: str) -> dict:
    """Start an Anvil instance, deploy challenge, return connection info."""
    meta = _load_challenge_meta(challenge_id)
    flag = meta.get("flag", "flag{placeholder}")

    # Check if token already has an instance
    with _lock:
        existing_id = _token_instances.get(token)
        if existing_id and existing_id in _instances:
            existing = _instances[existing_id]
            if existing["expires_at"] > time.time():
                return {
                    "instance_id": existing_id,
                    "challenge_id": challenge_id,
                    "rpc_url": existing["rpc_url"],
                    "setup_address": existing["setup_address"],
                    "player_address": existing["player_address"],
                    "player_key": existing["player_key"],
                    "expires_in": int(existing["expires_at"] - time.time()),
                }
            else:
                _cleanup_instance(existing_id)

    public_port = _find_free_port()
    anvil_port = _find_ephemeral_port()
    instance_id = str(uuid.uuid4())

    deployer_key = ANVIL_ACCOUNTS[0]
    player_key = ANVIL_ACCOUNTS[1]

    # Derive player address
    addr_result = subprocess.run(
        [f"{FOUNDRY_BIN}/cast", "wallet", "address", "--private-key", player_key],
        capture_output=True, text=True, env=_foundry_env(),
    )
    player_address = addr_result.stdout.strip()

    # Start Anvil with Cancun hardfork + disabled code-size-limit
    proc = subprocess.Popen(
        [
            f"{FOUNDRY_BIN}/anvil",
            "--host", "127.0.0.1",
            "--port", str(anvil_port),
            "--hardfork", "cancun",
            "--chain-id", "31337",
            "--accounts", "10",
            "--balance", "10000",
            "--disable-code-size-limit",
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

    # Deploy Setup contract
    setup_address = _deploy_setup(challenge_id, internal_rpc, deployer_key, player_address)

    if not setup_address:
        proc.terminate()
        with _port_lock:
            _used_ports.discard(public_port)
        raise RuntimeError("Failed to deploy Setup contract")

    # Start RPC proxy for player access
    proxy = _start_rpc_proxy(public_port, internal_rpc)

    now = time.time()
    info = {
        "instance_id": instance_id,
        "challenge_id": challenge_id,
        "token": token,
        "flag": flag,
        "port": public_port,
        "anvil_port": anvil_port,
        "internal_rpc": internal_rpc,
        "rpc_url": public_rpc,
        "setup_address": setup_address,
        "player_address": player_address,
        "player_key": player_key,
        "proc": proc,
        "proxy": proxy,
        "created_at": now,
        "expires_at": now + INSTANCE_TIMEOUT,
    }

    with _lock:
        _instances[instance_id] = info
        _token_instances[token] = instance_id

    _schedule_cleanup(instance_id, INSTANCE_TIMEOUT)

    print(
        f"[+] Instance {instance_id[:12]} launched on rpc={public_port}",
        flush=True,
    )

    return {
        "instance_id": instance_id,
        "challenge_id": challenge_id,
        "rpc_url": public_rpc,
        "setup_address": setup_address,
        "player_address": player_address,
        "player_key": player_key,
        "expires_in": INSTANCE_TIMEOUT,
    }


def check_solved(instance_id: str) -> dict:
    """Check if isSolved() returns true, return flag if yes."""
    with _lock:
        info = _instances.get(instance_id)

    if not info:
        return {"error": "Instance not found or expired"}

    if info["expires_at"] < time.time():
        return {"error": "Instance has expired"}

    result = subprocess.run(
        [
            f"{FOUNDRY_BIN}/cast", "call",
            info["setup_address"],
            "isSolved()(bool)",
            "--rpc-url", info["internal_rpc"],
        ],
        capture_output=True,
        text=True,
        env=_foundry_env(),
    )

    if result.returncode != 0:
        return {"error": f"Failed to call isSolved(): {result.stderr.strip()}"}

    solved = result.stdout.strip().lower() == "true"

    if solved:
        return {
            "solved": True,
            "flag": info.get("flag", "flag{placeholder}"),
            "challenge_id": info["challenge_id"],
        }
    return {"solved": False}


def get_instance_by_token(token: str) -> Optional[str]:
    """Return instance_id for a given token, or None."""
    with _lock:
        instance_id = _token_instances.get(token)
        if instance_id and instance_id in _instances:
            inst = _instances[instance_id]
            if inst["expires_at"] > time.time():
                return instance_id
    return None


def get_instance_info(instance_id: str) -> Optional[dict]:
    """Return summary info for an instance."""
    with _lock:
        info = _instances.get(instance_id)
    if not info:
        return None
    return {
        "instance_id": instance_id,
        "rpc_url": info["rpc_url"],
        "setup_address": info["setup_address"],
        "player_address": info["player_address"],
        "player_key": info["player_key"],
        "expires_in": max(0, int(info["expires_at"] - time.time())),
    }


def delete_instance(instance_id: str) -> bool:
    _cleanup_instance(instance_id)
    return True
