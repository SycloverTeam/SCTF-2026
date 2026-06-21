import os
import subprocess
import socket
import time
import threading
import json
import uuid
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
FOUNDRY_BIN = os.environ.get("FOUNDRY_BIN", "/root/.foundry/bin")
INSTANCE_TIMEOUT = int(os.environ.get("INSTANCE_TIMEOUT", 1800))  # 30 min default
STATIC_FLAG = "SCTF{SYC_!ntern_Ray}"

# Public hostname/IP shown to players in the RPC URL.
# Set to the server's public IP or hostname for remote deployments.
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "127.0.0.1")

# Port range reserved for player-facing RPC proxies (must be exposed in docker-compose).
# The real Anvil nodes bind to 127.0.0.1 on private ephemeral ports.
ANVIL_PORT_MIN = int(os.environ.get("ANVIL_PORT_MIN", 20000))
ANVIL_PORT_MAX = int(os.environ.get("ANVIL_PORT_MAX", 20200))

# Anvil funded account private keys (default anvil accounts)
ANVIL_ACCOUNTS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
]

_instances: dict[str, dict] = {}
_team_instances: dict[tuple[str, str], str] = {}
_lock = threading.Lock()
_used_ports: set[int] = set()
_port_lock = threading.Lock()

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


def _foundry_env() -> dict:
    env = os.environ.copy()
    no_proxy_hosts = "127.0.0.1,localhost"
    env["NO_PROXY"] = no_proxy_hosts
    env["no_proxy"] = no_proxy_hosts
    return env


def _find_free_port() -> int:
    """Pick a free port from the configured Anvil port range."""
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
    raise RuntimeError(
        f"No free ports available in range {ANVIL_PORT_MIN}-{ANVIL_PORT_MAX}"
    )


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


def _rpc_error(request_id, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


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


def _load_challenge_meta(challenge_id: str) -> dict:
    path = CHALLENGES_DIR / challenge_id / "challenge.json"
    with open(path) as f:
        return json.load(f)


def _compile_challenge(challenge_id: str) -> bool:
    """Compile the challenge contracts with forge."""
    challenge_dir = CHALLENGES_DIR / challenge_id
    result = subprocess.run(
        [f"{FOUNDRY_BIN}/forge", "build", "--root", str(challenge_dir)],
        capture_output=True,
        text=True,
        env=_foundry_env(),
    )
    return result.returncode == 0


def _deploy_setup(challenge_id: str, rpc_url: str, deployer_key: str, player_address: str, value_eth: int) -> Optional[str]:
    """Deploy Setup.sol and return its address."""
    challenge_dir = CHALLENGES_DIR / challenge_id
    src_dir = challenge_dir / "src"

    # Find Setup.sol
    setup_sol = src_dir / "Setup.sol"
    if not setup_sol.exists():
        return None

    constructor_args = []

    value_arg = []
    if value_eth > 0:
        value_arg = ["--value", f"{value_eth}ether"]

    cmd = [
        f"{FOUNDRY_BIN}/forge", "create",
        "--broadcast",
        "--root", str(challenge_dir),
        "--rpc-url", rpc_url,
        "--private-key", deployer_key,
        *value_arg,
        "src/Setup.sol:Setup",
        *constructor_args,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, env=_foundry_env())
    if result.returncode != 0:
        print(f"[deploy error] {result.stderr}")
        return None

    # Parse "Deployed to: 0x..." from output
    for line in result.stdout.splitlines():
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()
    return None


def _generate_flag(instance_id: str) -> str:
    return STATIC_FLAG


def _cleanup_instance(instance_id: str):
    with _lock:
        info = _instances.pop(instance_id, None)
        if info:
            team_id = info.get("team_id")
            challenge_id = info.get("challenge_id")
            if team_id and challenge_id:
                team_key = (challenge_id, team_id)
                if _team_instances.get(team_key) == instance_id:
                    _team_instances.pop(team_key, None)
    if info:
        proxy: ThreadingHTTPServer | None = info.get("proxy")
        if proxy:
            proxy.shutdown()
            proxy.server_close()

        proc: subprocess.Popen = info.get("proc")
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        # Release the port back to the pool
        with _port_lock:
            _used_ports.discard(info.get("port", 0))


def _schedule_cleanup(instance_id: str, timeout: int):
    def _run():
        time.sleep(timeout)
        _cleanup_instance(instance_id)
        print(f"[cleanup] instance {instance_id} expired after {timeout}s")

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def _release_team_reservation(challenge_id: str, team_id: str, instance_id: str) -> None:
    with _lock:
        team_key = (challenge_id, team_id)
        if _team_instances.get(team_key) == instance_id:
            _team_instances.pop(team_key, None)


def create_instance(challenge_id: str, team_id: str, team_info: Optional[dict] = None) -> dict:
    """Start an Anvil instance, deploy challenge, return connection info."""
    meta = _load_challenge_meta(challenge_id)
    instance_id = str(uuid.uuid4())
    team_info = team_info or {}
    team_key = (challenge_id, team_id)

    with _lock:
        existing_id = _team_instances.get(team_key)
        if existing_id:
            raise RuntimeError(
                f"Team already has an active instance for {challenge_id}: "
                f"{existing_id[:8]}..."
            )
        _team_instances[team_key] = instance_id

    public_port: Optional[int] = None
    proc: Optional[subprocess.Popen] = None
    proxy: Optional[ThreadingHTTPServer] = None

    try:
        public_port = _find_free_port()
        anvil_port = _find_ephemeral_local_port()

        deployer_key = ANVIL_ACCOUNTS[0]
        player_key = ANVIL_ACCOUNTS[1]

        # Derive player address from key
        addr_result = subprocess.run(
            [f"{FOUNDRY_BIN}/cast", "wallet", "address", "--private-key", player_key],
            capture_output=True, text=True,
            env=_foundry_env(),
        )
        player_address = addr_result.stdout.strip()
        if addr_result.returncode != 0 or not player_address:
            raise RuntimeError("Failed to derive player address")

        # Anvil stays private. Players only access the filtered RPC proxy.
        proc = subprocess.Popen(
            [
                f"{FOUNDRY_BIN}/anvil",
                "--host", "127.0.0.1",
                "--port", str(anvil_port),
                "--chain-id", "31337",
                "--accounts", "10",
                "--balance", "10000",
                "--silent",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Internal URL (used for forge deploy, always localhost)
        internal_rpc = f"http://127.0.0.1:{anvil_port}"
        # Player-facing URL (uses PUBLIC_HOST for remote deployments)
        public_rpc = f"http://{PUBLIC_HOST}:{public_port}"

        if not _wait_for_port(anvil_port):
            raise RuntimeError("Anvil failed to start")

        # Deploy Setup contract using internal URL
        setup_address = _deploy_setup(
            challenge_id,
            internal_rpc,
            deployer_key,
            player_address,
            meta.get("setup_value_eth", 0),
        )

        if not setup_address:
            raise RuntimeError("Failed to deploy Setup contract")

        proxy = _start_rpc_proxy(public_port, internal_rpc)

        info = {
            "instance_id": instance_id,
            "challenge_id": challenge_id,
            "team_id": team_id,
            "team_name": team_info.get("team_name")
            or team_info.get("name")
            or team_info.get("nickname")
            or team_id,
            "team_info": team_info,
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

        _schedule_cleanup(instance_id, INSTANCE_TIMEOUT)

        return {
            "instance_id": instance_id,
            "challenge_id": challenge_id,
            "team_id": team_id,
            "team_name": info["team_name"],
            "rpc_url": public_rpc,
            "setup_address": setup_address,
            "player_address": player_address,
            "player_key": player_key,
            "expires_in": INSTANCE_TIMEOUT,
        }
    except Exception:
        if proxy:
            proxy.shutdown()
            proxy.server_close()
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if public_port is not None:
            with _port_lock:
                _used_ports.discard(public_port)
        _release_team_reservation(challenge_id, team_id, instance_id)
        raise


def check_solved(instance_id: str) -> dict:
    """Check if isSolved() returns true, return flag if yes."""
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
        capture_output=True,
        text=True,
        env=_foundry_env(),
    )

    if result.returncode != 0:
        return {"error": "Failed to call isSolved()"}

    solved = result.stdout.strip().lower() == "true"

    if solved:
        return {
            "solved": True,
            "flag": _generate_flag(instance_id),
            "challenge_id": info["challenge_id"],
        }
    return {"solved": False}


def _public_instance_info(info: dict) -> dict:
    return {
        "instance_id": info["instance_id"],
        "challenge_id": info["challenge_id"],
        "team_id": info.get("team_id"),
        "team_name": info.get("team_name"),
        "rpc_url": info["rpc_url"],
        "created_at": info["created_at"],
        "expires_at": info["expires_at"],
    }


def get_instance(instance_id: str) -> Optional[dict]:
    with _lock:
        info = _instances.get(instance_id)
        return _public_instance_info(info) if info else None


def get_instance_for_team(challenge_id: str, team_id: str) -> Optional[dict]:
    with _lock:
        instance_id = _team_instances.get((challenge_id, team_id))
        if not instance_id:
            return None
        info = _instances.get(instance_id)
        return _public_instance_info(info) if info else None


def list_instances() -> list:
    with _lock:
        return [
            _public_instance_info(v)
            for v in _instances.values()
        ]


def delete_instance(instance_id: str) -> bool:
    _cleanup_instance(instance_id)
    return True
