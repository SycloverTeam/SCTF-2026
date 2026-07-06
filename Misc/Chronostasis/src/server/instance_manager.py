import os
import re
import subprocess
import socket
import time
import threading
import json
import uuid
import requests
from pathlib import Path
from typing import Optional

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
FOUNDRY_BIN = os.environ.get("FOUNDRY_BIN", "/root/.foundry/bin")
INSTANCE_TIMEOUT = int(os.environ.get("INSTANCE_TIMEOUT", 1800))  # 30 min default
MAX_INSTANCES_PER_TEAM = int(os.environ.get("MAX_INSTANCES_PER_TEAM", 0))  # 0 = unlimited
TEAM_API_URL = os.environ.get(
    "TEAM_API_URL",
    "https://adworld.xctf.org.cn/api/ct/public/jeopardy_race/race/token_info/",
)
FLAG = os.environ.get("FLAG_SECRET", "SCTF{w0r!d.3xecut3(3th3r_!p_str1k3);}")

# Public hostname/IP shown to players in the RPC URL.
# Set to the server's public IP or hostname for remote deployments.
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "127.0.0.1")

# Port range reserved for Anvil instances (must be exposed in docker-compose)
ANVIL_PORT_MIN = int(os.environ.get("ANVIL_PORT_MIN", 7001))
ANVIL_PORT_MAX = int(os.environ.get("ANVIL_PORT_MAX", 7050))


def _random_keys() -> tuple[str, str, str]:
    """Generate random deployer + player keys, return (deployer_key, player_key, player_addr).

    Uses cast wallet new to generate unique keys per instance.  The random
    deployer guarantees every Setup contract lands at a different address,
    preventing cross-instance attacks.
    """
    keys: list[str] = []
    addrs: list[str] = []
    for _ in range(2):  # 0 = deployer, 1 = player
        r = subprocess.run(
            [f"{FOUNDRY_BIN}/cast", "wallet", "new", "--json"],
            capture_output=True, text=True,
        )
        try:
            info = json.loads(r.stdout)
        except json.JSONDecodeError:
            # fallback: parse text output  "Address: 0x...\nPrivate key: 0x..."
            addr_m = re.search(r'Address:\s*(0x[0-9a-fA-F]{40})', r.stdout)
            key_m = re.search(r'Private key:\s*(0x[0-9a-fA-F]{64})', r.stdout)
            if not addr_m or not key_m:
                raise RuntimeError(f"cast wallet new parse failed: {r.stdout[:200]}")
            addrs.append(addr_m.group(1))
            keys.append(key_m.group(1))
            continue
        addrs.append(info[0]["address"])
        keys.append(info[0].get("private_key") or info[0]["privateKey"])
    return keys[0], keys[1], addrs[1]

_instances: dict[str, dict] = {}
_lock = threading.Lock()
_used_ports: set[int] = set()
_port_lock = threading.Lock()


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


def _wait_for_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


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

    # Determine constructor args based on challenge
    meta = _load_challenge_meta(challenge_id)
    constructor_args = []

    # Challenges that need player address as constructor arg
    needs_player = challenge_id in ("chronostasis")
    if needs_player:
        constructor_args = ["--constructor-args", player_address]

    value_arg = []
    if value_eth > 0:
        value_arg = ["--value", f"{value_eth}ether"]

    cmd = [
        f"{FOUNDRY_BIN}/forge", "create",
        "--root", str(challenge_dir),
        "--rpc-url", rpc_url,
        "--private-key", deployer_key,
        "--broadcast",
        "--json",
        *value_arg,
        "src/Setup.sol:Setup",
        *constructor_args,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[deploy error] {result.stderr}", flush=True)
        return None

    # forge >=1.3 with --json outputs {"deployedTo": "0x..."}
    try:
        deploy_info = json.loads(result.stdout)
        addr = deploy_info.get("deployedTo")
        if addr:
            return addr
    except json.JSONDecodeError:
        pass

    # Fallback: older forge versions print "Deployed to: 0x..."
    for line in result.stdout.splitlines():
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()

    print(f"[deploy] could not parse deploy address from: {result.stdout[:300]}", flush=True)
    return None


def _generate_flag(instance_id: str) -> str:
    """Return the static flag. Only called after on-chain isSolved() passes."""
    return FLAG


def _cleanup_instance(instance_id: str):
    with _lock:
        info = _instances.pop(instance_id, None)
    if info:
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


def query_team_info(enroll_token: str) -> dict:
    """Query the CTF platform API for team information by enroll token.

    Returns a dict with keys: identifier, name, enroll_id, race_id.
    Raises RuntimeError on failure.
    """
    url = f"{TEAM_API_URL}?enroll_token={enroll_token}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        body = resp.json()
    except requests.exceptions.Timeout:
        raise RuntimeError("无法连接赛事平台（超时），请稍后重试")
    except requests.exceptions.ConnectionError:
        raise RuntimeError("无法连接赛事平台（网络错误），请稍后重试")
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"赛事平台返回错误: HTTP {resp.status_code}，请检查 token 是否正确")
    except json.JSONDecodeError:
        raise RuntimeError("赛事平台返回数据格式异常，请稍后重试")

    data = body.get("data")
    if not data or not data.get("identifier"):
        raise RuntimeError("无效的队伍 token，请检查后重试")

    return {
        "identifier": data["identifier"],
        "name": data.get("name", data["identifier"]),
        "enroll_id": data.get("enroll_id", ""),
        "race_id": data.get("race_id", ""),
    }


def count_team_instances(team_identifier: str) -> int:
    """Return the number of active instances owned by a team."""
    with _lock:
        return sum(
            1 for info in _instances.values()
            if info.get("team_identifier") == team_identifier
        )


def create_instance(challenge_id: str, team_info: dict) -> dict:
    """Start an Anvil instance, deploy challenge, return connection info."""
    meta = _load_challenge_meta(challenge_id)

    port = _find_free_port()
    instance_id = str(uuid.uuid4())

    # Start Anvil with DEFAULT mnemonic (reliable) — bind to 0.0.0.0
    proc = subprocess.Popen(
        [
            f"{FOUNDRY_BIN}/anvil",
            "--host", "0.0.0.0",
            "--port", str(port),
            "--chain-id", "31337",
            "--accounts", "10",
            "--balance", "10000",
            "--silent",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    internal_rpc = f"http://127.0.0.1:{port}"
    public_rpc = f"http://{PUBLIC_HOST}:{port}"

    if not _wait_for_port(port):
        proc.terminate()
        with _port_lock:
            _used_ports.discard(port)
        raise RuntimeError("Anvil failed to start")

    # Default anvil account 0 — funds random deployer + player
    funder_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    # Generate unique random keys for this instance
    deployer_key, player_key, player_address = _random_keys()

    # Derive deployer address from the random key
    deployer_addr_result = subprocess.run(
        [f"{FOUNDRY_BIN}/cast", "wallet", "address", "--private-key", deployer_key],
        capture_output=True, text=True,
    )
    if deployer_addr_result.returncode != 0:
        proc.terminate()
        with _port_lock:
            _used_ports.discard(port)
        raise RuntimeError(f"Failed to derive deployer address: {deployer_addr_result.stderr}")
    deployer_address = deployer_addr_result.stdout.strip()

    # Fund random accounts from the default genesis account (with retries)
    for addr, label in [(deployer_address, "deployer"), (player_address, "player")]:
        for attempt in range(5):
            result = subprocess.run(
                [
                    f"{FOUNDRY_BIN}/cast", "send",
                    "--rpc-url", internal_rpc,
                    "--private-key", funder_key,
                    addr,
                    "--value", "100ether",
                ],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                break
            print(f"[fund] attempt {attempt + 1}/5: failed to fund {label} {addr}: {result.stderr.strip()}", flush=True)
            time.sleep(0.5)
        else:
            proc.terminate()
            with _port_lock:
                _used_ports.discard(port)
            raise RuntimeError(f"Failed to fund {label} {addr} after 5 attempts: {result.stderr}")

    # Deploy Setup using random deployer (guarantees unique Setup address)
    setup_address = _deploy_setup(
        challenge_id,
        internal_rpc,
        deployer_key,
        player_address,
        meta.get("setup_value_eth", 0),
    )

    if not setup_address:
        proc.terminate()
        with _port_lock:
            _used_ports.discard(port)
        raise RuntimeError("Failed to deploy Setup contract")

    info = {
        "instance_id": instance_id,
        "challenge_id": challenge_id,
        "team_identifier": team_info["identifier"],
        "team_name": team_info["name"],
        "port": port,
        "internal_rpc": internal_rpc,
        "rpc_url": public_rpc,
        "setup_address": setup_address,
        "player_address": player_address,
        "player_key": player_key,
        "proc": proc,
        "created_at": time.time(),
        "expires_at": time.time() + INSTANCE_TIMEOUT,
    }

    with _lock:
        _instances[instance_id] = info

    _schedule_cleanup(instance_id, INSTANCE_TIMEOUT)

    return {
        "instance_id": instance_id,
        "challenge_id": challenge_id,
        "team_name": team_info["name"],
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

    result = subprocess.run(
        [
            f"{FOUNDRY_BIN}/cast", "call",
            info["setup_address"],
            "isSolved()(bool)",
            "--rpc-url", info["internal_rpc"],
        ],
        capture_output=True,
        text=True,
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


def list_instances() -> list:
    with _lock:
        return [
            {
                "instance_id": iid,
                "challenge_id": v["challenge_id"],
                "team_name": v.get("team_name", "unknown"),
                "team_identifier": v.get("team_identifier", ""),
                "rpc_url": v["rpc_url"],
                "created_at": v["created_at"],
                "expires_at": v["expires_at"],
            }
            for iid, v in _instances.items()
        ]


def delete_instance(instance_id: str) -> bool:
    _cleanup_instance(instance_id)
    return True
