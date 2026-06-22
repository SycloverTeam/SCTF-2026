#!/usr/bin/env python3
"""nc-style TCP challenge server for DeepSea Finance CTF."""

import json
import os
import socketserver
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import instance_manager as im

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"

# CTF Platform API for token verification
CTF_API_URL = os.environ.get(
    "CTF_API_URL",
    "https://adworld.xctf.org.cn/api/ct/public/jeopardy_race/race/token_info/",
)

BANNER = r"""
  ____   ____ _____ _____
 / ___| / ___|_   _|  ___|
 \___ \| |     | | | |_
  ___) | |___  | | |  _|
 |____/ \____| |_| |_|

          SCTF Platform
  Powered by Foundry + Anvil
"""

SEP = "=" * 52


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


def _load_challenges() -> list[dict]:
    result = []
    for d in sorted(CHALLENGES_DIR.iterdir()):
        meta = d / "challenge.json"
        if meta.exists():
            with open(meta) as f:
                result.append(json.load(f))
    return result


class ChallengeSession(socketserver.StreamRequestHandler):
    """One TCP connection = one player session."""

    # ── Session state ────────────────────────────────────────────────────────

    token: Optional[str] = None
    team_name: Optional[str] = None
    instance_id: Optional[str] = None

    # ── I/O helpers ──────────────────────────────────────────────────────────

    def w(self, msg: str = "") -> None:
        try:
            self.wfile.write((msg + "\n").encode())
            self.wfile.flush()
        except BrokenPipeError:
            pass

    def ask(self, prompt: str) -> str:
        try:
            self.wfile.write(prompt.encode())
            self.wfile.flush()
            line = self.rfile.readline()
            if not line:
                raise ConnectionResetError
            return line.decode(errors="replace").strip()
        except (BrokenPipeError, ConnectionResetError):
            raise

    # ── Menu ─────────────────────────────────────────────────────────────────

    def show_menu(self) -> None:
        self.w()
        self.w("  [1] Launch new instance")
        self.w("  [2] Get flag")
        self.w("  [3] Kill instance")
        self.w("  [0] Exit")
        self.w()

    # ── Handlers ─────────────────────────────────────────────────────────────

    def handle_launch(self) -> None:
        # Step 1: Verify team token
        self.w()
        self.w("[*] Please enter your team token from the CTF platform.")
        try:
            token = self.ask("Token > ").strip()
        except (ConnectionResetError, BrokenPipeError):
            return

        if not token:
            self.w("[!] Empty token.")
            return

        self.w("[*] Verifying token...")

        is_valid, team_info = verify_token(token)
        if not is_valid:
            self.w("[!] Invalid token. Please check your token.")
            return

        team_name = team_info.get("name", "Unknown") if team_info else "Unknown"
        self.w(f"[*] Welcome, {team_name}!")
        self.token = token
        self.team_name = team_name

        # Step 2: Check if this token already has a running instance
        existing = im.get_instance_by_token(token)
        if existing:
            info = im.get_instance_info(existing)
            if info:
                self.w()
                self.w(f"[!] You already have a running instance!")
                self.w(SEP)
                self.w(f"  Instance ID    : {existing[:16]}...")
                self.w(f"  RPC URL        : {info['rpc_url']}")
                self.w(f"  Setup contract : {info['setup_address']}")
                self.w(f"  Player address : {info['player_address']}")
                self.w(f"  Player key     : {info['player_key']}")
                self.w(f"  Expires in     : {info['expires_in']}s")
                self.w(SEP)
                self.instance_id = existing
                self.w()
                self.w("[*] Kill it first (option 3) if you want a new one.")
                return

        # Step 3: Launch instance
        self.w()
        self.w("[*] Starting Anvil and deploying contracts...")
        self.w("[*] This usually takes 5-15 seconds, please wait...")

        try:
            info = im.create_instance("deepsea_finance", token)
        except Exception as exc:
            self.w(f"[!] Launch failed: {exc}")
            return

        self.instance_id = info["instance_id"]

        self.w()
        self.w(SEP)
        self.w("  Instance launched!")
        self.w(SEP)
        self.w(f"  Team           : {team_name}")
        self.w(f"  Instance ID    : {info['instance_id']}")
        self.w(f"  RPC URL        : {info['rpc_url']}")
        self.w(f"  Setup contract : {info['setup_address']}")
        self.w(f"  Player address : {info['player_address']}")
        self.w(f"  Player key     : {info['player_key']}")
        self.w(f"  Expires in     : {info['expires_in']}s")
        self.w(SEP)
        self.w()
        self.w("  Connect with:")
        self.w(f"    export RPC={info['rpc_url']}")
        self.w(f"    export PK={info['player_key']}")
        self.w(f"    export SETUP={info['setup_address']}")
        self.w()

    def handle_flag(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance. Launch one first (option 1).")
            return

        self.w()
        self.w("[*] Checking on-chain state via isSolved()...")

        result = im.check_solved(self.instance_id)

        if "error" in result:
            self.w(f"[!] {result['error']}")
        elif result["solved"]:
            self.w()
            self.w(SEP)
            self.w("  Congratulations! Challenge solved!")
            self.w(SEP)
            self.w(f"  FLAG: {result['flag']}")
            self.w(SEP)
            self.w()
            # Kill instance after successful solve
            im.delete_instance(self.instance_id)
            self.w("[*] Instance destroyed after successful solve.")
            self.instance_id = None
        else:
            self.w("[*] Not solved yet - isSolved() returned false.")
            self.w("[*] Keep going!")

    def handle_kill(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance.")
            return
        im.delete_instance(self.instance_id)
        self.w(f"[*] Instance {self.instance_id[:8]}... killed.")
        self.instance_id = None

    # ── Main loop ────────────────────────────────────────────────────────────

    def handle(self) -> None:
        self.instance_id = None
        self.token = None
        self.team_name = None

        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[+] Connection from {peer}", flush=True)

        try:
            self.w(BANNER)

            while True:
                self.show_menu()

                try:
                    choice = self.ask("Choice > ")
                except (ConnectionResetError, BrokenPipeError, EOFError):
                    break

                if choice == "1":
                    self.handle_launch()
                elif choice == "2":
                    self.handle_flag()
                elif choice == "3":
                    self.handle_kill()
                elif choice == "0":
                    self.w("Goodbye!")
                    break
                else:
                    self.w("[!] Unknown option. Please try again.")

        except Exception as exc:
            print(f"[!] Session error from {peer}: {exc}", flush=True)
        finally:
            print(f"[-] Disconnected: {peer}", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "1337"))

    print(f"[*] DeepSea Finance CTF server listening on {host}:{port}", flush=True)
    print(f"[*] Players connect with:  nc <host> {port}", flush=True)

    with ThreadedTCPServer((host, port), ChallengeSession) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...", flush=True)
            sys.exit(0)
