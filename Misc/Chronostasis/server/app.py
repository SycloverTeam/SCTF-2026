#!/usr/bin/env python3
"""nc-style TCP challenge server for Smart Contract CTF."""

import json
import os
import socketserver
import sys
import threading
import uuid
from pathlib import Path

import instance_manager as im

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"

BANNER = r"""

  ░██████  ░██                                                                ░██                          ░██
 ░██   ░██ ░██                                                                ░██
░██        ░████████  ░██░████  ░███████  ░████████   ░███████   ░███████  ░████████  ░██████    ░███████  ░██ ░███████
░██        ░██    ░██ ░███     ░██    ░██ ░██    ░██ ░██    ░██ ░██           ░██          ░██  ░██        ░██░██
░██        ░██    ░██ ░██      ░██    ░██ ░██    ░██ ░██    ░██  ░███████     ░██     ░███████   ░███████  ░██ ░███████
 ░██   ░██ ░██    ░██ ░██      ░██    ░██ ░██    ░██ ░██    ░██        ░██    ░██    ░██   ░██         ░██ ░██       ░██
  ░██████  ░██    ░██ ░██       ░███████  ░██    ░██  ░███████   ░███████      ░████  ░█████░██  ░███████  ░██ ░███████

                                                 blockchain / misc / SCTF
                                                Powered by Foundry + Anvil
"""

SEP = "=" * 52


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

    # ── I/O helpers ──────────────────────────────────────────────────────────

    def w(self, msg: str = "") -> None:
        """Write a line to the client."""
        try:
            self.wfile.write((msg + "\n").encode())
            self.wfile.flush()
        except BrokenPipeError:
            pass

    def ask(self, prompt: str) -> str:
        """Write prompt and read one line from the client."""
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
        self.w("  [1] List challenges")
        self.w("  [2] Launch new instance")
        self.w("  [3] Get flag")
        self.w("  [4] Kill instance")
        self.w("  [0] Exit")
        self.w()

    # ── Handlers ─────────────────────────────────────────────────────────────

    def handle_list(self) -> None:
        challenges = _load_challenges()
        self.w()
        self.w(SEP)
        for c in challenges:
            self.w(f"  ID      : {c['id']}")
            self.w(f"  Name    : {c['name']}")
            self.w(f"  Category: {c['category']}")
        self.w(SEP)

    def handle_launch(self) -> None:
        if self.instance_id:
            self.w(f"[!] You already have instance: {self.instance_id[:8]}...")
            self.w("[!] Kill it first (option 4) before launching a new one.")
            return

        challenges = _load_challenges()
        if not challenges:
            self.w("[!] No challenges available.")
            return

        if len(challenges) == 1:
            challenge_id = challenges[0]["id"]
            self.w(f"[*] Auto-selected challenge: {challenge_id}  —  {challenges[0]['name']}")
        else:
            self.w()
            self.w("Available challenges:")
            for c in challenges:
                self.w(f"  {c['id']}  —  {c['name']}")
            self.w()
            try:
                challenge_id = self.ask("Challenge ID > ").strip()
            except (ConnectionResetError, BrokenPipeError):
                return
            meta_path = CHALLENGES_DIR / challenge_id / "challenge.json"
            if not meta_path.exists():
                self.w(f"[!] Unknown challenge: {challenge_id!r}")
                return

        # Team token — always prompt
        try:
            team_token = self.ask("Team token   > ").strip()
            if not team_token:
                self.w("[!] Team token is required.")
                return
        except (ConnectionResetError, BrokenPipeError):
            return

        # Only validate token & enforce limits when instance limit is active
        if im.MAX_INSTANCES_PER_TEAM > 0:
            self.w()
            self.w("[*] Verifying team token...")
            try:
                team_info = im.query_team_info(team_token)
            except RuntimeError as exc:
                self.w(f"[!] {exc}")
                return

            self.w(f"[*] Team: {team_info['name']}")

            current_count = im.count_team_instances(team_info["identifier"])
            if current_count >= im.MAX_INSTANCES_PER_TEAM:
                self.w(
                    f"[!] 队伍 '{team_info['name']}' 已达到实例上限 "
                    f"({current_count}/{im.MAX_INSTANCES_PER_TEAM})，"
                    f"请先释放已有实例后再创建"
                )
                return
            self.w(f"[*] 实例使用情况: {current_count}/{im.MAX_INSTANCES_PER_TEAM}")
        else:
            # No limit — accept token as-is without platform verification
            team_info = {"identifier": team_token, "name": team_token}

        self.w()
        self.w("[*] Starting Anvil and deploying contracts...")
        self.w("[*] This usually takes a few seconds, please wait...")

        try:
            info = im.create_instance(challenge_id, team_info)
        except Exception as exc:
            self.w(f"[!] Launch failed: {exc}")
            return

        self.instance_id = info["instance_id"]

        self.w()
        self.w(SEP)
        self.w("  Instance launched!")
        self.w(SEP)
        self.w(f"  Team           : {info['team_name']}")
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

    def handle_hint(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance.")
            return
        with im._lock:
            info = im._instances.get(self.instance_id)
        if not info:
            self.w("[!] Instance not found.")
            return
        meta_path = CHALLENGES_DIR / info["challenge_id"] / "challenge.json"
        with open(meta_path) as f:
            meta = json.load(f)
        hints = meta.get("hints", [])
        if not hints:
            self.w("[*] No hints available for this challenge.")
            return
        self.w()
        self.w("Hints:")
        for i, h in enumerate(hints, 1):
            self.w(f"  {i}. {h}")
        self.w()

    def handle_flag(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance. Launch one first (option 2).")
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
        else:
            self.w("[*] Not solved yet — isSolved() returned false.")
            self.w("[*] Keep going!")

    def handle_kill(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance.")
            return
        im.delete_instance(self.instance_id)
        self.w(f"[*] Instance {self.instance_id[:8]}... killed.")
        self.instance_id = None

    # ── Main loop ─────────────────────────────────────────────────────────────

    def handle(self) -> None:
        self.instance_id: str | None = None

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
                    self.handle_list()
                elif choice == "2":
                    self.handle_launch()
                elif choice == "3":
                    self.handle_flag()
                elif choice == "4":
                    self.handle_kill()
                elif choice == "0":
                    self.w("Goodbye!")
                    break
                else:
                    self.w(f"[!] Unknown option: {choice!r}")

        except Exception as exc:
            print(f"[!] Session error from {peer}: {exc}", flush=True)
        finally:
            # Clean up instance if player disconnects without killing it
            if self.instance_id:
                im.delete_instance(self.instance_id)
                print(f"[-] Auto-cleaned instance for {peer}", flush=True)
            print(f"[-] Disconnected: {peer}", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 7000))

    print(f"[*] Smart Contract CTF server listening on {host}:{port}", flush=True)
    print(f"[*] Players connect with:  nc <host> {port}", flush=True)

    with ThreadedTCPServer((host, port), ChallengeSession) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...", flush=True)
            sys.exit(0)
