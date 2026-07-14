#!/usr/bin/env python3
"""GateCrash — Static-Flag TCP Challenge Server.

Per-player isolated Anvil instances + unified static flag.
Provides a menu-driven nc interface:
  [1] Challenge info
  [2] Launch new instance -> RPC + private key + Setup address
  [3] Get flag (auto-checks isSolved(), reads static flag from /flag)
  [4] Kill instance
  [0] Exit
"""

import json
import os
import socketserver
import sys
import threading
from pathlib import Path

import instance_manager as im

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
CHALLENGE_ID = "gatecrash"

BANNER = r"""
   ____       _         ____               _
  / ___| __ _| |_ ___  / ___|_ __ __ _ ___| |__
 | |  _ / _` | __/ _ \| |   | '__/ _` / __| '_ \
 | |_| | (_| | ||  __/| |___| | | (_| \__ \ | | |
  \____|\__,_|\__\___| \____|_|  \__,_|___/_| |_|

                Blockchain / SCTF
            Powered by Foundry + Anvil
"""

SEP = "=" * 52


def _load_meta() -> dict:
    path = CHALLENGES_DIR / CHALLENGE_ID / "challenge.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


class ChallengeSession(socketserver.StreamRequestHandler):

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

    def show_menu(self) -> None:
        self.w()
        self.w("  [1] Challenge info")
        self.w("  [2] Launch new instance")
        self.w("  [3] Get flag")
        self.w("  [4] Kill instance")
        self.w("  [0] Exit")
        self.w()

    # ── [1] Info ────────────────────────────────────────────────────

    def handle_info(self) -> None:
        meta = _load_meta()
        diff_label = {"Easy": "[Easy]", "Medium": "[Medium]", "Hard": "[Hard]"}
        label = diff_label.get(meta.get("difficulty", "Medium"), "[Medium]")
        self.w()
        self.w(SEP)
        self.w(f"  Name    : {meta.get('name', 'GateCrash')}  {label}")
        self.w(f"  Category: {meta.get('category', 'Blockchain')}")
        desc = meta.get("description_en") or meta.get("description", "")
        self.w(f"  Desc    : {desc}")
        self.w()
        self.w(SEP)

    # ── [2] Launch ──────────────────────────────────────────────────

    def handle_launch(self) -> None:
        if self.instance_id:
            self.w(f"[!] You already have an instance: {self.instance_id[:8]}...")
            self.w("[!] Kill it first (option 4).")
            return

        try:
            token = self.ask("CTF Token > ").strip()
        except (ConnectionResetError, BrokenPipeError):
            return

        if not token:
            self.w("[!] Token cannot be empty.")
            return

        player_ip = self.client_address[0]

        self.w()
        self.w("[*] Verifying token...")

        try:
            info = im.create_instance(player_ip, token)
        except RuntimeError as exc:
            self.w(f"[!] Launch failed: {exc}")
            return
        except Exception as exc:
            self.w(f"[!] Launch failed: {exc}")
            return

        self.instance_id = info["instance_id"]

        self.w()
        self.w(SEP)
        if info.get("recovered"):
            self.w("  Instance recovered! (previous session)")
        else:
            self.w("  Instance launched!")
        self.w(SEP)
        self.w(f"  Team           : {info.get('team_name', 'unknown')}")
        self.w(f"  Race           : {info.get('race_name', 'unknown')}")
        self.w(f"  Instance ID    : {info['instance_id']}")
        self.w(f"  RPC URL        : {info['rpc_url']}")
        self.w(f"  Setup address  : {info['setup_address']}")
        self.w(f"  Player address : {info['player_address']}")
        self.w(f"  Player key     : {info['player_key']}")
        self.w(f"  Expires in     : {info['expires_in']}s")
        self.w(f"  Created at     : {info.get('created_at', 0):.0f}")
        self.w(SEP)
        self.w()
        self.w("  Connect with:")
        self.w(f"    export RPC={info['rpc_url']}")
        self.w(f"    export PK={info['player_key']}")
        self.w(f"    export SETUP={info['setup_address']}")
        self.w()


    # ── [3] Flag ────────────────────────────────────────────────────

    def handle_flag(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance. Launch one first (option 2).")
            return

        self.w()
        self.w("[*] Checking on-chain state via Setup.isSolved()...")

        result = im.check_solved(self.instance_id)

        if "error" in result:
            self.w(f"[!] {result['error']}")
        elif result.get("solved"):
            self.w()
            self.w(SEP)
            self.w("  Congratulations! Challenge solved!")
            self.w(SEP)
            self.w(f"  FLAG: {result['flag']}")
            self.w(SEP)
            self.w()
        else:
            self.w("[*] Not solved yet -- isSolved() returned false.")
            self.w("[*] Keep going!")

    # ── [4] Kill ────────────────────────────────────────────────────

    def handle_kill(self) -> None:
        if not self.instance_id:
            self.w("[!] No active instance.")
            return
        im.delete_instance(self.instance_id)
        self.w(f"[*] Instance {self.instance_id[:8]}... killed.")
        self.instance_id = None

    # ── Main loop ────────────────────────────────────────────────────

    def handle(self) -> None:
        self.instance_id: str | None = None
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[+] Connection from {peer}  [threads: {threading.active_count()}]", flush=True)

        try:
            self.w(BANNER)
            while True:
                self.show_menu()
                try:
                    choice = self.ask("Choice > ")
                except (ConnectionResetError, BrokenPipeError, EOFError):
                    break

                if choice == "1":
                    self.handle_info()
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
            # Instance persists after disconnect (cleaned by timeout, not by nc hangup)
            if self.instance_id:
                print(f"[-] Session ended, instance {self.instance_id[:8]}... preserved for reconnection", flush=True)
            print(f"[-] Disconnected: {peer}", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 1337))

    print(f"[*] GateCrash SCTF server listening on {host}:{port}", flush=True)
    print(f"[*] Players connect with:  nc <host> {port}", flush=True)

    with ThreadedTCPServer((host, port), ChallengeSession) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...", flush=True)
            sys.exit(0)
