#!/usr/bin/env python3
"""nc-style TCP challenge server for SCTF."""

import json
import os
import socketserver
import sys
import hashlib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

import instance_manager as im

CHALLENGES_DIR = Path(__file__).parent.parent / "challenges"
CTF_API_URL = os.environ.get("CTF_API_URL", "").strip()

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


def _load_challenges() -> list[dict]:
    result = []
    for d in sorted(CHALLENGES_DIR.iterdir()):
        meta = d / "challenge.json"
        if meta.exists():
            with open(meta) as f:
                result.append(json.load(f))
    return result


# ── Token verification ──────────────────────────────────────────────────────

def verify_token(token: str) -> tuple[bool, Optional[dict]]:
    """Verify token via CTF platform API. Returns (is_valid, team_info)."""
    try:
        if not CTF_API_URL:
            print("[!] Token verification error: CTF_API_URL is not set", flush=True)
            return False, None

        query = urllib.parse.urlencode({"enroll_token": token})
        separator = "&" if "?" in CTF_API_URL else "?"
        url = f"{CTF_API_URL}{separator}{query}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("data") is not None:
                team_info = data["data"]
                if isinstance(team_info, dict):
                    return True, team_info
                return True, {"value": team_info}
            return False, None
    except Exception as e:
        print(f"[!] Token verification error: {e}", flush=True)
        return False, None


def _nested_get(data: dict, path: str) -> object:
    value: object = data
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _team_identity(team_info: dict, token: str) -> str:
    for field in (
        "team_id",
        "teamId",
        "id",
        "uuid",
        "team.id",
        "team.team_id",
        "team.uuid",
        "team.name",
        "name",
    ):
        value = _nested_get(team_info, field)
        if value not in (None, ""):
            return f"{field}:{value}"

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return f"token_sha256:{token_hash}"


def _team_display_name(team_info: dict, team_id: str) -> str:
    for field in ("team_name", "name", "nickname", "team.name"):
        value = _nested_get(team_info, field)
        if value not in (None, ""):
            return str(value)
    return team_id


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

    def ask_challenge_id(self) -> Optional[str]:
        default = self.challenge_id
        if not default:
            challenges = _load_challenges()
            if len(challenges) == 1:
                default = challenges[0]["id"]

        prompt = f"Challenge ID [{default}] > " if default else "Challenge ID > "
        try:
            challenge_id = self.ask(prompt).strip() or default
        except (ConnectionResetError, BrokenPipeError):
            return None

        if not challenge_id:
            self.w("[!] Challenge ID is required.")
            return None

        meta_path = CHALLENGES_DIR / challenge_id / "challenge.json"
        if not meta_path.exists():
            self.w(f"[!] Unknown challenge: {challenge_id!r}")
            return None
        return challenge_id

    def ask_team(self) -> Optional[tuple[str, dict]]:
        try:
            token = self.ask("Team token  > ").strip()
        except (ConnectionResetError, BrokenPipeError):
            return None

        if not token:
            self.w("[!] Team token is required.")
            return None

        is_valid, team_info = verify_token(token)
        if not is_valid or team_info is None:
            self.w("[!] Invalid team token.")
            return None

        team_id = _team_identity(team_info, token)
        team_info["team_name"] = _team_display_name(team_info, team_id)
        return team_id, team_info

    def ask_team_instance(self) -> Optional[dict]:
        challenge_id = self.ask_challenge_id()
        if not challenge_id:
            return None

        team = self.ask_team()
        if not team:
            return None
        team_id, _team_info = team

        info = im.get_instance_for_team(challenge_id, team_id)
        if not info:
            self.w(f"[!] No active instance for this team on {challenge_id}.")
            self.w("[!] Launch one first (option 2).")
            return None

        self.instance_id = info["instance_id"]
        self.challenge_id = challenge_id
        return info

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
            diff_map = {"Easy": "★☆☆", "Medium": "★★☆", "Hard": "★★★"}
            stars = diff_map.get(c["difficulty"], c["difficulty"])
            self.w(f"  ID      : {c['id']}")
            self.w(f"  Name    : {c['name']}  {stars}  ({c['points']} pts)")
            self.w(f"  Category: {c['category']}")
            self.w(f"  Desc    : {c['description']}")
            if c.get("hints"):
                self.w(f"  Hints   : {len(c['hints'])} available")
            self.w()
        self.w(SEP)

    def handle_launch(self) -> None:
        if self.instance_id and im.get_instance(self.instance_id):
            self.w(f"[!] You already have instance: {self.instance_id[:8]}...")
            self.w("[!] Kill it first (option 4) before launching a new one.")
            return
        self.instance_id = None

        challenges = _load_challenges()
        self.w()
        self.w("Available challenges:")
        for c in challenges:
            self.w(f"  {c['id']}  —  {c['name']}")
        self.w()

        challenge_id = self.ask_challenge_id()
        if not challenge_id:
            return

        team = self.ask_team()
        if not team:
            return
        team_id, team_info = team

        self.w()
        self.w("[*] Starting Anvil and deploying contracts...")
        self.w("[*] This usually takes 5–15 seconds, please wait...")

        try:
            info = im.create_instance(challenge_id, team_id, team_info)
        except Exception as exc:
            self.w(f"[!] Launch failed: {exc}")
            return

        self.instance_id = info["instance_id"]
        self.challenge_id = challenge_id

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
        info = self.ask_team_instance()
        if not info:
            return

        self.w()
        self.w("[*] Checking on-chain state via isSolved()...")

        result = im.check_solved(info["instance_id"])

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
        info = self.ask_team_instance()
        if not info:
            return
        im.delete_instance(info["instance_id"])
        self.w(f"[*] Instance {info['instance_id'][:8]}... killed.")
        self.instance_id = None
        self.challenge_id = None

    # ── Main loop ─────────────────────────────────────────────────────────────

    def handle(self) -> None:
        self.instance_id: str | None = None
        self.challenge_id: str | None = None

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
            print(f"[-] Disconnected: {peer}", flush=True)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 1337))

    print(f"[*] SCTF server listening on {host}:{port}", flush=True)
    print(f"[*] Players connect with:  nc <host> {port}", flush=True)

    with ThreadedTCPServer((host, port), ChallengeSession) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down...", flush=True)
            sys.exit(0)
