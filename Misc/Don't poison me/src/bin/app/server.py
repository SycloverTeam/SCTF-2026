#!/usr/bin/env python3
import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parent
CODEX_CONFIG = APP_ROOT / "codex_config.toml"
CODEX_TIMEOUT = 45


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Don't poison me</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7f8;
      color: #192124;
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
    }}
    main {{
      width: min(760px, calc(100vw - 32px));
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: clamp(28px, 5vw, 44px);
      font-weight: 720;
      letter-spacing: 0;
    }}
    p {{
      margin: 0 0 22px;
      color: #536068;
      line-height: 1.55;
    }}
    form {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
      gap: 10px;
      margin-bottom: 18px;
    }}
    input {{
      min-width: 0;
      padding: 13px 14px;
      border: 1px solid #cbd5dc;
      border-radius: 8px;
      font: inherit;
      background: #fff;
      color: #192124;
    }}
    button {{
      border: 0;
      border-radius: 8px;
      padding: 0 18px;
      min-height: 48px;
      font: inherit;
      font-weight: 700;
      color: #fff;
      background: #006d77;
      cursor: pointer;
    }}
    pre {{
      min-height: 180px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      padding: 16px;
      border: 1px solid #d7e0e5;
      border-radius: 8px;
      background: #101719;
      color: #dff6f1;
      line-height: 1.45;
    }}
    @media (max-width: 620px) {{
      form {{
        grid-template-columns: 1fr;
      }}
      button {{
        width: 100%;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>Don't poison me</h1>
    <p>Give the assistant a compatible API endpoint. It will ask once, then show the result it received.</p>
    <form method="post" action="/run">
      <input name="url" type="url" required autocomplete="url" placeholder="https://example.com/v1" value="{url}">
      <input name="api_key" type="password" required autocomplete="off" placeholder="API key">
      <button type="submit">Connect</button>
    </form>
    <pre>{output}</pre>
  </main>
</body>
</html>
"""


def render_page(output: str = "Waiting for an upstream endpoint.", url: str = "") -> bytes:
    return INDEX_HTML.format(output=html.escape(output), url=html.escape(url, quote=True)).encode()


def json_response(handler: BaseHTTPRequestHandler, status: int, data: dict) -> None:
    body = json.dumps(data, ensure_ascii=False).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def html_response(handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def toml_string(value: str) -> str:
    return json.dumps(value)


def normalize_api_base(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Only absolute http(s) URLs are accepted.")

    if parsed.path.rstrip("/").endswith("/responses"):
        path = parsed.path.rstrip("/")[: -len("/responses")]
        parsed = parsed._replace(path=path or "/", query="", fragment="")
    else:
        parsed = parsed._replace(query="", fragment="")
    return urllib.parse.urlunparse(parsed).rstrip("/")


def normalize_api_key(api_key: str) -> str:
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("API key is required.")
    if len(api_key) > 512:
        raise ValueError("API key is too long.")
    return api_key


def prepare_codex_home(codex_home: str) -> None:
    path = Path(codex_home)
    path.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CODEX_CONFIG, path / "config.toml")
    if os.geteuid() == 0:
        for item in [path, path / "config.toml"]:
            os.chown(item, 1000, 1000)


def codex_command(api_base: str) -> list[str]:
    command = [
        "codex",
        "exec",
        "--json",
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-rules",
        "--disable",
        "shell_tool",
        "--disable",
        "unified_exec",
        "--disable",
        "apply_patch_streaming_events",
        "--disable",
        "apply_patch_freeform",
        "-c",
        f"model_providers.challenge.base_url={toml_string(api_base)}",
        "-C",
        "/tmp",
        "-m",
        "gpt-5",
        "hello",
    ]
    if os.geteuid() == 0 and shutil.which("setpriv"):
        return [
            "setpriv",
            "--reuid",
            "1000",
            "--regid",
            "1000",
            "--clear-groups",
            *command,
        ]
    return command


def run_codex(url: str, api_key: str) -> str:
    api_base = normalize_api_base(url)
    contestant_api_key = normalize_api_key(api_key)
    with tempfile.TemporaryDirectory(prefix="codex-home-") as codex_home:
        prepare_codex_home(codex_home)
        env = {
            "CODEX_HOME": codex_home,
            "HOME": "/tmp",
            "LC_ALL": "C.UTF-8",
            "CONTESTANT_API_BASE": api_base,
            "CONTESTANT_API_KEY": contestant_api_key,
            "PATH": "/opt/homebrew/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }
        try:
            completed = subprocess.run(
                codex_command(api_base),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd="/tmp",
                env=env,
                timeout=CODEX_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return "codex timed out"

    output = completed.stdout or ""
    if len(output) > 16000:
        output = output[:16000] + "\n[truncated]"
    return output


def run_agent(url: str, api_key: str) -> str:
    return run_codex(url, api_key)


class Handler(BaseHTTPRequestHandler):

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            html_response(self, 200, render_page())
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path not in {"/run", "/api/run"}:
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            self.send_error(413)
            return
        body = self.rfile.read(length).decode("utf-8", "replace")

        if self.headers.get("Content-Type", "").startswith("application/json"):
            try:
                form = json.loads(body)
            except json.JSONDecodeError:
                form = {}
            url = form.get("url", "") if isinstance(form, dict) else ""
            api_key = form.get("api_key", form.get("apiKey", "")) if isinstance(form, dict) else ""
        else:
            form = urllib.parse.parse_qs(body, keep_blank_values=True)
            url = form.get("url", [""])[0]
            api_key = form.get("api_key", [""])[0]

        try:
            output = run_agent(str(url), str(api_key))
            ok = True
        except Exception as exc:
            output = f"Error: {exc}"
            ok = False

        if self.path == "/api/run":
            json_response(self, 200 if ok else 400, {"ok": ok, "output": output})
        else:
            html_response(self, 200, render_page(output, str(url)))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=80, type=int)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"listening on {args.host}:{args.port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
