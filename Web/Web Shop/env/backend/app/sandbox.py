from __future__ import annotations

import ast
import json
import multiprocessing as mp
import os
import time
from pathlib import Path
from typing import Any


class SandboxError(Exception):
    pass


FORBIDDEN_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.Yield,
    ast.YieldFrom,
    ast.ClassDef,
)

FORBIDDEN_NAMES = {
    "open",
    "eval",
    "exec",
    "compile",
    "__import__",
    "input",
    "help",
    "dir",
    "vars",
    "locals",
    "globals",
    "getattr",
    "setattr",
    "delattr",
}

BLOCKED_ATTRS = {
    "__class__",
    "__base__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__closure__",
    "__globals__",
    "__builtins__",
    "__dict__",
    "__getattribute__",
    "gi_frame",
    "gi_code",
    "f_locals",
    "f_code",
    "f_back",
    "f_globals",
}

BLOCKED_STRING_PARTS = {
    "__class__",
    "__base__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__closure__",
    "__globals__",
    "__builtins__",
    "__dict__",
    "__getattribute__",
    "gi_frame",
    "gi_code",
    "f_locals",
    "f_code",
    "f_builtins",
    "f_globals",
    "f_back",
}

SAFE_BUILTINS = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "float": float,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "next": next,
    "pow": pow,
    "range": range,
    "reversed": reversed,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}


def validate_code(code: str) -> ast.AST:
    if len(code) > 4096:
        raise SandboxError("code too long")
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        raise SandboxError(f"syntax error: {exc.msg}") from exc

    for node in ast.walk(tree):
        if isinstance(node, FORBIDDEN_NODES):
            raise SandboxError("forbidden syntax")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            raise SandboxError(f"forbidden name: {node.id}")
        if isinstance(node, ast.Attribute):
            if node.attr in BLOCKED_ATTRS:
                raise SandboxError(f"forbidden attribute: {node.attr}")
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise SandboxError(f"forbidden attribute: {node.attr}")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if any(part in node.value for part in BLOCKED_STRING_PARTS):
                raise SandboxError("forbidden string")
    return tree


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return repr(value)


def _execute_code(code: str, context: dict[str, Any]) -> dict[str, Any]:
    try:
        tree = validate_code(code)
        rule_context = {
            "user": context.get("user", {}),
            "order": context.get("order", {}),
            "products": context.get("products", []),
            "policy": {
                "currency": "coin",
                "refundWindowDays": 7,
                "maxAdjustment": 200,
            },
            "shop": {
                "region": "default",
                "previewMode": True,
            },
        }
        preview_path = Path(os.environ.get("SHIPMENT_PREVIEW_FILE", "/app/private/flag.txt"))

        def load_manifest() -> str:
            return preview_path.read_text(encoding="utf-8")

        preview_items = [
            {"key": "user", "value": rule_context["user"]},
            {"key": "order", "value": rule_context["order"]},
            {"key": "policy", "value": rule_context["policy"]},
            {"key": "shop", "value": rule_context["shop"]},
        ]

        def iter_preview_items():
            shipment_manifest = load_manifest()
            for item in preview_items:
                yield item

        local_vars: dict[str, Any] = {
            "user": rule_context["user"],
            "order": rule_context["order"],
            "products": rule_context["products"],
            "policy": rule_context["policy"],
            "iter_preview_items": iter_preview_items,
            "result": None,
        }
        exec(compile(tree, "<pricing-rule>", "exec"), {"__builtins__": SAFE_BUILTINS}, local_vars)
        return {"ok": True, "result": _json_safe(local_vars.get("result"))}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _worker(code: str, context: dict[str, Any], queue: mp.Queue) -> None:
    queue.put(_execute_code(code, context))


def run_pricing_code(code: str, context: dict[str, Any], timeout: float = 2.0) -> dict[str, Any]:
    start = time.monotonic()
    sandbox_context = {
        "user": context.get("user", {}),
        "order": context.get("order", {}),
        "products": context.get("products", []),
    }

    if "fork" not in mp.get_all_start_methods():
        result = _execute_code(code, sandbox_context)
        result["elapsedMs"] = round((time.monotonic() - start) * 1000)
        return result

    ctx = mp.get_context("fork")
    queue: mp.Queue = ctx.Queue(1)
    proc = ctx.Process(target=_worker, args=(code, sandbox_context, queue), daemon=True)
    proc.start()
    proc.join(timeout)

    if proc.is_alive():
        proc.terminate()
        proc.join(0.2)
        return {"ok": False, "error": "execution timeout", "elapsedMs": round((time.monotonic() - start) * 1000)}

    if queue.empty():
        return {"ok": False, "error": "sandbox worker exited", "elapsedMs": round((time.monotonic() - start) * 1000)}

    result = queue.get()
    result["elapsedMs"] = round((time.monotonic() - start) * 1000)
    return result
