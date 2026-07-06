from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class ParsedCommand:
    command: str
    args: list[str]
    raw: str


@dataclass(frozen=True)
class CommandResult:
    reply: str
    data: dict[str, Any]


CommandHandler = Callable[[ParsedCommand, dict[str, Any]], CommandResult]


def _load_reply_book() -> tuple[list[tuple[tuple[str, ...], list[str]]], list[str]]:
    path = Path(__file__).with_name("bot_replies.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        data = {}

    qa_pairs = []
    for item in data.get("qa_pairs", []):
        keywords = item.get("keywords", [])
        replies = item.get("replies", [])
        if isinstance(keywords, list) and isinstance(replies, list):
            qa_pairs.append((tuple(str(keyword) for keyword in keywords), [str(reply) for reply in replies]))

    fallback = [str(reply) for reply in data.get("fallback_replies", [])]
    if not fallback:
        fallback = ["我会根据用户状态、订单状态和配置策略给出建议。"]
    return qa_pairs, fallback


QA_PAIRS, FALLBACK_REPLIES = _load_reply_book()


def parse_command(message: str) -> ParsedCommand:
    raw = message.strip()
    if not raw:
        return ParsedCommand(command="", args=[], raw=message)

    parts = raw.split()
    command = parts[0] if raw.startswith("/") else ""
    args = parts[1:] if command else []
    return ParsedCommand(command=command, args=args, raw=raw)


def _role(context: dict[str, Any]) -> str:
    return context.get("user", {}).get("role", "customer")


def _is_admin(context: dict[str, Any]) -> bool:
    return _role(context) == "support_admin"


def help_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    commands = [
        "/help",
        "/profile",
        "/order_status <id>",
        "/config <json>",
        "/login <staff-code>",
    ]
    if _is_admin(context):
        commands.extend(
            [
                "/whoami",
                "/rulelab",
            ]
        )

    return CommandResult(
        reply="可用命令：\n" + "\n".join(commands),
        data={
            "command": parsed.command,
            "args": parsed.args,
            "availableCommands": ["/help", "/profile", "/order_status", "/config", "/login"],
            "user": context.get("user", {}),
        },
    )


def profile_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    user = context.get("user", {})
    return CommandResult(
        reply=f"{user.get('username', 'guest')}：{user.get('coins', 0)} 金币，身份 {user.get('role', 'customer')}。",
        data={"command": parsed.command, "user": user},
    )


def order_status_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    if not parsed.args:
        return CommandResult(
            reply="请提供订单号，例如：/order_status 1001",
            data={"command": parsed.command, "error": "missing_order_id"},
        )
    return CommandResult(
        reply=f"订单 {parsed.args[0]} 暂无物流更新。如需人工处理，请联系 staff。",
        data={"command": parsed.command, "orderId": parsed.args[0], "status": "pending"},
    )


def _filter_config_fields(obj: dict[str, Any]) -> dict[str, Any]:
    allowed_fields = {"name", "color", "theme", "size", "position"}
    return {key: value for key, value in obj.items() if key in allowed_fields}


def config_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    if not parsed.args:
        return CommandResult(
            reply="请提供 JSON 配置，例如：/config {\"name\": \"Mona\", \"color\": \"gold\"}",
            data={"command": parsed.command, "error": "missing_config"},
        )

    raw_json = " ".join(parsed.args)
    try:
        config_data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        return CommandResult(
            reply=f"JSON 解析失败：{exc.msg}",
            data={"command": parsed.command, "error": "invalid_json"},
        )

    if not isinstance(config_data, dict):
        return CommandResult(
            reply="配置必须是一个 JSON 对象。",
            data={"command": parsed.command, "error": "not_object"},
        )

    sanitized = _filter_config_fields(config_data)
    allowed_fields = {"name", "color", "theme", "size", "position"}
    unknown = set(config_data.keys()) - allowed_fields
    warning = ""
    if unknown:
        warning = f"\n未知字段已忽略：{', '.join(sorted(unknown))}"

    return CommandResult(
        reply=f"配置已保存。{warning}",
        data={"command": parsed.command, "config": sanitized, "user": context.get("user", {})},
    )


def login_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    if not parsed.args:
        return CommandResult(
            reply="请输入 staff-code，例如：/login <staff-code>",
            data={"command": parsed.command, "error": "missing_code"},
        )

    provided = parsed.args[0]
    verifier = context.get("services", {}).get("verify_staff_code")
    if not callable(verifier) or not verifier(context.get("user", {}), provided):
        return CommandResult(
            reply="staff-code 无效或已过期。",
            data={"command": parsed.command, "error": "invalid_code"},
        )

    promote = context.get("services", {}).get("promote_user")
    if not callable(promote):
        return CommandResult(
            reply="staff 登录服务暂不可用。",
            data={"command": parsed.command, "error": "service_unavailable"},
        )

    updated = promote(context.get("user", {}).get("id"), "support_admin")
    return CommandResult(
        reply="登录成功，已激活 support_admin 权限。重新输入 /help 查看 staff 命令。",
        data={"command": parsed.command, "user": updated},
    )


def whoami_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    return CommandResult(
        reply=f"当前身份：{_role(context)}",
        data={"command": parsed.command, "user": context.get("user", {})},
    )


def rulelab_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    if not _is_admin(context):
        return CommandResult(
            reply="权限不足：Rule Lab 仅供 support_admin 使用。",
            data={"command": parsed.command, "error": "permission_denied"},
        )
    return CommandResult(
        reply="Rule Lab 已打开。",
        data={"command": parsed.command, "action": "open_rule_lab", "user": context.get("user", {})},
    )


def qa_reply(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    text = parsed.raw.lower()
    candidates: list[str] = []
    for keywords, replies in QA_PAIRS:
        if any(keyword.lower() in text for keyword in keywords):
            candidates.extend(replies)
    if not candidates:
        candidates = FALLBACK_REPLIES

    user = context.get("user", {})
    prefix = random.choice(["", "", f"{user.get('username', '用户')}，"])
    return CommandResult(
        reply=prefix + random.choice(candidates),
        data={"command": "", "matched": bool(candidates), "user": user},
    )


def unknown_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    return CommandResult(
        reply="未知命令，输入 /help 查看可用命令。",
        data={"command": parsed.command, "args": parsed.args, "user": context.get("user", {})},
    )


COMMANDS: dict[str, CommandHandler] = {
    "/help": help_command,
    "/profile": profile_command,
    "/order_status": order_status_command,
    "/config": config_command,
    "/login": login_command,
    "/whoami": whoami_command,
    "/rulelab": rulelab_command,
}


def execute_command(parsed: ParsedCommand, context: dict[str, Any]) -> CommandResult:
    time.sleep(0.6)
    if not parsed.command:
        return qa_reply(parsed, context)
    handler = COMMANDS.get(parsed.command, unknown_command)
    return handler(parsed, context)


def build_response(result: CommandResult) -> dict[str, Any]:
    return {"reply": result.reply, "status": "complete", "data": result.data}


def handle_bot_message(message: str, context: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_command(message)
    result = execute_command(parsed, context)
    return build_response(result)
