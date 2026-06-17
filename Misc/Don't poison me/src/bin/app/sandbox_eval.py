#!/usr/bin/env python3
import sys


ALLOWED = "abcdefghijklmnopqrstuvwxyz:_.[]"
MAX_INPUT = 60


def main() -> None:
    try:
        raw = input("> ")
    except EOFError:
        print("no input")
        return

    if len(raw) > MAX_INPUT:
        print("input too long")
        return

    code = "".join(ch for ch in raw if ch in ALLOWED)
    try:
        result = eval(code, {"__builtins__": __builtins__}, {})
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}")
        return

    if result is not None:
        print("ok")


if __name__ == "__main__":
    sys.path.insert(0, ".")
    main()
