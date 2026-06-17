#!/usr/bin/env python3
import errno
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP


APP_ROOT = Path(__file__).resolve().parent
SANDBOX = APP_ROOT / "sandbox_eval.py"
MAX_STDIN_BYTES = 4096
TIMEOUT = 8

mcp = FastMCP(
    "sandbox-eval",
    instructions="sandbox python runner",
    log_level="ERROR",
)


def set_terminal_size(fd: int, rows: int = 30, cols: int = 120) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except OSError:
        pass


def run_sandbox_with_pty(stdin: str) -> str:
    data = stdin.encode()
    output = bytearray()
    env = {
        "HOME": "/tmp",
        "LC_ALL": "C.UTF-8",
        "LESS": "-R -X",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PAGER": "less",
        "PYTHONIOENCODING": "utf-8",
        "TERM": "xterm",
    }
    argv = [sys.executable, "-u", str(SANDBOX)]

    try:
        pid, master_fd = pty.fork()
    except OSError as exc:
        return f"pty failed: {exc}\n"

    if pid == 0:
        try:
            os.chdir(APP_ROOT)
            os.execve(sys.executable, argv, env)
        except Exception as exc:
            print(f"exec failed: {exc}", flush=True)
            os._exit(127)

    set_terminal_size(master_fd)
    os.set_blocking(master_fd, False)

    deadline = time.monotonic() + TIMEOUT
    child_done = False
    timed_out = False

    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break

            if not child_done:
                try:
                    done_pid, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    child_done = True
                else:
                    child_done = done_pid == pid

            read_list = [master_fd]
            write_list = [master_fd] if data and not child_done else []
            wait = 0 if child_done else min(0.05, deadline - now)

            try:
                readable, writable, _ = select.select(read_list, write_list, [], wait)
            except OSError:
                break

            if master_fd in writable and data:
                try:
                    written = os.write(master_fd, data[:1024])
                    data = data[written:]
                except BlockingIOError:
                    pass
                except OSError:
                    data = b""

            if master_fd in readable:
                try:
                    chunk = os.read(master_fd, 4096)
                except BlockingIOError:
                    chunk = b""
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if chunk:
                    output.extend(chunk)
                elif child_done:
                    break
            elif child_done:
                break
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
        if not child_done:
            try:
                done_pid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                if done_pid == 0:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass

    text = output.decode("utf-8", "replace")
    if timed_out:
        text += "\nsandbox_eval timed out\n"
    return text[:12000] + ("\n[truncated]\n" if len(text) > 12000 else "")


@mcp.tool(
    name="sandbox_eval",
    description="Evaluate one short diagnostic expression in a restricted Python sandbox.",
)
def sandbox_eval(stdin: str) -> str:
    """Run the sandbox process with complete stdin supplied by the caller."""
    if not isinstance(stdin, str):
        return "stdin must be a string\n"
    if len(stdin.encode()) > MAX_STDIN_BYTES:
        return "stdin too large\n"
    return run_sandbox_with_pty(stdin)


if __name__ == "__main__":
    os.chdir(APP_ROOT)
    mcp.run(transport="stdio")
