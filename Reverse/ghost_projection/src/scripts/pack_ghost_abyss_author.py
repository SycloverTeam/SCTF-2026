#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Author-side packer for ghost_abyss_hardened.

Purpose:
  1. Patch the core checker source to require a loader_cookie.
  2. Recalibrate enc_final_state_output_v5 so the official flag still prints success
     only when the loader writes the correct cookie.
  3. Strip/clean the inner payload.
  4. Generate a lightweight encrypted ELF loader:
       - encrypted whole-payload blob in outer ELF
       - runtime decrypt
       - manual mmap of inner PT_LOAD segments
       - write loader_cookie to inner payload
       - jump to inner entry
  5. Generate a player directory and optional zip.

This script is intended for CTF challenge authoring only.
It does not implement persistence, injection, networking, or destructive behavior.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import shutil
import stat
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from textwrap import dedent

DEFAULT_FLAG = "sctf{fabsfoagf3432y9adl!fesfsffhoyh345gdhh}"
DEFAULT_SUCCESS = b"Access Granted. You survived the Abyss.\n"
DEFAULT_COOKIE = 0x6A09E667F3BCC909
DEFAULT_COOKIE_MIX = 0xBB67AE8584CAA73B
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MOV_BLOB = PROJECT_ROOT / "assets" / "prime_mov.o"
MOV_BLOB_COOKIE_MIX = 0x4D4F56465553434F


def run(cmd: list[str], *, cwd: Path | None = None, input_data: bytes | None = None,
        timeout: int = 20, capture: bool = False) -> subprocess.CompletedProcess:
    print("[+]", " ".join(map(str, cmd)))
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        input=input_data,
        timeout=timeout,
        check=True,
        capture_output=capture,
    )


def need_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise SystemExit(f"[-] required tool not found: {name}")


def u16(b: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def u32(b: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def u64(b: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def elf_entry(b: bytes | bytearray) -> int:
    return u64(b, 0x18)


def elf_phdrs(b: bytes | bytearray) -> list[dict[str, int]]:
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise ValueError("only ELF64 little-endian is supported")
    phoff = u64(b, 0x20)
    phentsize = u16(b, 0x36)
    phnum = u16(b, 0x38)
    out: list[dict[str, int]] = []
    for i in range(phnum):
        off = phoff + i * phentsize
        out.append({
            "type": u32(b, off),
            "flags": u32(b, off + 4),
            "offset": u64(b, off + 8),
            "vaddr": u64(b, off + 16),
            "paddr": u64(b, off + 24),
            "filesz": u64(b, off + 32),
            "memsz": u64(b, off + 40),
            "align": u64(b, off + 48),
        })
    return out


def vaddr_to_file_offset(b: bytes | bytearray, va: int) -> int:
    for ph in elf_phdrs(b):
        if ph["type"] != 1:  # PT_LOAD
            continue
        start = ph["vaddr"]
        end = start + ph["filesz"]
        if start <= va < end:
            return ph["offset"] + (va - start)
    raise RuntimeError(f"vaddr not backed by file data: 0x{va:x}")


def clean_elf_sections_and_overlay(path: Path) -> tuple[int, int]:
    """Zero section table fields and truncate overlay after last PT_LOAD file byte."""
    b = bytearray(path.read_bytes())
    old_size = len(b)
    end = 0
    for ph in elf_phdrs(b):
        if ph["type"] == 1:
            end = max(end, ph["offset"] + ph["filesz"])
    if end <= 0 or end > len(b):
        raise RuntimeError("bad PT_LOAD end while cleaning ELF")

    # e_shoff, e_shnum, e_shstrndx
    struct.pack_into("<Q", b, 0x28, 0)
    struct.pack_into("<H", b, 0x3C, 0)
    struct.pack_into("<H", b, 0x3E, 0)
    b = b[:end]
    path.write_bytes(b)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return old_size, len(b)


def nm_addr(binary: Path, symbol: str) -> int:
    p = subprocess.run(["nm", "-a", str(binary)], capture_output=True, text=True, check=True)
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] == symbol:
            return int(parts[0], 16)
    raise RuntimeError(f"symbol not found: {symbol}")


def patch_source_text(src: str, cookie: int, cookie_mix: int) -> str:
    if "volatile unsigned long external_loader_cookie" in src:
        raise RuntimeError("source already seems patched")

    src = src.replace(
        "struct AbyssState g;\n",
        "struct AbyssState g;\nvolatile unsigned long external_loader_cookie = 0;\n",
        1,
    )

    target_seed_line = "    k = xorshift64(k + U64(0xD6E8FEB86659FD93));\n"
    inject_seed = (
        f"    k ^= rol64(external_loader_cookie ^ U64(0x{cookie_mix:016X}), 11);\n"
        + target_seed_line
    )
    if target_seed_line not in src:
        raise RuntimeError("cannot find final_output_seed insertion point")
    src = src.replace(target_seed_line, inject_seed, 1)

    target_final_guard = (
        "    FINAL_POISON_IF(&final_poison, g.real_state != U64(0x778C4A416D5EEADF), "
        "U64(0xE001000000000011));\n"
    )
    inject_guard = (
        f"    FINAL_POISON_IF(&final_poison, external_loader_cookie != U64(0x{cookie:016X}), "
        "U64(0xE001000000000019));\n"
        + target_final_guard
    )
    if target_final_guard not in src:
        raise RuntimeError("cannot find final_stage real_state guard insertion point")
    src = src.replace(target_final_guard, inject_guard, 1)
    return src


def write_temp_loader(path: Path, cookie_addr: int, cookie: int) -> None:
    path.write_text(dedent(f"""
    #define _GNU_SOURCE
    #include <errno.h>
    #include <fcntl.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>

    #define COOKIE_ADDR ((uintptr_t)0x{cookie_addr:016X}ULL)
    #define COOKIE_VAL  ((uint64_t)0x{cookie:016X}ULL)
    #define PAGE_MASK   (~(uintptr_t)0xfffULL)

    static uint64_t rd64(const unsigned char *p) {{ uint64_t v; memcpy(&v, p, 8); return v; }}
    static uint32_t rd32(const unsigned char *p) {{ uint32_t v; memcpy(&v, p, 4); return v; }}
    static uint16_t rd16(const unsigned char *p) {{ uint16_t v; memcpy(&v, p, 2); return v; }}
    static void die(void) {{ _exit(111); }}
    static int prot_from_flags(unsigned f) {{ int p = 0; if (f & 4) p |= PROT_READ; if (f & 2) p |= PROT_WRITE; if (f & 1) p |= PROT_EXEC; return p; }}

    int main(int argc, char **argv) {{
        if (argc < 2) {{ write(2, "usage: temp_loader payload\\n", 27); return 2; }}
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) die();
        struct stat st;
        if (fstat(fd, &st)) die();
        unsigned char *buf = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED) die();

        uintptr_t entry = (uintptr_t)rd64(buf + 0x18);
        uint64_t phoff = rd64(buf + 0x20);
        uint16_t phentsz = rd16(buf + 0x36), phnum = rd16(buf + 0x38);

        for (unsigned i = 0; i < phnum; i++) {{
            unsigned char *ph = buf + phoff + (uint64_t)i * phentsz;
            uint32_t type = rd32(ph), flags = rd32(ph + 4);
            if (type != 1) continue;
            uint64_t off = rd64(ph + 8), va = rd64(ph + 16), filesz = rd64(ph + 32), memsz = rd64(ph + 40);
            uintptr_t start = (uintptr_t)va & PAGE_MASK;
            uintptr_t end = ((uintptr_t)va + memsz + 0xfffULL) & PAGE_MASK;
            void *m = mmap((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (m == MAP_FAILED) die();
            memcpy((void *)(uintptr_t)va, buf + off, filesz);
            if (memsz > filesz) memset((void *)(uintptr_t)(va + filesz), 0, memsz - filesz);
        }}

        *(volatile uint64_t *)COOKIE_ADDR = COOKIE_VAL;

        for (unsigned i = 0; i < phnum; i++) {{
            unsigned char *ph = buf + phoff + (uint64_t)i * phentsz;
            uint32_t type = rd32(ph), flags = rd32(ph + 4);
            if (type != 1) continue;
            uint64_t va = rd64(ph + 16), memsz = rd64(ph + 40);
            uintptr_t start = (uintptr_t)va & PAGE_MASK;
            uintptr_t end = ((uintptr_t)va + memsz + 0xfffULL) & PAGE_MASK;
            if (mprotect((void *)start, end - start, prot_from_flags(flags))) die();
        }}

        void (*fn)(void) = (void (*)(void))entry;
        fn();
        return 0;
    }}
    """))


def xs64(s: int) -> int:
    s = (s ^ ((s << 13) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    s = (s ^ (s >> 7)) & 0xFFFFFFFFFFFFFFFF
    s = (s ^ ((s << 17) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    return s


def crypt_blob(data: bytes, cookie: int) -> bytes:
    st_a = (cookie ^ 0xD1B54A32D192ED03) & 0xFFFFFFFFFFFFFFFF
    st_b = ((~cookie) ^ 0xA24BAED4963EE407) & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    block_a = 0
    block_b = 0
    for i, ch in enumerate(data):
        if (i & 7) == 0:
            st_a = xs64((st_a + 0x9E3779B97F4A7C15 + i) & 0xFFFFFFFFFFFFFFFF)
            st_b = xs64((st_b ^ st_a ^ 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF)
            block_a = st_a
            block_b = ((st_b << 17) | (st_b >> 47)) & 0xFFFFFFFFFFFFFFFF
        k = ((block_a >> ((i & 7) * 8)) ^ (block_b >> (((i + 3) & 7) * 8)) ^ (i * 0x5D + 0xA7)) & 0xFF
        out.append(ch ^ k)
    return bytes(out)


def payload_hash(data: bytes, cookie: int) -> int:
    h = (0xCBF29CE484222325 ^ cookie) & 0xFFFFFFFFFFFFFFFF
    for i, ch in enumerate(data):
        h ^= ch
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        h ^= (h >> 32)
        h ^= (i * 0x9E3779B1) & 0xFFFFFFFFFFFFFFFF
    return h & 0xFFFFFFFFFFFFFFFF


def scatter_blob(data: bytes) -> tuple[bytes, int, int]:
    n = len(data)
    add = 0x2D3
    mul = 0x9E37
    while math.gcd(mul, n) != 1:
        mul += 2
    out = bytearray(n)
    for i, ch in enumerate(data):
        out[(i * mul + add) % n] = ch
    return bytes(out), mul, add


def c_array(name: str, data: bytes, cols: int = 16) -> str:
    lines = []
    for i in range(0, len(data), cols):
        lines.append("    " + ", ".join(f"0x{x:02x}" for x in data[i:i + cols]) + ",")
    return f"static const unsigned char {name}[{len(data)}] = {{\n" + "\n".join(lines) + "\n};\n"


def write_zip_tree(zip_path: Path, root: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root.parent)
            if path.is_dir():
                info = zipfile.ZipInfo(str(rel).rstrip("/") + "/")
                info.external_attr = 0o755 << 16
                zf.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(str(rel))
            mode = path.stat().st_mode & 0o777
            info.external_attr = mode << 16
            zf.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def write_outer_loader(path: Path, enc_payload: bytes, enc_mov_blob: bytes, cookie: int,
                       cookie_addr: int, payload_hash_value: int, mov_blob_hash_value: int,
                       scatter_mul: int, scatter_add: int) -> None:
    blob = c_array("enc_payload", enc_payload)
    mov_blob = c_array("enc_mov_blob", enc_mov_blob)
    path.write_text(dedent(f"""
    #define _GNU_SOURCE
    #include <stdint.h>
    #include <stddef.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/mman.h>
    #include <unistd.h>

    #define PACK_COOKIE 0x{cookie:016X}ULL
    #define COOKIE_ADDR ((uintptr_t)0x{cookie_addr:016X}ULL)
    #define PAYLOAD_HASH 0x{payload_hash_value:016X}ULL
    #define MOV_BLOB_HASH 0x{mov_blob_hash_value:016X}ULL
    #define MOV_BLOB_KEY (PACK_COOKIE ^ 0x{MOV_BLOB_COOKIE_MIX:016X}ULL)
    #define SCATTER_MUL ((size_t){scatter_mul}ULL)
    #define SCATTER_ADD ((size_t){scatter_add}ULL)
    #define PAGE_MASK (~(uintptr_t)0xfffULL)

    {blob}
    {mov_blob}

    static uint64_t rd64(const unsigned char *p) {{ uint64_t v; memcpy(&v, p, 8); return v; }}
    static uint32_t rd32(const unsigned char *p) {{ uint32_t v; memcpy(&v, p, 4); return v; }}
    static uint16_t rd16(const unsigned char *p) {{ uint16_t v; memcpy(&v, p, 2); return v; }}
    static uint64_t xs(uint64_t s) {{ s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }}
    static uint64_t rol64_local(uint64_t x, unsigned r) {{ return (x << r) | (x >> (64 - r)); }}
    static void die(void) {{ _exit(111); }}
    static int prot_from_flags(unsigned f) {{ int p = 0; if (f & 4) p |= PROT_READ; if (f & 2) p |= PROT_WRITE; if (f & 1) p |= PROT_EXEC; return p; }}

    static void decrypt_payload(unsigned char *dst) {{
        uint64_t st_a = PACK_COOKIE ^ 0xD1B54A32D192ED03ULL;
        uint64_t st_b = (~PACK_COOKIE) ^ 0xA24BAED4963EE407ULL;
        uint64_t block_a = 0, block_b = 0;
        for (size_t i = 0; i < sizeof(enc_payload); i++) {{
            if ((i & 7) == 0) {{
                st_a = xs(st_a + 0x9E3779B97F4A7C15ULL + i);
                st_b = xs(st_b ^ st_a ^ 0xBF58476D1CE4E5B9ULL);
                block_a = st_a;
                block_b = rol64_local(st_b, 17);
            }}
            unsigned char k = (unsigned char)(((block_a >> ((i & 7) * 8)) ^
                                               (block_b >> (((i + 3) & 7) * 8)) ^
                                               (i * 0x5dU + 0xa7U)) & 0xffU);
            size_t src_i = (i * SCATTER_MUL + SCATTER_ADD) % sizeof(enc_payload);
            dst[i] = (unsigned char)(enc_payload[src_i] ^ k);
        }}
    }}

    static void decrypt_mov_blob(unsigned char *dst) {{
        uint64_t st_a = MOV_BLOB_KEY ^ 0xD1B54A32D192ED03ULL;
        uint64_t st_b = (~MOV_BLOB_KEY) ^ 0xA24BAED4963EE407ULL;
        uint64_t block_a = 0, block_b = 0;
        for (size_t i = 0; i < sizeof(enc_mov_blob); i++) {{
            if ((i & 7) == 0) {{
                st_a = xs(st_a + 0x9E3779B97F4A7C15ULL + i);
                st_b = xs(st_b ^ st_a ^ 0xBF58476D1CE4E5B9ULL);
                block_a = st_a;
                block_b = rol64_local(st_b, 17);
            }}
            unsigned char k = (unsigned char)(((block_a >> ((i & 7) * 8)) ^
                                               (block_b >> (((i + 3) & 7) * 8)) ^
                                               (i * 0x5dU + 0xa7U)) & 0xffU);
            dst[i] = (unsigned char)(enc_mov_blob[i] ^ k);
        }}
    }}

    static uint64_t hash_payload(const unsigned char *p, size_t n) {{
        uint64_t h = 0xCBF29CE484222325ULL ^ PACK_COOKIE;
        for (size_t i = 0; i < n; i++) {{
            h ^= p[i];
            h *= 0x100000001B3ULL;
            h ^= h >> 32;
            h ^= (uint64_t)i * 0x9E3779B1ULL;
        }}
        return h;
    }}

    static uint64_t probe_mov_blob(const unsigned char *p, size_t n) {{
        if (n < 0x34) return 0;
        if (p[0] != 0x7f || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') return 0;
        if (p[4] != 1 || p[5] != 1) return 0;
        if (rd16(p + 0x10) != 1 || rd16(p + 0x12) != 3) return 0;

        uint64_t score = 0;
        for (size_t i = 0; i < n; i++) {{
            unsigned char x = p[i];
            if (x == 0x88 || x == 0x89 || x == 0x8a || x == 0x8b ||
                x == 0xa0 || x == 0xa1 || x == 0xa2 || x == 0xa3 ||
                x == 0xc6 || x == 0xc7 || (x >= 0xb0 && x <= 0xbf)) {{
                score++;
            }}
        }}
        if (score < (n / 32)) return 0;
        return score ^ ((uint64_t)n << 17) ^ 0xC001D00D4D4F5601ULL;
    }}

    __attribute__((noreturn)) static void call_payload(uintptr_t entry) {{
        __asm__ volatile(
            "mov %[cookie], %%r12\\n"
            "call *%[entry]\\n"
            :
            : [cookie] "r" ((uint64_t)PACK_COOKIE), [entry] "r" ((void *)entry)
            : "r12", "memory");
        _exit(0);
    }}

    int main(void) {{
        unsigned char *mov_buf = (unsigned char *)malloc(sizeof(enc_mov_blob));
        if (!mov_buf) die();
        decrypt_mov_blob(mov_buf);
        if (hash_payload(mov_buf, sizeof(enc_mov_blob)) != MOV_BLOB_HASH) die();
        if (probe_mov_blob(mov_buf, sizeof(enc_mov_blob)) == 0) die();
        free(mov_buf);

        unsigned char *buf = (unsigned char *)malloc(sizeof(enc_payload));
        if (!buf) die();
        decrypt_payload(buf);
        if (hash_payload(buf, sizeof(enc_payload)) != PAYLOAD_HASH) die();
        if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') die();

        uintptr_t entry = (uintptr_t)rd64(buf + 0x18);
        uint64_t phoff = rd64(buf + 0x20);
        uint16_t phentsz = rd16(buf + 0x36), phnum = rd16(buf + 0x38);

        for (unsigned i = 0; i < phnum; i++) {{
            unsigned char *ph = buf + phoff + (uint64_t)i * phentsz;
            uint32_t type = rd32(ph), flags = rd32(ph + 4);
            if (type != 1) continue;
            uint64_t off = rd64(ph + 8), va = rd64(ph + 16), filesz = rd64(ph + 32), memsz = rd64(ph + 40);
            uintptr_t start = (uintptr_t)va & PAGE_MASK;
            uintptr_t end = ((uintptr_t)va + memsz + 0xfffULL) & PAGE_MASK;
            void *m = mmap((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (m == MAP_FAILED) die();
            memcpy((void *)(uintptr_t)va, buf + off, filesz);
            if (memsz > filesz) memset((void *)(uintptr_t)(va + filesz), 0, memsz - filesz);
        }}

        *(volatile uint64_t *)COOKIE_ADDR = PACK_COOKIE;

        for (unsigned i = 0; i < phnum; i++) {{
            unsigned char *ph = buf + phoff + (uint64_t)i * phentsz;
            uint32_t type = rd32(ph), flags = rd32(ph + 4);
            if (type != 1) continue;
            uint64_t va = rd64(ph + 16), memsz = rd64(ph + 40);
            uintptr_t start = (uintptr_t)va & PAGE_MASK;
            uintptr_t end = ((uintptr_t)va + memsz + 0xfffULL) & PAGE_MASK;
            if (mprotect((void *)start, end - start, prot_from_flags(flags))) die();
        }}

        call_payload(entry);
    }}
    """))



def compile_outer_loader(outdir: Path, loader_c: Path, packed: Path,
                         payload_data: bytes, cookie: int, cookie_addr: int,
                         mov_blob_data: bytes) -> None:
    enc_payload = crypt_blob(payload_data, cookie)
    assert crypt_blob(enc_payload, cookie) == payload_data
    enc_mov_blob = crypt_blob(mov_blob_data, cookie ^ MOV_BLOB_COOKIE_MIX)
    assert crypt_blob(enc_mov_blob, cookie ^ MOV_BLOB_COOKIE_MIX) == mov_blob_data
    scattered, scatter_mul, scatter_add = scatter_blob(enc_payload)
    unscatter = bytearray(len(scattered))
    for i in range(len(scattered)):
        unscatter[i] = scattered[(i * scatter_mul + scatter_add) % len(scattered)]
    assert bytes(unscatter) == enc_payload
    write_outer_loader(loader_c, scattered, enc_mov_blob, cookie, cookie_addr,
                       payload_hash(payload_data, cookie), payload_hash(mov_blob_data, cookie),
                       scatter_mul, scatter_add)
    run([
        "gcc", "-O2", "-fPIE", "-pie", "-fno-stack-protector",
        "-o", str(packed), str(loader_c),
    ], cwd=outdir, timeout=60)
    run(["strip", "-s", str(packed)])
    old_sz, new_sz = clean_elf_sections_and_overlay(packed)
    print(f"[+] outer loader cleaned: {old_sz} -> {new_sz} bytes")


def build(args: argparse.Namespace) -> None:
    for t in ("gcc", "nm", "strip"):
        need_tool(t)

    source = args.source.resolve()
    header = args.header.resolve()
    outdir = args.outdir.resolve()
    flag_line = (args.flag + "\n").encode()
    success = args.success.encode() + (b"\n" if not args.success.endswith("\n") else b"")
    cookie = int(args.cookie, 0)
    cookie_mix = int(args.cookie_mix, 0)
    mov_blob_path = args.mov_blob.resolve()
    if not mov_blob_path.exists():
        raise SystemExit(f"[-] mov blob not found: {mov_blob_path}")
    mov_blob_data = mov_blob_path.read_bytes()
    if len(mov_blob_data) < 0x34 or mov_blob_data[:4] != b"\x7fELF" or mov_blob_data[4] != 1:
        raise SystemExit(f"[-] mov blob is not an ELF32 file: {mov_blob_path}")

    if outdir.exists():
        if args.force:
            shutil.rmtree(outdir)
        else:
            raise SystemExit(f"[-] output directory exists: {outdir}; use --force")
    outdir.mkdir(parents=True)

    print(f"[+] workdir: {outdir}")
    print(f"[+] mov blob: {mov_blob_path} ({len(mov_blob_data)} bytes)")
    shutil.copy2(header, outdir / "ghost_step30_generated.h")

    src_text = source.read_text()
    patched = patch_source_text(src_text, cookie, cookie_mix)
    payload_c = outdir / "payload_cookie.c"
    payload_c.write_text(patched)

    payload_sym = outdir / "payload_cookie.sym"
    compile_payload = [
        "gcc", "-std=gnu11", "-Og", "-ffreestanding", "-fno-builtin", "-nostdlib", "-static",
        "-no-pie", "-fno-pie", "-fno-stack-protector",
        "-fno-strict-aliasing", "-fno-optimize-sibling-calls",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-Wl,-z,execstack",
        "-o", str(payload_sym), str(payload_c),
    ]
    run(compile_payload, cwd=outdir, timeout=60)

    cookie_addr = nm_addr(payload_sym, "external_loader_cookie")
    enc_addr = nm_addr(payload_sym, "enc_final_state_output_v5")
    print(f"[+] external_loader_cookie: 0x{cookie_addr:x}")
    print(f"[+] enc_final_state_output_v5: 0x{enc_addr:x}")

    # Strip and clean the uncalibrated inner payload first. Calibration is done
    # against the real outer-loader execution path, not against temp_loader.
    payload_uncalib = outdir / "payload_cookie.uncalib"
    shutil.copy2(payload_sym, payload_uncalib)
    run(["strip", "-s", str(payload_uncalib)])
    old_sz, new_sz = clean_elf_sections_and_overlay(payload_uncalib)
    print(f"[+] uncalibrated inner payload cleaned: {old_sz} -> {new_sz} bytes")

    # Direct inner payload should not pass because no loader cookie is written.
    p_direct = run([str(payload_uncalib)], input_data=flag_line, timeout=15, capture=True)
    if success in p_direct.stdout:
        raise RuntimeError("uncalibrated direct payload unexpectedly prints success")
    print("[+] direct inner payload without loader cookie: not accepted")

    # Build a temporary outer loader with uncalibrated payload, then run official
    # flag to learn the exact wrong 40-byte final output under the outer-loader path.
    outer_uncalib = outdir / "ghost_abyss_hardened.uncalib_outer"
    loader_uncalib_c = outdir / "ghost_abyss_packed_loader_uncalib.c"
    compile_outer_loader(outdir, loader_uncalib_c, outer_uncalib, payload_uncalib.read_bytes(),
                         cookie, cookie_addr, mov_blob_data)

    samples = []
    for i in range(3):
        p = run([str(outer_uncalib)], input_data=flag_line, timeout=15, capture=True)
        if len(p.stdout) < len(success):
            raise RuntimeError(f"unexpected uncalibrated outer output: {p.stdout!r}")
        samples.append(p.stdout[-len(success):])
    if samples[0] != samples[1] or samples[0] != samples[2]:
        raise RuntimeError("outer calibration output is unstable across runs")
    actual = samples[0]
    print(f"[+] outer calibration suffix: {actual.hex()}")

    # Patch enc_final_state_output_v5 in the cleaned inner payload so that the
    # outer-loader path decrypts to the desired success line.
    inner = bytearray(payload_uncalib.read_bytes())
    enc_off = vaddr_to_file_offset(inner, enc_addr)
    old = bytes(inner[enc_off:enc_off + len(success)])
    if len(old) != len(success):
        raise RuntimeError("enc_final_state_output_v5 too short for success output")
    new = bytes(old[i] ^ actual[i] ^ success[i] for i in range(len(success)))
    inner[enc_off:enc_off + len(success)] = new

    payload_clean = outdir / "payload_cookie.clean"
    payload_clean.write_bytes(inner)
    payload_clean.chmod(0o755)

    # Verify direct inner payload still cannot succeed.
    p_direct = run([str(payload_clean)], input_data=flag_line, timeout=15, capture=True)
    if success in p_direct.stdout:
        raise RuntimeError("calibrated direct payload succeeded without loader cookie; binding failed")
    print("[+] calibrated direct inner payload without loader cookie: not accepted")

    # Build final packed binary from calibrated inner payload.
    loader_c = outdir / "ghost_abyss_packed_loader.c"
    packed = outdir / args.output_name
    compile_outer_loader(outdir, loader_c, packed, payload_clean.read_bytes(),
                         cookie, cookie_addr, mov_blob_data)

    # Test official flag and wrong input several times for stability.
    for i in range(3):
        p = run([str(packed)], input_data=flag_line, timeout=15, capture=True)
        if success not in p.stdout:
            print(p.stdout, p.stderr, file=sys.stderr)
            raise RuntimeError("packed binary failed official flag test")
    print("[+] packed binary official flag test: OK")

    p = run([str(packed)], input_data=b"testflag\n", timeout=15, capture=True)
    if success in p.stdout:
        raise RuntimeError("packed binary accepted wrong test input")
    print("[+] packed binary wrong-input test: OK")

    # Player package
    player_dir = outdir / args.package_name
    player_dir.mkdir()
    shutil.copy2(packed, player_dir / args.output_name)
    (player_dir / args.output_name).chmod(0o755)

    (player_dir / "Dockerfile").write_text(dedent(f"""
    FROM --platform=linux/amd64 ubuntu:22.04
    WORKDIR /chal
    COPY {args.output_name} /chal/{args.output_name}
    RUN chmod +x /chal/{args.output_name}
    CMD ["/bin/bash"]
    """).lstrip())

    (player_dir / "README.md").write_text(dedent(f"""
    # ghost_abyss_hardened

    ## Run

    ```bash
    chmod +x {args.output_name}
    ./{args.output_name}
    ```

    ## Docker

    ```bash
    docker build -t ghost-abyss-packed .
    docker run --rm -it ghost-abyss-packed
    ```

    Non-interactive example:

    ```bash
    printf 'your_flag_here\\n' | docker run --rm -i ghost-abyss-packed /chal/{args.output_name}
    ```
    """).lstrip())

    print(f"[+] player dir: {player_dir}")

    if args.zip:
        zip_path = outdir.parent / f"{args.package_name}.zip"
        if zip_path.exists():
            zip_path.unlink()
        write_zip_tree(zip_path, player_dir)
        print(f"[+] zip: {zip_path}")
        print(f"[+] zip sha256: {hashlib.sha256(zip_path.read_bytes()).hexdigest()}")

    print(f"[+] final sha256: {hashlib.sha256(packed.read_bytes()).hexdigest()}")
    print("[+] done")

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Author-side packer for ghost_abyss_hardened CTF challenge."
    )
    ap.add_argument("--source", type=Path, required=True, help="core checker C source")
    ap.add_argument("--header", type=Path, required=True, help="ghost_step30_generated.h")
    ap.add_argument("--outdir", type=Path, default=Path("build_packed"), help="build output directory")
    ap.add_argument("--flag", default=DEFAULT_FLAG, help="official flag, without trailing newline")
    ap.add_argument("--success", default=DEFAULT_SUCCESS.decode().rstrip("\n"), help="success line, without trailing newline")
    ap.add_argument("--cookie", default=hex(DEFAULT_COOKIE), help="loader cookie, e.g. 0x...")
    ap.add_argument("--cookie-mix", default=hex(DEFAULT_COOKIE_MIX), help="cookie mix constant")
    ap.add_argument("--mov-blob", type=Path, default=DEFAULT_MOV_BLOB, help="ELF32 movfuscated blob embedded by the outer loader")
    ap.add_argument("--output-name", default="ghost_abyss_hardened", help="final binary name")
    ap.add_argument("--package-name", default="ghost_step40_route_projection_packed_player", help="player package directory name")
    ap.add_argument("--zip", action="store_true", help="also produce package zip next to outdir")
    ap.add_argument("--force", action="store_true", help="delete outdir if it exists")
    args = ap.parse_args()
    build(args)


if __name__ == "__main__":
    main()
