#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import platform
import struct
import subprocess
from pathlib import Path


FLAG_LEN = 43
DEFAULT_INPUT = b"A" * FLAG_LEN + b"\n"

EXP_DIR = Path(__file__).resolve().parent

GATE_PATCHES = (
    (0x42E020, 0xE4, "route_projection_runtime_b.beta_enc"),
    (0x42E022, 0xB2, "route_projection_runtime_b.arm_enc"),
    (0x42E040, 0xF3, "route_projection_runtime_a.alpha_enc"),
    (0x42E110, 0x5E, "route_projection_gate_b.phase_enc"),
    (0x42E112, 0x93, "route_projection_gate_b.lane_enc"),
    (0x42E130, 0xA7, "route_projection_gate_a.bias_enc"),
)

EPOCH_GATE_VA = 0x42E060
HOOK_VA = 0x4141DD
HOOK_BACK_VA = 0x4141E3
CAVE_VA = 0x4286C4
RX_LOAD_VA = 0x401000
RX_LOAD_NEW_SIZE = 0x28000
RECORD_MAGIC = b"OCAFLOG0"
RECORD_SIZE = 0x28


def va_to_file_offset(elf: bytes, va: int) -> int:
    if elf[:4] != b"\x7fELF" or elf[4] != 2:
        raise SystemExit("expected ELF64")

    e_phoff = struct.unpack_from("<Q", elf, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", elf, 0x36)[0]
    e_phnum = struct.unpack_from("<H", elf, 0x38)[0]
    for i in range(e_phnum):
        phoff = e_phoff + i * e_phentsize
        p_type, _p_flags = struct.unpack_from("<II", elf, phoff)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from("<QQQQQQ", elf, phoff + 8)
        if p_type != 1:
            continue
        if p_vaddr <= va < p_vaddr + p_memsz:
            off = p_offset + (va - p_vaddr)
            if off >= p_offset + p_filesz:
                return off
            return off
    raise SystemExit(f"VA 0x{va:x} is not covered by any PT_LOAD")


def expand_rx_load(elf: bytearray) -> None:
    e_phoff = struct.unpack_from("<Q", elf, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", elf, 0x36)[0]
    e_phnum = struct.unpack_from("<H", elf, 0x38)[0]
    for i in range(e_phnum):
        phoff = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", elf, phoff)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from("<QQQQQQ", elf, phoff + 8)
        if p_type == 1 and p_vaddr == RX_LOAD_VA and (p_flags & 1):
            new_file_end = p_offset + RX_LOAD_NEW_SIZE
            if len(elf) < new_file_end:
                elf.extend(b"\x00" * (new_file_end - len(elf)))
            struct.pack_into("<Q", elf, phoff + 0x20, max(p_filesz, RX_LOAD_NEW_SIZE))
            struct.pack_into("<Q", elf, phoff + 0x28, max(p_memsz, RX_LOAD_NEW_SIZE))
            return
    raise SystemExit("RX PT_LOAD not found")


def movabs_r10_imm64(value: int) -> bytes:
    return b"\x49\xBA" + struct.pack("<Q", value)


def build_logger() -> bytes:
    code = bytearray()
    code += b"\x48\x81\xEC\x80\x00\x00\x00"      # sub rsp, 0x80
    code += b"\x48\x89\x04\x24"                  # mov [rsp+0], rax
    code += b"\x48\x89\x5C\x24\x08"              # mov [rsp+8], rbx
    code += movabs_r10_imm64(0x30474F4C4641434F)  # "OCAFLOG0"
    code += b"\x4C\x89\x54\x24\x20"              # mov [rsp+0x20], r10
    code += b"\x48\x89\x6C\x24\x28"              # mov [rsp+0x28], rbp
    code += b"\x4C\x89\x64\x24\x30"              # mov [rsp+0x30], r12
    code += b"\x48\x89\x44\x24\x38"              # mov [rsp+0x38], rax
    code += b"\x0F\xB6\x45\x09\x88\x44\x24\x40"  # logical position
    code += b"\x0F\xB6\x45\x10\x88\x44\x24\x41"  # phase
    code += b"\x0F\xB6\x45\x16\x88\x44\x24\x42"  # hidden idx
    code += b"\x0F\xB6\x45\x20\x88\x44\x24\x43"  # staged input byte
    code += b"\xB8\x01\x00\x00\x00"              # mov eax, 1
    code += b"\xBF\x02\x00\x00\x00"              # mov edi, 2
    code += b"\x48\x8D\x74\x24\x20"              # lea rsi, [rsp+0x20]
    code += b"\xBA\x28\x00\x00\x00"              # mov edx, 0x28
    code += b"\x0F\x05"                          # syscall
    code += b"\x48\x8B\x04\x24"                  # mov rax, [rsp+0]
    code += b"\x48\x8B\x5C\x24\x08"              # mov rbx, [rsp+8]
    code += b"\x48\x81\xC4\x80\x00\x00\x00"      # add rsp, 0x80
    code += b"\x32\x45\x20"                      # xor al, [rbp+0x20]
    code += b"\x44\x31\xE0"                      # xor eax, r12d
    code += movabs_r10_imm64(HOOK_BACK_VA)
    code += b"\x41\xFF\xE2"                      # jmp r10
    return bytes(code)


def patch_one_epoch(base: bytes, epoch: int, out_path: Path) -> None:
    elf = bytearray(base)
    expand_rx_load(elf)

    for va, value, _name in GATE_PATCHES:
        elf[va_to_file_offset(elf, va)] = value
    elf[va_to_file_offset(elf, EPOCH_GATE_VA)] = epoch ^ 0x22

    cave_off = va_to_file_offset(elf, CAVE_VA)
    logger = build_logger()
    elf[cave_off:cave_off + len(logger)] = logger

    hook_off = va_to_file_offset(elf, HOOK_VA)
    rel = CAVE_VA - (HOOK_VA + 5)
    elf[hook_off:hook_off + 6] = b"\xE9" + struct.pack("<i", rel) + b"\x90"

    out_path.write_bytes(elf)
    out_path.chmod(0o755)


def parse_records(stderr: bytes) -> dict[int, int]:
    recovered: dict[int, int] = {}
    i = 0
    while True:
        pos = stderr.find(RECORD_MAGIC, i)
        if pos < 0:
            break
        rec = stderr[pos:pos + RECORD_SIZE]
        if len(rec) < RECORD_SIZE:
            break
        raw_ret = struct.unpack_from("<Q", rec, 0x18)[0]
        hidden_idx = rec[0x22]
        if hidden_idx < FLAG_LEN:
            recovered[hidden_idx] = raw_ret & 0xFF
        i = pos + RECORD_SIZE
    return recovered


def run_epoch(path: Path) -> dict[int, int]:
    proc = subprocess.run(
        [str(path)],
        input=DEFAULT_INPUT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    return parse_records(proc.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description="Patch route-projection oracle and recover the hidden bytes.")
    ap.add_argument("stage2", nargs="?", type=Path, default=EXP_DIR / "stage2_payload_loaderfixed.elf")
    ap.add_argument("-o", "--out-dir", type=Path, default=EXP_DIR / "oracle_epochs")
    ap.add_argument("--no-run", action="store_true", help="only generate patched ELF files")
    args = ap.parse_args()

    base = args.stage2.read_bytes()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    merged: dict[int, int] = {}
    can_run = platform.system() == "Linux" and os.access(args.stage2, os.X_OK)
    for epoch in range(4):
        out_path = args.out_dir / f"oracle_epoch_{epoch}.elf"
        patch_one_epoch(base, epoch, out_path)
        print(f"[+] epoch {epoch}: wrote {out_path}")

        if not args.no_run and can_run:
            rows = run_epoch(out_path)
            print(f"[+] epoch {epoch}: leaked {len(rows)} byte(s)")
            for idx, value in rows.items():
                if (idx & 3) == epoch:
                    merged[idx] = value

    if args.no_run or not can_run:
        print("[!] patched ELF files generated; run this script on Linux without --no-run to execute and recover flag")
        return

    missing = [i for i in range(FLAG_LEN) if i not in merged]
    if missing:
        raise SystemExit(f"missing leaked indexes: {missing}")
    flag = bytes(merged[i] for i in range(FLAG_LEN))
    print(f"flag_hex = {flag.hex()}")
    print(f"flag = {flag.decode('ascii', errors='replace')}")


if __name__ == "__main__":
    main()
