#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


MASK64 = (1 << 64) - 1

EXP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = EXP_DIR.parent
DEFAULT_PACKED = PROJECT_ROOT / "src" / "player" / "ghost_abyss_hardened"

ENC_PAYLOAD_OFF = 0x13520
ENC_PAYLOAD_SIZE = 0x2E13C
COOKIE_VA = 0x42F000
COOKIE_VALUE = 0x6A09E667F3BCC909


def xorshift64(v: int) -> int:
    v &= MASK64
    v ^= (v << 13) & MASK64
    v ^= v >> 7
    v ^= (v << 17) & MASK64
    return v & MASK64


def digest(data: bytes) -> tuple[str, str]:
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


def decrypt_stage2(packed: bytes) -> bytes:
    src = packed[ENC_PAYLOAD_OFF:ENC_PAYLOAD_OFF + ENC_PAYLOAD_SIZE]
    if len(src) != ENC_PAYLOAD_SIZE:
        raise SystemExit("packed file is too small for the encrypted stage2 blob")

    out = bytearray(ENC_PAYLOAD_SIZE)
    r10 = (-89) & 0xFFFFFFFF
    r9 = 0x2D3
    r11 = 0
    r8 = 0x37BDB74C9A7DD2F1
    rdi = 0xBBBCAC55222E240A
    r14 = 0x9E3779B97F4A7C15
    r13 = 0xBF58476D1CE4E5B9
    rbx = 0

    for i in range(ENC_PAYLOAD_SIZE):
        if (i & 7) == 0:
            rdi = xorshift64(i + rdi + r14)
            r8 ^= rdi
            r11 = rdi
            r8 ^= r13
            r8 = xorshift64(r8)
            rbx = ((r8 << 17) | (r8 >> (64 - 17))) & MASK64

        src_i = r9 % ENC_PAYLOAD_SIZE
        r9 = (r9 + 0x9E37) & MASK64
        edx = src[src_i] ^ r10
        r10 = (r10 + 0x5D) & 0xFFFFFFFF
        eax = edx ^ ((r11 >> ((i & 7) * 8)) & 0xFFFFFFFF)
        eax ^= (rbx >> ((i * 8 + 0x18) & 0x38)) & 0xFFFFFFFF
        out[i] = eax & 0xFF

    if out[:4] != b"\x7fELF":
        raise SystemExit("stage2 decrypt failed: output is not an ELF")
    return bytes(out)


def load_segments(elf: bytes) -> list[tuple[int, int, int, int, int, int, int, int]]:
    if elf[:4] != b"\x7fELF" or elf[4] != 2:
        raise SystemExit("expected ELF64")

    e_phoff = struct.unpack_from("<Q", elf, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", elf, 0x36)[0]
    e_phnum = struct.unpack_from("<H", elf, 0x38)[0]

    segs = []
    for i in range(e_phnum):
        phoff = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", elf, phoff)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<QQQQQQ", elf, phoff + 8)
        if p_type == 1:
            segs.append((phoff, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align))
    return segs


def va_to_file_offset_for_load(elf: bytes, va: int) -> tuple[int, int, int]:
    for phoff, _flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align in load_segments(elf):
        if p_vaddr <= va < p_vaddr + p_memsz:
            return phoff, p_offset + (va - p_vaddr), p_offset + p_filesz
    raise SystemExit(f"VA 0x{va:x} is not covered by any PT_LOAD")


def fix_loader_cookie(stage2: bytes) -> bytes:
    fixed = bytearray(stage2)

    phoff, cookie_off, old_file_end = va_to_file_offset_for_load(fixed, COOKIE_VA)
    needed_size = cookie_off + 8
    if len(fixed) < needed_size:
        fixed.extend(b"\x00" * (needed_size - len(fixed)))

    struct.pack_into("<Q", fixed, cookie_off, COOKIE_VALUE)

    p_filesz_off = phoff + 0x20
    old_filesz = struct.unpack_from("<Q", fixed, p_filesz_off)[0]
    new_filesz = max(old_filesz, needed_size - struct.unpack_from("<Q", fixed, phoff + 8)[0])
    struct.pack_into("<Q", fixed, p_filesz_off, new_filesz)

    print(
        f"[+] loader cookie repaired: VA=0x{COOKIE_VA:x} file_off=0x{cookie_off:x} "
        f"value=0x{COOKIE_VALUE:016x}"
    )
    print(f"[+] expanded file image: old_end=0x{old_file_end:x} new_size=0x{len(fixed):x} p_filesz=0x{new_filesz:x}")
    return bytes(fixed)


def write_hash_report(path: Path, entries: list[tuple[str, Path]]) -> None:
    lines = []
    for name, file_path in entries:
        data = file_path.read_bytes()
        md5, sha256 = digest(data)
        lines.append(f"{name}:")
        lines.append(f"  path   = {file_path.name}")
        lines.append(f"  size   = {len(data)}")
        lines.append(f"  md5    = {md5}")
        lines.append(f"  sha256 = {sha256}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Unpack ghost_abyss_hardened and repair the inner loader cookie.")
    ap.add_argument("packed", nargs="?", type=Path, default=DEFAULT_PACKED, help="outer packed ghost_abyss_hardened")
    ap.add_argument("-o", "--out-dir", type=Path, default=EXP_DIR, help="output directory")
    ap.add_argument("--reference", type=Path, help="optional reference stage2 payload for hash/byte comparison")
    args = ap.parse_args()

    packed_path = args.packed.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    packed = packed_path.read_bytes()
    stage2 = decrypt_stage2(packed)
    fixed = fix_loader_cookie(stage2)

    raw_path = out_dir / "stage2_payload.elf"
    fixed_path = out_dir / "stage2_payload_loaderfixed.elf"
    report_path = out_dir / "hash_report.txt"

    raw_path.write_bytes(stage2)
    fixed_path.write_bytes(fixed)
    raw_path.chmod(0o755)
    fixed_path.chmod(0o755)

    entries = [("packed", packed_path), ("stage2_payload", raw_path), ("stage2_payload_loaderfixed", fixed_path)]
    if args.reference:
        ref_path = args.reference.resolve()
        entries.append(("reference", ref_path))
        ref = ref_path.read_bytes()
        print(f"[+] reference match raw stage2: {ref == stage2}")
    write_hash_report(report_path, entries)

    for name, path in entries:
        md5, sha256 = digest(path.read_bytes())
        print(f"{name}: size={path.stat().st_size} md5={md5} sha256={sha256}")
    print(f"[+] wrote {raw_path}")
    print(f"[+] wrote {fixed_path}")
    print(f"[+] wrote {report_path}")


if __name__ == "__main__":
    main()
