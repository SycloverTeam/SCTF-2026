#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import subprocess
from pathlib import Path


FLAG_LEN = 43
TRACE_SNIP = (
    "    { unsigned char trace_rec[24]; trace_rec[0] = 0x44; "
    "trace_rec[1] = ctx->logical_stage; trace_rec[2] = ctx->phase; "
    "trace_rec[3] = ctx->idx; trace_rec[4] = ctx->c; trace_rec[5] = v; "
    "trace_rec[6] = 0; trace_rec[7] = 0; "
    "for (int trace_i = 0; trace_i < 8; trace_i++) trace_rec[8 + trace_i] = "
    "(unsigned char)(diff >> (trace_i * 8)); "
    "for (int trace_i = 0; trace_i < 8; trace_i++) trace_rec[16 + trace_i] = "
    "(unsigned char)(micro >> (trace_i * 8)); "
    "sys_write(2, (const char *)trace_rec, sizeof(trace_rec)); }\n"
)


def patch_source(src_text: str, epoch: int) -> str:
    replacements = [
        (
            "U64(0xC3A5C85C97CB3127), U64(0x5F3564959A6C932F), 0x59, 0xa6, 0x6d31",
            "U64(0xC3A5C85C97CB3127), U64(0x5F3564959A6C932F), 0xA7, 0xa6, 0x6d31",
        ),
        (
            "U64(0xB492B66FBE98F273), U64(0xD6E8FEB86659FD93), 0x73, 0x2d, 0x36, 0x91, 0xb17c",
            "U64(0xB492B66FBE98F273), U64(0xD6E8FEB86659FD93), 0x5E, 0x2d, 0x93, 0x91, 0xb17c",
        ),
        (
            "U64(0xB7E151628AED2A6B), U64(0xBF7158809CF4F3C7), 0x7d, 0x22, 0x3c91",
            f"U64(0xB7E151628AED2A6B), U64(0xBF7158809CF4F3C7), 0x{epoch ^ 0x22:02x}, 0x22, 0x3c91",
        ),
        (
            "U64(0x6A09E667F3BCC909), U64(0xBB67AE8584CAA73B), 0x64, 0xb2, 0x4a91",
            "U64(0x6A09E667F3BCC909), U64(0xBB67AE8584CAA73B), 0xF3, 0xb2, 0x4a91",
        ),
        (
            "U64(0x3C6EF372FE94F82B), U64(0xA54FF53A5F1D36F1), 0x11, 0xc8, 0x9a, 0x55, 0xd2c7",
            "U64(0x3C6EF372FE94F82B), U64(0xA54FF53A5F1D36F1), 0xE4, 0xc8, 0xB2, 0x55, 0xd2c7",
        ),
    ]
    for old, new in replacements:
        if old not in src_text:
            raise RuntimeError(f"missing gate pattern for epoch {epoch}: {old}")
        src_text = src_text.replace(old, new, 1)

    needle = (
        "    diff = stage_diff_scratch_load(ctx, v, micro);\n"
        "    diff ^= stage_diff_runtime_cookie(ctx, v, micro);\n"
    )
    if needle not in src_text:
        raise RuntimeError("missing apply-worker diff site")
    return src_text.replace(needle, needle + TRACE_SNIP, 1)


def compile_variant(workdir: Path, src_path: Path, out_path: Path) -> None:
    subprocess.check_call(
        [
            "gcc",
            "-ffreestanding",
            "-fno-builtin",
            "-nostdlib",
            "-no-pie",
            "-fno-stack-protector",
            "-z",
            "execstack",
            "-Og",
            "-fno-strict-aliasing",
            "-fno-optimize-sibling-calls",
            "-fno-asynchronous-unwind-tables",
            "-fno-unwind-tables",
            "-Wl,--build-id=none",
            "-o",
            str(out_path.resolve()),
            str(src_path.resolve()),
        ],
        cwd=workdir,
    )


def run_variant(bin_path: Path, csv_path: Path) -> None:
    proc = subprocess.run(
        [str(bin_path)],
        input=(b"a" * FLAG_LEN) + b"\n",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    rows = []
    data = proc.stderr
    for i in range(len(data) // 24):
        rec = data[i * 24 : (i + 1) * 24]
        if rec[0] != 0x44:
            continue
        rows.append(
            {
                "stage": rec[1] * 4 + rec[2],
                "L": rec[1],
                "phase": rec[2],
                "idx": rec[3],
                "c_dec": rec[4],
                "c_chr": chr(rec[4]) if 32 <= rec[4] <= 126 else "",
                "v": rec[5],
                "target": 0,
                "micro": int.from_bytes(rec[16:24], "little"),
                "diff": int.from_bytes(rec[8:16], "little"),
                "ok": 0,
            }
        )
    rows.sort(key=lambda row: row["L"])
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["stage", "L", "phase", "idx", "c_dec", "c_chr", "v", "target", "micro", "diff", "ok"],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"{csv_path}: rows={len(rows)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Author-side helper for validating the hidden route-projection oracle.")
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--header", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    src_text = args.source.read_text()
    (args.out_dir / args.header.name).write_bytes(args.header.read_bytes())
    for epoch in range(4):
        src_path = args.out_dir / f"oracle_epoch_{epoch}.c"
        bin_path = args.out_dir / f"oracle_epoch_{epoch}"
        csv_path = args.out_dir / f"oracle_epoch_{epoch}.csv"
        src_path.write_text(patch_source(src_text, epoch))
        compile_variant(args.out_dir, src_path, bin_path)
        run_variant(bin_path, csv_path)


if __name__ == "__main__":
    main()
