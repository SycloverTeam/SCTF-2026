打开ida反编译，发现整体为

```text
 解密第一层 block
    ↓
哈希与 ELF32/ET_REL 校验
    ↓
统计第一层内容中的特征字节
    ↓
释放第一层
    ↓
解密第二层 byte_13520
    ↓
哈希与 ELF Magic 校验
    ↓
解析第二层 ELF64 Program Header
    ↓
mmap 固定虚拟地址
    ↓
复制 PT_LOAD 文件内容
    ↓
清零 BSS
    ↓
写入 loader cookie
    ↓
mprotect 设置最终段权限
    ↓
直接 call e_entry
```

因为存在对文件操作，所以方便阅读，可以加入

```c
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;          
    uint16_t e_machine;        
    uint32_t e_version;        
    uint64_t e_entry;          
    uint64_t e_phoff;         
    uint64_t e_shoff;         
    uint32_t e_flags;          
    uint16_t e_ehsize;     
    uint16_t e_phentsize;     
    uint16_t e_phnum;         
} Elf64_Ehdr;
```

```c
        {
            v55 = 0;
            entry = (void (__fastcall *)(unsigned __int64, size_t, __int64, __int64, __int64, __int64))v24->e_entry;
            v44 = (char *)&v24->e_ident[v24->e_phoff];
            v45 = v44;
```

```c
while ( 1 )
            {
              if ( v56 == v49 )
              {
                entry(v3, a2, v43, v36, v39, v38);
                exit(0);
              }
              v3
```

跳转，需要注意的是存在

```c
MEMORY[0x42F000] = 0x6A09E667F3BCC909LL;
```

对一个地址的修改，直接`dump`可能存在偏移问题，所以直接通过脚本对其修复，脚本如下：

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


MASK64 = (1 << 64) - 1

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


def load_segments(elf: bytes) -> list[tuple[int, int, int, int, int, int, int]]:
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
    ap.add_argument(
        "packed",
        nargs="?",
        type=Path,
        default=Path("../../ghost_abyss_hardened"),
        help="outer packed ghost_abyss_hardened",
    )
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("."), help="output directory")
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
```


脚本会从最外层 `ghost_abyss_hardened` 中解出真实 stage2，并生成：

```text
stage2_payload.elf
stage2_payload_loaderfixed.elf
hash_report.txt
```

其中：

```text
stage2_payload.elf
  原始解密 inner

stage2_payload_loaderfixed.elf
  在原始 inner 基础上修复 loader 写入的 cookie：
  MEMORY[0x42f000] = 0x6a09e667f3bcc909
```

对里面的分析一下，发现对一个超大的结构体初始化，后序也存在大量的结构体，分别为

```c
typedef unsigned __int64 u64;

struct AbyssState {
    volatile u64 entropy[64];
    volatile u64 step_counter;
    volatile u64 dummy_hash;
    volatile u64 real_state;
    volatile u64 fail_acc;
    volatile u64 final_guard;
    volatile u64 target_key;
    volatile u64 anti_debug_alarm;
    volatile u64 code_hash_base;
    volatile u64 input_digest;

    volatile u64 event_mask;
    volatile u64 event_counter;
    volatile u64 event_shadow;
    volatile u64 key_epoch;
    volatile u64 timer_epoch;
    volatile u64 anti_epoch;
    volatile u64 event_algo_key;
    volatile u64 event_algo_mirror;
    volatile u64 event_algo_rounds;
    volatile u64 event_algo_ready;

    volatile unsigned int futex_word;
    volatile unsigned int gate_epoch;
    volatile u64 gate_waits;
    volatile u64 gate_shadow;

    volatile u64 sigill_count;
    volatile u64 sigill_shadow;
    volatile u64 sigill_last_rip;
    volatile u64 sigill_stage_hint;
    volatile u64 sigill_armed;

    volatile u64 segv_count;
    volatile u64 segv_shadow;
    volatile u64 segv_last_rip;
    volatile u64 segv_last_rsp;
    volatile u64 segv_fault_addr;
    volatile u64 segv_stage_hint;
    volatile u64 segv_armed;
    volatile u64 segv_saved_rsp;
    volatile u64 segv_recover_rip;

    volatile u64 split_shadow[43];
    volatile u64 split_counter;
    volatile u64 split_last;

    volatile u64 uffd_enabled;
    volatile u64 uffd_faults;
    volatile u64 uffd_last_addr;
    volatile u64 uffd_shadow;
    volatile u64 uffd_fallback;

    volatile u64 td_uffd_enabled;
    volatile u64 td_uffd_faults;
    volatile u64 td_uffd_last_addr;
    volatile u64 td_uffd_shadow;
    volatile u64 td_uffd_fallback;
    volatile u64 td_page_mix;

    volatile u64 heartbeat_epoch;
    volatile u64 heartbeat_mirror;
    volatile u64 heartbeat_cookie;
    volatile u64 heartbeat_shadow;
    volatile u64 heartbeat_baseline;
    volatile u64 heartbeat_last_seen;
    volatile u64 heartbeat_bad;
    volatile u64 heartbeat_code_hash;
    volatile u64 heartbeat_checks;
    volatile u64 heartbeat_stage_mix;
    volatile u64 heartbeat_key_mix;
    volatile u64 heartbeat_target_shadow;

    volatile u64 rx_helper_ready;
    volatile u64 rx_helper_calls;
    volatile u64 rx_helper_shadow;
    volatile u64 rx_helper_code_hash;
    volatile u64 rx_helper_bad;
    volatile u64 rx_helper_last_stage;
    volatile u64 rx_helper_active_mix;
    volatile u64 rx_helper_active_seen;
    volatile u64 rx_helper_active_guard;
    volatile u64 rx_helper_target_root;
    volatile u64 rx_helper_target_shadow;
    volatile u64 helper_output_key_mix;

    volatile u64 memfd_stage2_ready;
    volatile u64 memfd_stage2_calls;
    volatile u64 memfd_stage2_shadow;
    volatile u64 memfd_stage2_code_hash;
    volatile u64 memfd_stage2_bad;
    volatile u64 memfd_stage2_last_stage;
    volatile u64 memfd_stage2_active_mix;
    volatile u64 memfd_stage2_active_seen;
    volatile u64 memfd_stage2_active_guard;
    volatile u64 memfd_stage2_fd_tag;
    volatile u64 memfd_stage2_commit_mix;
    volatile u64 memfd_stage2_commit_mirror;
    volatile u64 memfd_stage2_target_root;
    volatile u64 memfd_stage2_target_shadow;
    volatile u64 memfd_stage2_target_uses;
    volatile u64 memfd_stage2_output_key_mix;

    volatile u64 pvm_mailbox;
    volatile u64 pvm_mirror;
    volatile u64 pvm_epoch;
    volatile u64 pvm_mix;
    volatile u64 pvm_writes;
    volatile u64 pvm_child_pid;
    volatile u64 pvm_bad;
    volatile u64 pvm_fallback;
    volatile u64 pvm_code_hash;
    volatile u64 pvm_stage_mix;

    volatile u64 handler_table_ready;
    volatile u64 handler_table_faults;
    volatile u64 handler_table_shadow;
    volatile u64 handler_table_bad;
    volatile u64 handler_table_last_addr;
    volatile u64 handler_table_reads;
    volatile u64 handler_table_stage_mix;
    volatile u64 handler_table_stage_mirror;
    volatile u64 handler_table_page_hash;

    volatile u64 code_island_ready;
    volatile u64 code_island_calls;
    volatile u64 code_island_bad;
    volatile u64 code_island_last_stage;
    volatile u64 code_island_code_hash;
    volatile u64 code_island_active_mix;
    volatile u64 code_island_active_seen;
    volatile u64 code_island_active_guard;
    volatile u64 code_island_wipes;
    volatile u64 code_island_shadow;

    volatile u64 phase_lane_mix[4];
    volatile u64 phase_lane_mirror[4];
    volatile u64 phase_dispatch_count;
    volatile u64 phase_dispatch_shadow;

    volatile u64 virtual_lane_mix[64];
    volatile u64 virtual_lane_mirror[64];
    volatile u64 virtual_dispatch_count;
    volatile u64 virtual_dispatch_shadow;
    volatile u64 virtual_lane_last;
    volatile u64 virtual_lane_bad;

    volatile u64 diff_scratch_a[8];
    volatile u64 diff_scratch_b[8];
    volatile u64 diff_scratch_mirror;
    volatile u64 diff_scratch_seq;

    volatile u64 forty_round_shadow;
    volatile u64 forty_round_mirror;
    volatile u64 forty_round_counter;
    volatile u64 forty_round_gate;

    volatile u64 target_vm_shadow;
    volatile u64 target_vm_mirror;
    volatile u64 target_vm_counter;
    volatile u64 target_vm_gate;

    volatile u64 target_decode_dispatch_shadow;
    volatile u64 target_decode_dispatch_mirror;
    volatile u64 target_decode_dispatch_counter;
    volatile u64 target_decode_dispatch_gate;
    volatile u64 target_decode_decoy_scratch[8];

    volatile u64 mix_vm_shadow;
    volatile u64 mix_vm_mirror;
    volatile u64 mix_vm_counter;
    volatile u64 mix_vm_gate;

    volatile u64 diff_dispatch_shadow;
    volatile u64 diff_dispatch_mirror;
    volatile u64 diff_dispatch_counter;
    volatile u64 diff_dispatch_gate;
    volatile u64 diff_decoy_scratch[8];

    volatile u64 apply_dispatch_shadow;
    volatile u64 apply_dispatch_mirror;
    volatile u64 apply_dispatch_counter;
    volatile u64 apply_dispatch_gate;
    volatile u64 apply_decoy_scratch[8];

    volatile u64 xchar_mix;
    volatile u64 xchar_mirror;
    volatile u64 xchar_count;
    volatile u64 xchar_last;

    volatile u64 fake_lane_mix;
    volatile u64 fake_lane_mirror;
    volatile u64 fake_lane_count;
    volatile u64 fake_lane_last;
    volatile u64 fake_lane_bad;

    volatile u64 route_roll_mix;
    volatile u64 route_roll_mirror;
    volatile u64 route_roll_count;
    volatile u64 route_roll_last;
    volatile u64 route_roll_bad;

    volatile u64 enc_target_deltas[1721];
};
```



```c
typedef unsigned long long u64;

struct RouteProjectionGateShardA {
    u64 shadow_a;
    u64 seed;
    unsigned char bias_enc;
    unsigned char bias_key;
    unsigned short touch;
};

struct RouteProjectionGateShardB {
    u64 shadow_b;
    u64 salt;
    unsigned char phase_enc;
    unsigned char phase_key;
    unsigned char lane_enc;
    unsigned char lane_key;
    unsigned short touch;
};

struct RouteProjectionLaneCell {
    u64 seed;
    unsigned char salt;
    unsigned char stride;
    unsigned short fold;
};

struct RouteProjectionRuntimeCache {
    unsigned char tap;
    unsigned char phase_noise;
    unsigned char lane_noise;
    unsigned char latch;
    struct RouteProjectionLaneCell lanes[4];
    u64 mirror;
    u64 decoy;
};

struct RouteProjectionMirrorGate {
    u64 shadow;
    u64 mirror;
    unsigned char enable_enc;
    unsigned char enable_key;
    unsigned char lane_enc;
    unsigned char lane_key;
    unsigned short fold;
};

struct RouteProjectionEpochGate {
    u64 nonce;
    u64 mix;
    unsigned char epoch_enc;
    unsigned char epoch_key;
    unsigned short touch;
};

struct RouteProjectionRuntimeShardA {
    u64 seed;
    u64 mirror;
    unsigned char alpha_enc;
    unsigned char alpha_key;
    unsigned short touch;
};

struct RouteProjectionRuntimeShardB {
    u64 fold;
    u64 latch_seed;
    unsigned char beta_enc;
    unsigned char beta_key;
    unsigned char arm_enc;
    unsigned char arm_key;
    unsigned short touch;
};
```

对应地址如下：

```text
0x42e000  route_projection_runtime_latch       u64
0x42e010  route_projection_runtime_b           struct RouteProjectionRuntimeShardB
0x42e030  route_projection_runtime_a           struct RouteProjectionRuntimeShardA
0x42e050  route_projection_epoch_gate          struct RouteProjectionEpochGate
0x42e070  route_projection_mirror_gate         struct RouteProjectionMirrorGate
0x42e0a0  route_projection_cache               struct RouteProjectionRuntimeCache
0x42e100  route_projection_gate_b              struct RouteProjectionGateShardB
0x42e120  route_projection_gate_a              struct RouteProjectionGateShardA
0x42cbd0  route_projection_orbit_targets       unsigned char[4]
0x42cbd4  route_projection_runtime_targets     unsigned char[4]
0x42cb60  route_projection_residue_packs       unsigned long long[6]
```

这一步做完后，IDA 里 `byte_42E130`、`byte_42E110` 这种裸全局就能看成结构体字段。例如：

```text
byte_42E130 = route_projection_gate_a.bias_enc
byte_42E131 = route_projection_gate_a.bias_key
byte_42E110 = route_projection_gate_b.phase_enc
byte_42E111 = route_projection_gate_b.phase_key
byte_42E112 = route_projection_gate_b.lane_enc
byte_42E113 = route_projection_gate_b.lane_key
byte_42E060 = route_projection_epoch_gate.epoch_enc
byte_42E061 = route_projection_epoch_gate.epoch_key
```

接着看程序运行逻辑，stage2 初始化时会先跑一批全局 runtime 初始化，其中和这里最相关的是 `init_route_projection_runtime_latch(0x414500)`。它读取上面几个结构体的初始字段，把编码字段 xor key 解出来，然后写入 `route_projection_runtime_latch(0x42e000)`(方便定位，重开了一个新的，没加结构体的)：

```c
__int64 sub_414500()
{
  unsigned __int8 v0; // bl
  __int64 v1; // r12
  __int64 v2; // rbp
  __int64 result; // rax

  v0 = byte_42E023 ^ byte_42E022;
  v1 = (unsigned __int8)(byte_42E041 ^ byte_42E040);
  v2 = (unsigned __int8)(byte_42E021 ^ byte_42E020);
  result = sub_413B62(
             __ROL8__(0xD1B54A32D192ED03LL * v2, ((byte_42E023 ^ byte_42E022) & 0x1Fu) + 1)
           ^ qword_42E100
           ^ qword_42E120
           ^ __ROL8__(qword_42E018, 17)
           ^ qword_42E010
           ^ __ROL8__(qword_42E038, 9)
           ^ qword_42E030
           ^ (0x100000001B3LL * v1));
  qword_42E000 = result ^ (v1 << 7) ^ (v2 << 23) ^ ((unsigned __int64)v0 << 41);
  return result;
}
```

这里几个关键字段对应关系是：

```text
byte_42E040 ^ byte_42E041 = runtime_a.alpha_enc ^ runtime_a.alpha_key
byte_42E020 ^ byte_42E021 = runtime_b.beta_enc  ^ runtime_b.beta_key
byte_42E022 ^ byte_42E023 = runtime_b.arm_enc   ^ runtime_b.arm_key
qword_42E000              = route_projection_runtime_latch
```

也就是说，后面的 gate 不是只看几个常量，而是依赖初始化后得到的 `route_projection_runtime_latch(0x42e000)`

然后程序读取输入，构造每一轮 stage 的本地上下文，这个上下文在 IDA 里经常表现成 `_BYTE *a1`，关键偏移是：

```text
a1[9]   = logical_stage
a1[16]  = phase
a1[22]  = idx
a1[32]  = 当前 staged input byte，也就是实际参与本轮计算的字符
```

每个 stage 会算出 `v`、`target`、`micro`，再进入 diff 聚合层。IDA 里这一层是 `sub_424D03(0x424d03)` 先更新一些 diff runtime 状态，然后调用 `sub_424BD7(0x424bd7)`：

```c
__int64 __fastcall sub_424D03(_BYTE *a1, unsigned __int8 a2, unsigned __int8 a3, __int64 a4)
{
  __int64 v6; // rax

  v6 = sub_423DC4(a1, a2, a3);
  qword_42FCE8 = sub_413B62(
                   ((unsigned __int64)((unsigned int)(unsigned __int8)a1[32] + 256) << (8 * ((a1[16] ^ a1[22]) & 7u)))
                 ^ __ROL8__(a4 ^ qword_42FD00, ((a1[9] + a1[22]) & 0x1Fu) + 1)
                 ^ v6
                 ^ qword_42FCE8);
  qword_42FD00 = sub_413B62(
                   ++qword_42FCF8
                 + 0xD1B54A32D192ED03LL * ((unsigned int)(unsigned __int8)a1[9] + 1)
                 + qword_42FCE8
                 + qword_42FD00);
  qword_42FCF0 = sub_41BA64();
  return sub_424BD7(a1, a2, a3, a4);
}
```

`sub_424BD7(0x424bd7)` 可以理解为`stage_commit_diff_worker` ：它把主变换差异、route projection、各种 guard 都 OR 到一起
这里最关键的是它会调用 `route_projection_hint_fold(0x4141f0)`：

```c
__int64 __fastcall sub_424BD7(_BYTE *a1, unsigned __int8 a2, unsigned __int8 a3, __int64 a4)
{
  char v6; // bl
  __int64 v7; // rbx
  __int64 v8; // rbx
  __int64 v9; // rbx
  unsigned __int64 v10; // rbx
  unsigned __int64 v11; // rbx
  unsigned __int64 v12; // rbx
  unsigned __int64 v13; // rbx
  unsigned __int64 v14; // rbx
  unsigned __int64 v15; // rbx
  unsigned __int64 v16; // rbx
  __int64 v17; // r14

  v6 = sub_4235BA((unsigned __int8)a1[9]);
  sub_415FAE(a1, a4);
  v7 = sub_413D07(a1, a2, a3, a4) | (unsigned __int8)(a3 ^ a2 ^ v6);
  v8 = route_projection_hint_fold(a1, a2, a3, a4) | v7;
  v9 = sub_41B43B(a1, a2, a4) | v8;
  v10 = (unsigned __int8)sub_418961((unsigned __int8)a1[9]) | (unsigned __int64)v9;
  v11 = (unsigned __int8)sub_421E73((unsigned __int8)a1[9]) | v10;
  v12 = (unsigned __int8)sub_4247FA((unsigned __int8)a1[9]) | v11;
  v13 = (unsigned __int8)sub_414D89((unsigned __int8)a1[9]) | v12;
  v14 = (unsigned __int8)sub_415777((unsigned __int8)a1[9]) | v13;
  v15 = (unsigned __int8)sub_4220FD((unsigned __int8)a1[9]) | v14;
  v16 = (unsigned __int8)sub_417019((unsigned __int8)a1[9]) | v15;
  v17 = sub_423730(a1, a2, a4) ^ v16;
  sub_417FE4(a1, a2, a4, v17);
  return v17 ^ __ROL8__(qword_42FC18, ((a1[16] + a1[22]) & 0x1Fu) + 1);
}
```

所以运行逻辑可以概括成：

```text
stage2 初始化
    ↓
init_route_projection_runtime_latch(0x414500) 初始化 route_projection_runtime_latch(0x42e000)
    ↓
读取输入并 materialize 成 staged input view
    ↓
每一轮 stage 构造 ctx：logical_stage / phase / idx / c
    ↓
算 v、target、micro
    ↓
sub_424D03(0x424d03) 更新 diff runtime 状态
    ↓
sub_424BD7(0x424bd7) 聚合 diff/guard/projection
    ↓
route_projection_hint_fold(0x4141f0) 读取 route_projection_cache/gate/runtime 结构体
    ↓
route_projection_gate_window(0x413f84) 判断 hidden oracle 是否打开
    ↓
如果 gate 没开，hint_fold 返回 0 或普通噪声
如果 gate 打开，进入 route_projection_leak_residue(0x4141c7)
```

不套类型时看到的是一堆 `byte_42E130`、`qword_42E0E8`，很难看出它们其实属于同一组 runtime/gate/cache；套完后就能看明白，patch 的 7 个字节其实都是在修改 gate 解码出来的 `bias/phase/lane/epoch` 和 runtime gate 相关字段

```text
route_projection_runtime_gate_byte(0x413e89)
route_projection_orbit_byte(0x413f01)
route_projection_gate_window(0x413f84)
route_projection_residue_byte(0x414185)
route_projection_leak_residue(0x4141c7)
route_projection_hint_fold(0x4141f0)
```

核心调用关系：

```text
route_projection_hint_fold(0x4141f0)
  -> route_projection_gate_window(0x413f84)
  -> route_projection_leak_residue(0x4141c7)
       -> route_projection_residue_byte(0x414185)
```

`route_projection_gate_window(0x413f84)` 的逻辑可以还原成：

```text
bias  == 1
phase == 0x73
lane  == 2
epoch <= 3
(idx ^ epoch) & 3 == 0
runtime_gate_byte(epoch, phase, lane) == byte_42cbd4[epoch]
orbit_byte(epoch, phase, lane)        == byte_42cbd0[epoch]
```

这说明它不是普通失败分支，而是一个 normally closed oracle。尤其是：

```text
epoch <= 3
(idx & 3) == epoch
```

这两个条件说明泄漏被拆成 4 轮，每轮泄漏一组 `idx % 4` 的字节


 gate patch 点

这些字段在修复后的 stage2 中地址如下：

```text
route_projection_runtime_b      = 0x42e010
route_projection_runtime_a      = 0x42e030
route_projection_epoch_gate     = 0x42e050
route_projection_gate_b         = 0x42e100
route_projection_gate_a         = 0x42e120
route_projection_residue_packs  = 0x42cb60
```

需要 patch 的 7 个字节：

```text
VA        file_off  old   new              meaning
0x42e020  0x2e020   0x11  0xe4             runtime_b.beta_enc
0x42e022  0x2e022   0x9a  0xb2             runtime_b.arm_enc
0x42e040  0x2e040   0x64  0xf3             runtime_a.alpha_enc
0x42e060  0x2e060   0x7d  epoch ^ 0x22     epoch_gate.epoch_enc
0x42e110  0x2e110   0x73  0x5e             gate_b.phase_enc
0x42e112  0x2e112   0x36  0x93             gate_b.lane_enc
0x42e130  0x2e130   0x59  0xa7             gate_a.bias_enc
```

这些 patch 不是把程序改成直接通过，而是让 `route_projection_hint_fold(0x4141f0)` 进入隐藏泄漏路径，这里每个 patch 字节都能从 IDA xref 追到具体使用位置：

```text
patch VA  field                         IDA xref    使用函数 / 作用
0x42e020  runtime_b.beta_enc            0x414516    init_route_projection_runtime_latch/sub_414500(0x414500)
                                                       参与 beta = runtime_b.beta_enc ^ runtime_b.beta_key
                                                       影响 qword_42e000(route_projection_runtime_latch)

0x42e022  runtime_b.arm_enc             0x414526    init_route_projection_runtime_latch/sub_414500(0x414500)
                                                       参与 arm = runtime_b.arm_enc ^ runtime_b.arm_key
                                                       影响 qword_42e000(route_projection_runtime_latch)

0x42e040  runtime_a.alpha_enc           0x414504    init_route_projection_runtime_latch/sub_414500(0x414500)
                                                       参与 alpha = runtime_a.alpha_enc ^ runtime_a.alpha_key
                                                       影响 qword_42e000(route_projection_runtime_latch)

0x42e060  epoch_gate.epoch_enc          0x4142a3    route_projection_hint_fold/sub_4141F0(0x4141f0)
                                                       计算 gate_epoch = epoch_enc ^ epoch_key
                                                       作为第 5 参数传给 route_projection_gate_window/sub_413F84(0x413f84)

0x42e110  gate_b.phase_enc              0x414279    route_projection_hint_fold/sub_4141F0(0x4141f0)
                                                       计算 gate_phase = phase_enc ^ phase_key
                                                       作为第 3 参数传给 route_projection_gate_window/sub_413F84(0x413f84)

0x42e112  gate_b.lane_enc               0x41428f    route_projection_hint_fold/sub_4141F0(0x4141f0)
                                                       计算 gate_lane = lane_enc ^ lane_key
                                                       作为第 4 参数传给 route_projection_gate_window/sub_413F84(0x413f84)

0x42e130  gate_a.bias_enc               0x414262    route_projection_hint_fold/sub_4141F0(0x4141f0)
                                                       计算 gate_bias = bias_enc ^ bias_key
                                                       作为第 2 参数传给 route_projection_gate_window/sub_413F84(0x413f84)
```

对应的关键调用位置如下：

```text
start(0x428580)
  -> init_route_projection_runtime_latch/sub_414500(0x414500)
       0x414504  读取 runtime_a.alpha_enc(0x42e040)
       0x414516  读取 runtime_b.beta_enc(0x42e020)
       0x414526  读取 runtime_b.arm_enc(0x42e022)
       0x4145c9  写 qword_42e000(route_projection_runtime_latch)

sub_424BD7(0x424bd7)
  -> 0x424c3b call route_projection_hint_fold/sub_4141F0(0x4141f0)

route_projection_hint_fold/sub_4141F0(0x4141f0)
       0x414262  读取 gate_a.bias_enc(0x42e130)
       0x414279  读取 gate_b.phase_enc(0x42e110)
       0x41428f  读取 gate_b.lane_enc(0x42e112)
       0x4142a3  读取 epoch_gate.epoch_enc(0x42e060)
  -> 0x41447a call route_projection_gate_window/sub_413F84(0x413f84)
  -> 0x4144c7 call route_projection_leak_residue/sub_4141C7(0x4141c7)

route_projection_gate_window/sub_413F84(0x413f84)
       0x413f98  判断 bias == 1
       0x413f9b  判断 phase == 0x73
       0x413f9e  判断 lane == 2
       0x413fab  判断 epoch <= 3
       0x413fb5  判断 ((idx ^ epoch) & 3) == 0
  -> 0x413fd5 call route_projection_runtime_gate_byte/sub_413E89(0x413e89)
       0x413fe3  比较 route_projection_runtime_targets(0x42cbd4)[epoch]
  -> 0x413ff1 call route_projection_orbit_byte/sub_413F01(0x413f01)
       0x413ffc  比较 route_projection_orbit_targets(0x42cbd0)[epoch]

route_projection_runtime_gate_byte/sub_413E89(0x413e89)
       0x413ee4  使用 qword_42e000(route_projection_runtime_latch)
       0x413ee4  同时混入 qword_42e050(epoch_gate.nonce)
       返回 gate byte 给 sub_413F84(0x413f84)

route_projection_orbit_byte/sub_413F01(0x413f01)
       0x413f68  使用 qword_42e010(runtime_b.fold)
       0x413f68  使用 qword_42e030(runtime_a.seed)
       0x413f68  使用 qword_42e000(route_projection_runtime_latch)
       返回 orbit byte 给 sub_413F84(0x413f84)

route_projection_leak_residue/sub_4141C7(0x4141c7)
  -> 0x4141d8 call route_projection_residue_byte/sub_414185(0x414185)
       0x4141dd  开始 xor ctx+0x20，也就是从这里开始混入输入字符

route_projection_residue_byte/sub_414185(0x414185)
       0x4141a3/0x4141ab  读取 route_projection_residue_packs(0x42cb60)
       返回值低 8 位就是 logger 在 0x4141dd 前要抓的 hidden byte
```

关键函数的反编译可以缩成下面几段。先看初始化 latch 的 `init_route_projection_runtime_latch/sub_414500(0x414500)`，前三个 patch 会影响这里最终写出的 `qword_42e000`：

```c
__int64 sub_414500()
{
  unsigned __int8 v0; // bl
  __int64 v1; // r12
  __int64 v2; // rbp
  __int64 result; // rax

  v0 = byte_42E023 ^ byte_42E022;
  v1 = (unsigned __int8)(byte_42E041 ^ byte_42E040);
  v2 = (unsigned __int8)(byte_42E021 ^ byte_42E020);
  result = sub_413B62(
             __ROL8__(0xD1B54A32D192ED03LL * v2, ((byte_42E023 ^ byte_42E022) & 0x1Fu) + 1)
           ^ qword_42E100
           ^ qword_42E120
           ^ __ROL8__(qword_42E018, 17)
           ^ qword_42E010
           ^ __ROL8__(qword_42E038, 9)
           ^ qword_42E030
           ^ (0x100000001B3LL * v1));
  qword_42E000 = result ^ (v1 << 7) ^ (v2 << 23) ^ ((unsigned __int64)v0 << 41);
  return result;
}
```

再看 `route_projection_hint_fold/sub_4141F0(0x4141f0)`。后四个 patch 在这里被 xor key 解成 gate 参数，然后传给 `route_projection_gate_window/sub_413F84(0x413f84)`：

```c
__int64 __fastcall sub_4141F0(_BYTE *a1, unsigned __int8 a2, unsigned __int8 a3, __int64 a4)
{
  unsigned __int8 v4; // r13
  unsigned __int8 v5; // r9
  unsigned __int64 v6; // rbp
  unsigned __int64 v7; // rbx
  __int64 v8; // r14
  char v10; // r14
  __int64 v11; // r12
  unsigned __int8 v14; // [rsp+22h] [rbp-46h]
  char v15; // [rsp+23h] [rbp-45h]
  unsigned __int16 v16; // [rsp+24h] [rbp-44h]
  char v17; // [rsp+26h] [rbp-42h]
  unsigned __int8 v18; // [rsp+27h] [rbp-41h]
  unsigned int v19; // [rsp+28h] [rbp-40h]
  unsigned __int8 v20; // [rsp+2Ch] [rbp-3Ch]
  unsigned __int8 v21; // [rsp+2Dh] [rbp-3Bh]
  unsigned __int8 v22; // [rsp+2Eh] [rbp-3Ah]
  unsigned __int8 v23; // [rsp+2Fh] [rbp-39h]

  v4 = a1[22];
  v5 = a1[16];
  v18 = (v5 ^ v4 ^ a1[9]) & 3;
  v6 = 16LL * v18;
  v15 = byte_42E0B1[v6];
  v16 = word_42E0B2[v6 / 2];
  v17 = byte_42E131 ^ byte_42E130;
  v20 = byte_42E111 ^ byte_42E110;
  v21 = byte_42E113 ^ byte_42E112;
  v22 = byte_42E061 ^ byte_42E060;
  v19 = (unsigned __int8)byte_42E0B0[v6];
  v7 = (__ROL8__(a4 ^ ((unsigned __int64)a2 << 8) ^ a3, ((v4 + 5) & 0x1Fu) + 1)
      ^ qword_42E050
      ^ qword_42E128
      ^ qword_42E0A8[v6 / 8]
      ^ qword_42E120)
     + ((0x100000001B3LL * (int)(v4 + v19)) ^ 0x9E3779B97F4A7C15LL);
  v14 = a1[9];
  v23 = v5;
  v8 = qword_42E0E8
     ^ sub_413B62(
         (__ROL8__(v7 + ((unsigned __int64)(unsigned __int8)a1[32] << (8 * (v4 & 7u))), ((v14 ^ v5) & 0x1Fu) + 1)
        ^ qword_42E058
        ^ qword_42E108
        ^ qword_42E100)
       + v5
       - 0x2E4AB5CD2E6D12FDLL);
  qword_42E0F0 = sub_413B62(v16 ^ v8 ^ qword_42E0F0);
  byte_42E0A0 = ((unsigned __int8)(v15 + (v20 ^ byte_42E0A1 ^ ((v7 >> 19) + (v8 ^ byte_42E0A0)))) >> 3)
              ^ (v15 + (v20 ^ byte_42E0A1 ^ ((v7 >> 19) + (v8 ^ byte_42E0A0))));
  byte_42E0A3 ^= v18;
  word_42E0B2[v6 / 2] = word_42E0B2[v6 / 2];
  qword_42E0E8 ^= __ROL8__(qword_42E0F0 ^ v8 ^ v7, ((v18 + v4) & 0x1Fu) + 1);
  if ( !(unsigned __int8)sub_413F84(v4, (unsigned int)v17, v20, v21, v22) )
    return 0;
  v10 = sub_40100F(v19, v20, v4, a4);
  v11 = (unsigned __int8)(v10 ^ __ROL1__(sub_4141C7((__int64)a1, v14, a2, a3, 0), ((v23 ^ v4) & 7) + 1));
  return v11 << sub_401024(v4, v14, v23, v21);
}
```

`route_projection_gate_window/sub_413F84(0x413f84)` 是真正决定 oracle 是否打开的地方：

```c
__int64 __fastcall sub_413F84(unsigned __int8 a1, int a2, int a3, int a4, unsigned __int8 a5)
{
  int v5; // eax
  unsigned __int8 v6; // bp
  unsigned __int8 v7; // r12
  int v9; // edx
  int v10; // ecx
  int v11; // r13d
  int v13; // eax
  __int64 v14; // rbx
  int v15; // r13d
  unsigned int v16; // eax

  v6 = a3;
  v7 = a4;
  LOBYTE(v5) = (_BYTE)a2 == 1;
  v9 = a3 ^ 0x73;
  v10 = a4 ^ 2;
  LOBYTE(a2) = ((unsigned __int8)v10 | (unsigned __int8)v9) == 0;
  LOBYTE(v10) = a5 <= 3u;
  LOBYTE(v9) = ((a5 ^ a1) & 3) == 0;
  v11 = v9 & v10 & a2 & v5;
  v13 = sub_413E89(a5, v6, v7);
  v14 = a5 & 3;
  LOBYTE(v13) = (_BYTE)v13 == (unsigned __int8)byte_42CBD4[v14];
  v15 = v13 & v11;
  v16 = sub_413F01(a5, v6, v7);
  LOBYTE(v16) = (_BYTE)v16 == (unsigned __int8)byte_42CBD0[v14];
  return v15 & v16;
}
```

最后，`route_projection_residue_packs(0x42cb60)` 不是 gate patch 字段，但它是最终泄漏数据来源：

```c
__int64 __fastcall sub_414185(unsigned __int8 a1)
{
  unsigned __int64 v2; // rbp

  if ( a1 > 0x2Au )
    return 0;
  v2 = (unsigned __int64)qword_42CB60[a1 >> 3] >> (8 * (a1 & 7u));
  LODWORD(v2) = sub_41400B(a1) ^ v2;
  return (unsigned int)v2 ^ (unsigned int)sub_4140C6(a1);
}
```

最干净的泄漏点在：

```text
route_projection_leak_residue(0x4141c7)
```

IDA 反编译结果核心为：

```c
v6 = route_projection_residue_byte(*(unsigned __int8 *)(ctx + 0x16)); // route_projection_residue_byte(0x414185)
LOBYTE(v6) = *(_BYTE *)(ctx + 0x20) ^ v6;
return (unsigned int)(a5 >> 8) ^ (unsigned int)a5 ^ a2 ^ v6;
```

对应汇编：

```asm
0x4141d4  movzx edi, byte ptr [rdi+0x16]   ; hidden idx
0x4141d8  call  route_projection_residue_byte(0x414185)
0x4141dd  xor   al, byte ptr [rbp+0x20]    ; 从这里开始混入 staged input
0x4141e0  xor   eax, r12d
0x4141e3  xor   eax, ebx
```

所以最佳 logger 点是：

```text
0x4141dd
```

在 `0x4141d8 call route_projection_residue_byte(0x414185)` 返回后，`AL` 里还保留没有混入用户输入的 hidden byte
此时记录：

```text
raw_return & 0xff
ctx+0x16 hidden idx
ctx+0x09 logical position
ctx+0x10 phase
ctx+0x20 staged input byte
```

就能直接得到当前 epoch 泄漏的 flag byte

使用代码洞：

```text
CAVE_VA = 0x4286c4
```

它位于 RX LOAD 原始末尾：

```text
0x401000 + 0x276c4 = 0x4286c4
```

需要把 RX `PT_LOAD` 的 `p_filesz/p_memsz` 扩到：

```text
0x28000
```

然后在 `0x4141dd` 覆盖 6 字节：

```text
old: 32 45 20 44 31 e0
new: e9 e2 44 01 00 90
```

含义：

```asm
jmp 0x4286c4
nop
```

logger 写入 `stderr`，每条记录大小 `0x28`，magic 为：

```text
OCAFLOG0
```

记录布局：

```text
record+0x00  "OCAFLOG0"
record+0x08  ctx pointer
record+0x10  r12
record+0x18  raw return from route_projection_residue_byte(0x414185)
record+0x20  logical position
record+0x21  phase
record+0x22  hidden idx
record+0x23  staged input byte
```

恢复时：

```python
hidden_idx = record[0x22]
flag_byte  = u64(record[0x18:0x20]) & 0xff
```

四个 epoch 合并即可得到完整 flag


脚本：

```python
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
                # Code-cave writes intentionally extend the executable segment.
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
    ap.add_argument("stage2", nargs="?", type=Path, default=Path("stage2_payload_loaderfixed.elf"))
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("oracle_epochs"))
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
```

会生成：

```text
oracle_epochs/oracle_epoch_0.elf
oracle_epochs/oracle_epoch_1.elf
oracle_epochs/oracle_epoch_2.elf
oracle_epochs/oracle_epoch_3.elf
```


```bash
cd /home/sleep4r/ctf
rm -rf ghost_decode_exp
mkdir -p ghost_decode_exp
tar -xzf ghost_decode_exp.tar.gz -C ghost_decode_exp
cd ghost_decode_exp/exp
chmod +x fix_outer_payload.py recover_flag_patch_oracle.py stage2_payload_loaderfixed.elf
cp stage2_payload.elf stage2_payload.reference.elf
./fix_outer_payload.py /home/sleep4r/ctf/ghost_abyss_hardened --reference stage2_payload.reference.elf | tee remote_fix_result.txt
./recover_flag_patch_oracle.py | tee remote_recover_result.txt
sha256sum stage2_payload.elf stage2_payload_loaderfixed.elf oracle_epochs/oracle_epoch_*.elf > remote_hashes.txt
```

`remote_fix_result.txt`：

```text
[+] loader cookie repaired: VA=0x42f000 file_off=0x2f000 value=0x6a09e667f3bcc909
[+] expanded file image: old_end=0x2e13c new_size=0x2f008 p_filesz=0x1008
[+] reference match raw stage2: True
packed: size=270352 md5=01338ea27bf1b94708a309c2181771ab sha256=f6bd79a7ef072a977e04804e7dbbc77a373d825cdce1cf66327db97796f77265
stage2_payload: size=188732 md5=523bd725b829b1b1010579d423cbd873 sha256=ba384e6607765806bc4e5fca2fe729018f96f4db9c235ff511acf49e28776c03
stage2_payload_loaderfixed: size=192520 md5=5b11da3b0472b7aa446578938e2f1fd4 sha256=991b70f95156fc46db2ca67ae9f09b2d550c9ee49343b4735dcc284d49e18e81
reference: size=188732 md5=523bd725b829b1b1010579d423cbd873 sha256=ba384e6607765806bc4e5fca2fe729018f96f4db9c235ff511acf49e28776c03
[+] wrote /home/sleep4r/ctf/ghost_decode_exp/exp/stage2_payload.elf
[+] wrote /home/sleep4r/ctf/ghost_decode_exp/exp/stage2_payload_loaderfixed.elf
[+] wrote /home/sleep4r/ctf/ghost_decode_exp/exp/hash_report.txt
```

`remote_recover_result.txt`：

```text
[+] epoch 0: wrote oracle_epochs/oracle_epoch_0.elf
[+] epoch 0: leaked 11 byte(s)
[+] epoch 1: wrote oracle_epochs/oracle_epoch_1.elf
[+] epoch 1: leaked 11 byte(s)
[+] epoch 2: wrote oracle_epochs/oracle_epoch_2.elf
[+] epoch 2: leaked 11 byte(s)
[+] epoch 3: wrote oracle_epochs/oracle_epoch_3.elf
[+] epoch 3: leaked 10 byte(s)
flag_hex = 736374667b66616273666f61676633343332793961646c2166657366736666686f7968333435676468687d
flag = sctf{fabsfoagf3432y9adl!fesfsffhoyh345gdhh}
```

`remote_hashes.txt`：

```text
ba384e6607765806bc4e5fca2fe729018f96f4db9c235ff511acf49e28776c03  stage2_payload.elf
991b70f95156fc46db2ca67ae9f09b2d550c9ee49343b4735dcc284d49e18e81  stage2_payload_loaderfixed.elf
30e9d96666c995e943e537011913d01ba88d99a9eeb19ea79309f7363fa3149b  oracle_epochs/oracle_epoch_0.elf
b73fec05facd10535f7f0eb76b31447279fd6ad04bfc47a9d4ee8395f0cb6f31  oracle_epochs/oracle_epoch_1.elf
77beb98d847776970929b2755504860f5f927f9f10f11554f9b94942a91062d4  oracle_epochs/oracle_epoch_2.elf
2919f2dbf330e314db5a2532190da22cf996f8d1516611552138ebd9ed3282dc  oracle_epochs/oracle_epoch_3.elf
```
