from __future__ import annotations
import argparse
import hashlib
import json
import marshal
import struct
from dataclasses import dataclass
from pathlib import Path


MASK = (1 << 64) - 1
ORACLE_SEED = 0x7D4510A77E21F39B
PAGE_COUNT = 16
BLOCK_COUNT = 80
BLOCKS_PER_PAGE = 5
PAGE_SIZE = 524
BLOCK_OP_COUNT = 8


FRAGMENT_SIZE = 0x800
FRAGMENT_PAYLOAD_SIZE = 0x7C0
FRAGMENT_RESERVED_SIZE = 0x20
FRAGMENT_COUNT = 320
INVALID_INDEX = 0xFFFFFFFF
FLAG_LAST = 0x01
FRAGMENT_RECORD = struct.Struct(f"<{FRAGMENT_PAYLOAD_SIZE}s16sQIHB B{FRAGMENT_RESERVED_SIZE}s")
PLAIN_SIZE_OFF = FRAGMENT_PAYLOAD_SIZE + 16 + 8 + 4
FLAGS_OFF = PLAIN_SIZE_OFF + 2 + 1

PYTHON_START_INDEX = 7
PYTHON_BOOTSTRAP_KEY = bytes.fromhex(
    "5bb87fb26f51c94633f87b6b25f28d73ecb9502ec5da8dbe410e896fc8ce10e0"
)
BRIDGE_START_INDEX = 75
BRIDGE_BOOTSTRAP_KEY = bytes.fromhex(
    "898a44965aed727eb1c952b97426fe712da57455dd01e6475d60ff38a4f81ed4"
)
HOST_ENGINE_START_SHARE = 0x244CE55D
HOST_ENGINE_KEY_SHARE = bytes.fromhex(
    "104a944111c2c1a2d5051be550561f2a8f9e7a968ae77f7baaf43ed0b23e7083"
)
PYD_ENGINE_START_SHARE = 0xEA1C86E6
PYD_ENGINE_KEY_SHARE = bytes.fromhex(
    "b9ee464fd8489c69dcab33c12df3a7d8e89ef55afb1e467bb09249ccb2a17e1f"
)
PUBLIC_STATE_START_INDEX = 13
PUBLIC_STATE_BOOTSTRAP_KEY = bytes.fromhex(
    "0976d6cc77760629a7a341c2c0c139e61e95e616c4095854daed45a07cb49d72"
)

PUBLIC_STATE_ROW_MASKS = (
    (0x0F9ADA19, 0xD7636D27, 0x31764D22, 0x91E3E443, 0x86A3889C, 0xEAE008BE),
    (0xE4ECE900, 0x2DC0CE42, 0x8CEE8546, 0xB24EB415, 0xDB6A2934, 0x78D2E02D),
    (0x8E87D9FB, 0x78048698, 0x9BA38D71, 0xB74B257F, 0x7A8258DB, 0xF0E920DF),
)

HOST_EDGE_OFF = 0x6420
HOST_IMMEDIATE_OFF = 0x6560
HOST_PAGE_OFF = 0x7960
PYD_EDGE_OFF = 0x4910
PYD_OPERAND_OFF = 0x4A50
PYD_IMMEDIATE_OFF = 0x4F50
PYD_PAGE_OFF = 0x6350
ENGINE_PAGE_SHARE_OFF = 0x20842
ENGINE_PAGE_BYTES_OFF = 0x20B70

SBOX = (0x6, 0xB, 0x0, 0x4, 0xD, 0x3, 0xF, 0x8, 0xA, 0x5, 0x9, 0xE, 0x1, 0xC, 0x7, 0x2)
INV_SBOX = tuple(SBOX.index(value) for value in range(16))

OPCODE_NAMES = {
    0x00: "MOV",
    0x01: "MOVI",
    0x02: "XOR",
    0x03: "XORI",
    0x04: "ADD",
    0x05: "ADDI",
    0x06: "SUB",
    0x07: "MUL",
    0x08: "ROL",
    0x0B: "NIBBLE_SBOX",
    0x10: "LOAD_INPUT",
    0x11: "LOAD_KEY",
    0x15: "PY_WINDOW",
    0x17: "TRANSCRIPT",
    0x18: "SWAP3",
    0x1D: "ASSERT_TAG",
    0x1E: "NOISE",
    0x1F: "HALT",
}


@dataclass(frozen=True)
class CoreSchedule:
    round_add_keys: tuple[tuple[int, int, int], ...]
    round_rotations: tuple[tuple[int, int, int, int, int, int], ...]
    round_permutations: tuple[tuple[int, int, int, int, int, int], ...]


@dataclass(frozen=True)
class RecoveredComponents:
    bridge_blob: bytes
    engine_blob: bytes
    carrier_blob: bytes
    final_state_blob: bytes
    details: dict[str, tuple[int, int, int]]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        out.extend(sha256(key + nonce + counter.to_bytes(4, "little")))
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out))


def fragment_u32_mask(current_key: bytes, salt: int, logical_index: int) -> int:
    return int.from_bytes(
        sha256(current_key + salt.to_bytes(8, "little") + logical_index.to_bytes(4, "little"))[:4],
        "little",
    )


def fragment_tag(current_key: bytes, plaintext: bytes, salt: int, logical_index: int) -> bytes:
    return sha256(
        b"tag" + current_key + plaintext + salt.to_bytes(8, "little") + logical_index.to_bytes(4, "little")
    )[:16]


def fragment_next_key(current_key: bytes, ciphertext: bytes, plaintext: bytes, salt: int, logical_index: int) -> bytes:
    tail = plaintext[-32:] if len(plaintext) >= 32 else plaintext
    return sha256(
        current_key
        + sha256(ciphertext)
        + tail
        + salt.to_bytes(8, "little")
        + logical_index.to_bytes(4, "little")
    )


def unpack_fragment(fragment: bytes):
    if len(fragment) != FRAGMENT_SIZE:
        raise ValueError("bad fragment size")
    return FRAGMENT_RECORD.unpack(fragment)


def try_restore_component(fragments: list[bytes], start_index: int, key: bytes) -> bytes | None:
    current_key = key
    logical_index = 0
    index = start_index
    out = bytearray()
    seen: set[int] = set()

    while index != INVALID_INDEX:
        if index >= len(fragments) or index in seen:
            return None
        seen.add(index)

        ciphertext, record_tag, salt, next_encoded, plain_size, _type_encoded, flags, _reserved = unpack_fragment(
            fragments[index]
        )
        if plain_size > FRAGMENT_PAYLOAD_SIZE:
            return None

        plaintext_padded = xor_stream(ciphertext, current_key, salt.to_bytes(8, "little"))
        plaintext = plaintext_padded[:plain_size]
        if fragment_tag(current_key, plaintext, salt, logical_index) != record_tag:
            return None

        out.extend(plaintext)
        next_index = next_encoded ^ fragment_u32_mask(current_key, salt, logical_index)
        current_key = fragment_next_key(current_key, ciphertext, plaintext, salt, logical_index)
        logical_index += 1
        if flags & FLAG_LAST:
            break
        index = next_index

    return bytes(out)


def parse_pe_sections(blob: bytes) -> list[tuple[str, int, int]]:
    if blob[:2] != b"MZ":
        raise ValueError("not a PE file")

    peoff = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[peoff : peoff + 4] != b"PE\0\0":
        raise ValueError("bad PE signature")

    coff = peoff + 4
    _machine, section_count, _ts, _sym, _symcnt, opt_size, _chars = struct.unpack_from("<HHIIIHH", blob, coff)
    sec_off = coff + 20 + opt_size

    sections: list[tuple[str, int, int]] = []
    for index in range(section_count):
        base = sec_off + index * 40
        name = blob[base : base + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        _virtual_size, _virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, base + 8)
        if raw_size and raw_ptr:
            sections.append((name, raw_ptr, raw_size))
    return sections


def plausible_fragment_table(blob: bytes, offset: int) -> bool:
    if offset < 0 or offset + FRAGMENT_COUNT * FRAGMENT_SIZE > len(blob):
        return False
    for index in range(FRAGMENT_COUNT):
        base = offset + index * FRAGMENT_SIZE
        plain_size = struct.unpack_from("<H", blob, base + PLAIN_SIZE_OFF)[0]
        flags = blob[base + FLAGS_OFF]
        if plain_size > FRAGMENT_PAYLOAD_SIZE or flags not in (0, FLAG_LAST):
            return False
    return True


def find_fragment_tables(blob: bytes) -> list[int]:
    tables: list[int] = []
    for _name, raw_ptr, raw_size in parse_pe_sections(blob):
        start = raw_ptr
        end = min(len(blob), raw_ptr + raw_size)
        max_off = end - FRAGMENT_COUNT * FRAGMENT_SIZE
        if max_off < start:
            continue
        for offset in range(start, max_off + 1, 0x10):
            if plausible_fragment_table(blob, offset):
                tables.append(offset)
    return tables


def split_fragments(blob: bytes, table_offset: int) -> list[bytes]:
    return [
        blob[table_offset + index * FRAGMENT_SIZE : table_offset + (index + 1) * FRAGMENT_SIZE]
        for index in range(FRAGMENT_COUNT)
    ]


def looks_like_pe(blob: bytes) -> bool:
    return len(blob) > 0x100 and blob[:2] == b"MZ"


def classify_pe_role(blob: bytes) -> str | None:
    if not looks_like_pe(blob):
        return None
    if b"PyInit_bridge" in blob and b"BridgeBindHost" in blob:
        return "bridge"
    if b"engine_create" in blob and b"engine_resume" in blob and b"engine_destroy" in blob:
        return "engine"
    return None


def extract_code_object(carrier_blob: bytes):
    module_code = marshal.loads(carrier_blob)
    for const in module_code.co_consts:
        if isinstance(const, type(module_code)) and len(const.co_exceptiontable) == 80 * 128:
            return const
    raise ValueError("unable to locate embedded carrier code object")


def carrier_validator(blob: bytes) -> bool:
    try:
        extract_code_object(blob)
        return True
    except Exception:
        return False


def decode_public_final_state(blob: bytes) -> tuple[int, ...]:
    rows = json.loads(blob.decode("utf-8"))
    if not isinstance(rows, list) or len(rows) < len(PUBLIC_STATE_ROW_MASKS):
        raise ValueError("unexpected public final-state payload")

    recovered = []
    for row, masks in zip(rows, PUBLIC_STATE_ROW_MASKS):
        if not isinstance(row, list) or len(row) != 6:
            raise ValueError("unexpected public final-state row")
        recovered.append(tuple((int(value) ^ mask) & MASK for value, mask in zip(row, masks)))

    if len(set(recovered)) != 1:
        raise ValueError("public final-state rows did not recover to one shared state")
    return recovered[0]

def public_state_validator(blob: bytes) -> bool:
    try:
        decode_public_final_state(blob)
        return True
    except Exception:
        return False


def restore_known_component(
    exe_blob: bytes,
    table_offsets: list[int],
    start_index: int,
    key: bytes,
    role: str,
    validator,
) -> tuple[bytes, tuple[int, int, int]]:
    for table_offset in table_offsets:
        restored = try_restore_component(split_fragments(exe_blob, table_offset), start_index, key)
        if restored is None:
            continue
        if validator(restored):
            return restored, (table_offset, start_index, len(restored))
    raise RuntimeError(f"failed to recover {role}")


def recover_components(exe_blob: bytes, table_offsets: list[int]) -> RecoveredComponents:
    details: dict[str, tuple[int, int, int]] = {}

    carrier_blob, details["carrier"] = restore_known_component(
        exe_blob,
        table_offsets,
        PYTHON_START_INDEX,
        PYTHON_BOOTSTRAP_KEY,
        "carrier",
        carrier_validator,
    )
    bridge_blob, details["bridge"] = restore_known_component(
        exe_blob,
        table_offsets,
        BRIDGE_START_INDEX,
        BRIDGE_BOOTSTRAP_KEY,
        "bridge",
        lambda blob: classify_pe_role(blob) == "bridge",
    )

    carrier_state = decode_carrier(carrier_blob)
    engine_start_index = (
        carrier_state["engine_start_share"] ^ PYD_ENGINE_START_SHARE ^ HOST_ENGINE_START_SHARE
    ) & 0xFFFFFFFF
    engine_bootstrap_key = xor_bytes(
        carrier_state["engine_key_share"],
        xor_bytes(PYD_ENGINE_KEY_SHARE, HOST_ENGINE_KEY_SHARE),
    )
    engine_blob, details["engine"] = restore_known_component(
        exe_blob,
        table_offsets,
        engine_start_index,
        engine_bootstrap_key,
        "engine",
        lambda blob: classify_pe_role(blob) == "engine",
    )

    final_state_blob, details["final_state"] = restore_known_component(
        exe_blob,
        table_offsets,
        PUBLIC_STATE_START_INDEX,
        PUBLIC_STATE_BOOTSTRAP_KEY,
        "public final-state blob",
        public_state_validator,
    )

    return RecoveredComponents(
        bridge_blob=bridge_blob,
        engine_blob=engine_blob,
        carrier_blob=carrier_blob,
        final_state_blob=final_state_blob,
        details=details,
    )


def splitmix64(value: int) -> int:
    value = (value + 0x9E3779B97F4A7C15) & MASK
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK
    return (value ^ (value >> 31)) & MASK


def rol64(value: int, rotate: int) -> int:
    rotate &= 63
    if rotate == 0:
        return value & MASK
    return ((value << rotate) & MASK) | ((value & MASK) >> (64 - rotate))


def ror64(value: int, rotate: int) -> int:
    rotate &= 63
    if rotate == 0:
        return value & MASK
    return ((value & MASK) >> rotate) | ((value << (64 - rotate)) & MASK)


def sub64(value: int) -> int:
    out = 0
    for index in range(16):
        nibble = (value >> (index * 4)) & 0xF
        out |= SBOX[nibble] << (index * 4)
    return out & MASK


def inv_sub64(value: int) -> int:
    out = 0
    for index in range(16):
        nibble = (value >> (index * 4)) & 0xF
        out |= INV_SBOX[nibble] << (index * 4)
    return out & MASK


def oracle_mask(block_id: int, transcript: int, nonce: int) -> int:
    wide = pow(nonce ^ ORACLE_SEED ^ block_id, 5)
    wide += transcript << 193
    wide += ((block_id + 1) ** 7) << 311
    wide ^= wide << 131
    wide ^= wide >> 17
    wide ^= wide << 257
    return wide & ((1 << 1024) - 1)


def derive_page_key(
    engine_page_share: bytes,
    python_page_share: bytes,
    pyd_page_share: bytes,
    host_page_share: bytes,
    page_id: int,
) -> bytes:
    combined = bytes(
        a ^ b ^ c ^ d
        for a, b, c, d in zip(engine_page_share, python_page_share, pyd_page_share, host_page_share)
    )
    seed = 0xBABA1F0C0FFE1234
    for offset in range(0, len(combined), 8):
        seed ^= int.from_bytes(combined[offset : offset + 8], "little")
        seed = splitmix64(seed ^ page_id ^ offset)
    out = bytearray()
    for round_index in range(4):
        seed = splitmix64(seed ^ 0x9E3779B97F4A7C15 ^ round_index)
        out.extend(seed.to_bytes(8, "little"))
    return bytes(out)


def keystream(page_key: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        hash_value = 0xCBF29CE484222325
        for byte in page_key:
            hash_value ^= byte
            hash_value = (hash_value * 0x100000001B3) & MASK
        for byte in counter.to_bytes(8, "little"):
            hash_value ^= byte
            hash_value = (hash_value * 0x100000001B3) & MASK
        out.extend(hash_value.to_bytes(8, "little"))
        counter += 1
    return bytes(out[:length])


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def invert_permute_words(words: tuple[int, ...], permutation: tuple[int, ...]) -> tuple[int, ...]:
    out = [0] * 6
    for dst_index, src_index in enumerate(permutation):
        out[src_index] = words[dst_index] & MASK
    return tuple(out)


def invert_babel_round(words: tuple[int, ...], core: CoreSchedule, round_index: int) -> tuple[int, ...]:
    x0, x1, x2, x3, x4, x5 = invert_permute_words(words, core.round_permutations[round_index])
    k0, k1, k2 = core.round_add_keys[round_index]
    r0, r1, r2, r3, r4, r5 = core.round_rotations[round_index]

    x1 = (x1 - rol64(x4, r5)) & MASK
    x5 = (x5 - rol64(x2, r4)) & MASK
    x3 = (x3 - rol64(x0, r3)) & MASK

    x0 = inv_sub64(x0) ^ x5
    x2 = inv_sub64(x2) ^ x1
    x4 = inv_sub64(x4) ^ x3

    x5 = ror64(x5, r2) ^ x4
    x4 = (x4 - x3 - k2) & MASK

    x3 = ror64(x3, r1) ^ x2
    x2 = (x2 - x1 - k1) & MASK

    x1 = ror64(x1, r0) ^ x0
    x0 = (x0 - k0) & MASK
    return x0, x1, x2, x3, x4, x5


def invert_transform(words: tuple[int, ...], core: CoreSchedule) -> tuple[int, ...]:
    state = tuple(word & MASK for word in words)
    for round_index in range(len(core.round_add_keys) - 1, -1, -1):
        state = invert_babel_round(state, core, round_index)
    return state


def pack_words(words: tuple[int, ...]) -> bytes:
    return b"".join((word & MASK).to_bytes(8, "little") for word in words)


def read_u64_array(blob: bytes, offset: int, count: int) -> list[int]:
    return [struct.unpack_from("<Q", blob, offset + index * 8)[0] for index in range(count)]


def read_u32_array(blob: bytes, offset: int, count: int) -> list[int]:
    return [struct.unpack_from("<I", blob, offset + index * 4)[0] for index in range(count)]


def decode_carrier(carrier_blob: bytes) -> dict[str, object]:
    carrier = extract_code_object(carrier_blob)
    qualname = carrier.co_qualname.encode("latin1")
    if not qualname.startswith(b"\xBF\x03"):
        raise ValueError("carrier metadata magic mismatch")

    return {
        "engine_start_share": int.from_bytes(qualname[2:6], "little"),
        "engine_key_share": qualname[6:38],
        "permutation": [ord(ch) for ch in carrier.co_name],
        "stored_chunks": [
            carrier.co_exceptiontable[index * 128 : (index + 1) * 128]
            for index in range(BLOCK_COUNT)
        ],
        "python_page_shares": [
            carrier.co_linetable[index * 32 : (index + 1) * 32]
            for index in range(PAGE_COUNT)
        ],
    }


def recover_python_words(
    carrier_state: dict[str, object],
    block_id: int,
    transcript: int,
) -> tuple[list[int], list[int]]:
    permutation = carrier_state["permutation"]
    physical_id = permutation[block_id]
    nonce = splitmix64(ORACLE_SEED ^ block_id ^ transcript)
    stored_chunk = int.from_bytes(carrier_state["stored_chunks"][physical_id], "little")
    clear_bytes = (stored_chunk ^ oracle_mask(block_id, transcript, nonce)).to_bytes(128, "little")
    python_tokens = [int.from_bytes(clear_bytes[index * 8 : (index + 1) * 8], "little") for index in range(8)]
    python_immediates = [
        int.from_bytes(clear_bytes[(8 + index) * 8 : (9 + index) * 8], "little")
        for index in range(8)
    ]
    return python_tokens, python_immediates


def parse_runtime_binary_data(exe_blob: bytes, bridge_blob: bytes, engine_blob: bytes) -> dict[str, object]:
    host_edge_shares = read_u32_array(exe_blob, HOST_EDGE_OFF, BLOCK_COUNT)
    host_immediate_shares = [
        read_u64_array(exe_blob, HOST_IMMEDIATE_OFF + block_id * BLOCK_OP_COUNT * 8, BLOCK_OP_COUNT)
        for block_id in range(BLOCK_COUNT)
    ]
    host_page_shares = [
        exe_blob[HOST_PAGE_OFF + index * 32 : HOST_PAGE_OFF + (index + 1) * 32]
        for index in range(PAGE_COUNT)
    ]

    pyd_edge_shares = read_u32_array(bridge_blob, PYD_EDGE_OFF, BLOCK_COUNT)
    pyd_operand_tokens = [
        [struct.unpack_from("<H", bridge_blob, PYD_OPERAND_OFF + (block_id * BLOCK_OP_COUNT + slot) * 2)[0] for slot in range(BLOCK_OP_COUNT)]
        for block_id in range(BLOCK_COUNT)
    ]
    pyd_immediate_masks = [
        [
            struct.unpack_from(
                "<Q",
                bridge_blob,
                PYD_IMMEDIATE_OFF + (block_id * BLOCK_OP_COUNT + slot) * 8,
            )[0]
            for slot in range(BLOCK_OP_COUNT)
        ]
        for block_id in range(BLOCK_COUNT)
    ]
    pyd_page_shares = [
        bridge_blob[PYD_PAGE_OFF + index * 32 : PYD_PAGE_OFF + (index + 1) * 32]
        for index in range(PAGE_COUNT)
    ]

    engine_page_shares = [
        engine_blob[ENGINE_PAGE_SHARE_OFF + index * 32 : ENGINE_PAGE_SHARE_OFF + (index + 1) * 32]
        for index in range(PAGE_COUNT)
    ]
    encrypted_pages = [
        engine_blob[ENGINE_PAGE_BYTES_OFF + index * PAGE_SIZE : ENGINE_PAGE_BYTES_OFF + (index + 1) * PAGE_SIZE]
        for index in range(PAGE_COUNT)
    ]

    return {
        "host_edge_shares": host_edge_shares,
        "host_immediate_shares": host_immediate_shares,
        "host_page_shares": host_page_shares,
        "pyd_edge_shares": pyd_edge_shares,
        "pyd_operand_tokens": pyd_operand_tokens,
        "pyd_immediate_masks": pyd_immediate_masks,
        "pyd_page_shares": pyd_page_shares,
        "engine_page_shares": engine_page_shares,
        "encrypted_pages": encrypted_pages,
    }


def decode_engine_page(
    runtime_data: dict[str, object],
    carrier_state: dict[str, object],
    page_id: int,
) -> bytes:
    return xor_bytes(
        runtime_data["encrypted_pages"][page_id],
        keystream(
            derive_page_key(
                runtime_data["engine_page_shares"][page_id],
                carrier_state["python_page_shares"][page_id],
                runtime_data["pyd_page_shares"][page_id],
                runtime_data["host_page_shares"][page_id],
                page_id,
            ),
            PAGE_SIZE,
        ),
    )


def decode_logical_blocks(runtime_data: dict[str, object], carrier_state: dict[str, object]) -> list[tuple[str, int, int, int, int]]:
    transcript = 0
    logical_ops: list[tuple[str, int, int, int, int]] = []
    page_cache: dict[int, bytes] = {}

    for block_id in range(BLOCK_COUNT):
        python_tokens, python_immediates = recover_python_words(carrier_state, block_id, transcript)
        page_id = block_id // BLOCKS_PER_PAGE
        if page_id not in page_cache:
            page_cache[page_id] = decode_engine_page(runtime_data, carrier_state, page_id)
        page_blob = page_cache[page_id]

        block_offset = 4 + (block_id % BLOCKS_PER_PAGE) * 104
        page_block_id = struct.unpack_from("<I", page_blob, block_offset)[0]
        if page_block_id != block_id:
            raise ValueError("decoded page block id mismatch")

        block_offset += 4
        opcode_share = list(page_blob[block_offset : block_offset + 8])
        block_offset += 8
        operand_mask = list(page_blob[block_offset : block_offset + 8])
        block_offset += 8
        engine_immediates = [
            struct.unpack_from("<Q", page_blob, block_offset + slot * 8)[0]
            for slot in range(BLOCK_OP_COUNT)
        ]
        block_offset += 64
        engine_edge_share = struct.unpack_from("<I", page_blob, block_offset)[0]
        block_offset += 4
        successor_a = struct.unpack_from("<I", page_blob, block_offset)[0]
        block_offset += 4
        successor_b = struct.unpack_from("<I", page_blob, block_offset)[0]

        real_successor = (
            runtime_data["host_edge_shares"][block_id]
            ^ runtime_data["pyd_edge_shares"][block_id]
            ^ engine_edge_share
        ) & 0xFFFFFFFF
        predicate = splitmix64(transcript ^ block_id) & 1
        if (successor_b if predicate else successor_a) != real_successor:
            raise ValueError("opaque successor reconstruction mismatch")

        for slot in range(BLOCK_OP_COUNT):
            pyd_token = runtime_data["pyd_operand_tokens"][block_id][slot]
            opcode = opcode_share[slot] ^ (pyd_token & 0x1F) ^ (python_tokens[slot] & 0x1F)
            dst = ((pyd_token >> 5) & 0x0F) ^ (operand_mask[slot] & 0x0F)
            src_a = ((pyd_token >> 9) & 0x0F) ^ ((python_tokens[slot] >> 8) & 0x0F)
            src_b = ((pyd_token >> 13) & 0x0F) ^ ((operand_mask[slot] >> 4) & 0x0F)
            immediate = (
                python_immediates[slot]
                ^ runtime_data["pyd_immediate_masks"][block_id][slot]
                ^ engine_immediates[slot]
                ^ runtime_data["host_immediate_shares"][block_id][slot]
            ) & MASK
            logical_ops.append((OPCODE_NAMES[opcode], dst, src_a, src_b, immediate))

        for opname, _, _, _, immediate in logical_ops[-BLOCK_OP_COUNT:]:
            if opname == "TRANSCRIPT":
                transcript = splitmix64(transcript ^ immediate)

    return logical_ops


def extract_core_schedule(logical_ops: list[tuple[str, int, int, int, int]]) -> CoreSchedule:
    cursor = 24
    round_add_keys: list[tuple[int, int, int]] = []
    round_rotations: list[tuple[int, int, int, int, int, int]] = []
    round_permutations: list[tuple[int, int, int, int, int, int]] = []

    for _ in range(14):
        segment: list[tuple[str, int, int, int, int]] = []
        while True:
            entry = logical_ops[cursor]
            segment.append(entry)
            cursor += 1
            if entry[0] == "TRANSCRIPT":
                break
        while cursor < len(logical_ops) and logical_ops[cursor][0] == "NOISE":
            cursor += 1

        if len(segment) < 42:
            raise ValueError("round segment shorter than expected")

        round_add_keys.append((segment[0][4], segment[4][4], segment[9][4]))
        round_rotations.append((segment[3][4], segment[8][4], segment[13][4], segment[21][4], segment[24][4], segment[27][4]))
        round_permutations.append(tuple(segment[35 + index][2] - 6 for index in range(6)))

    return CoreSchedule(
        round_add_keys=tuple(round_add_keys),
        round_rotations=tuple(round_rotations),
        round_permutations=tuple(round_permutations),
    )


def solve_from_exe(exe_path: Path, verbose: bool = False) -> bytes:
    exe_blob = exe_path.read_bytes()
    table_offsets = find_fragment_tables(exe_blob)
    if not table_offsets:
        raise RuntimeError("unable to locate packed fragment table in EXE")

    components = recover_components(exe_blob, table_offsets)
    final_state = decode_public_final_state(components.final_state_blob)
    carrier_state = decode_carrier(components.carrier_blob)
    runtime_data = parse_runtime_binary_data(exe_blob, components.bridge_blob, components.engine_blob)
    logical_ops = decode_logical_blocks(runtime_data, carrier_state)
    core = extract_core_schedule(logical_ops)
    raw_words = invert_transform(final_state, core)

    if verbose:
        print(f"[+] exe             : {exe_path}")
        print("[+] fragment tables : " + ", ".join(f"0x{offset:X}" for offset in table_offsets))
        for role, detail in sorted(components.details.items()):
            table_offset, start_index, size = detail
            print(f"[+] {role:<13}: table=0x{table_offset:X}, start={start_index}, size={size}")
        print("[+] recovered final_state:")
        for index, word in enumerate(final_state):
            print(f"    state[{index}] = 0x{word:016X}")
        print(f"[+] flag hex        : {pack_words(raw_words).hex()}")

    return pack_words(raw_words)


def main() -> int:
    parser = argparse.ArgumentParser(description="Self-contained static solver for the Babel Furnace release build.")
    parser.add_argument("exe", type=Path, help="packed babel_furnace.exe")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    flag = solve_from_exe(args.exe, verbose=args.verbose)
    print(flag.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
