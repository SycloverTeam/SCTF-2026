from __future__ import annotations

import argparse
import hashlib
import shlex
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


offline_sim = ModuleType("offline_sim_embedded")
sys.modules[offline_sim.__name__] = offline_sim
_OFFLINE_SIM_SOURCE = r'''from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass


CUBE_N = 6
FACE_COUNT = 6
STICKERS_PER_FACE = 36
TOTAL_STICKERS = FACE_COUNT * STICKERS_PER_FACE

AXIS_X = 1
AXIS_Y = 2
AXIS_Z = 4

FACE_U = 0
FACE_D = 1
FACE_F = 2
FACE_B = 3
FACE_R = 4
FACE_L = 5

COLOR_W = 0
COLOR_Y = 1
COLOR_G = 2
COLOR_B = 3
COLOR_R = 4
COLOR_O = 5

DEV_SCRAMBLE = "3Rw U2 F 2L' z Rw2 B 3U"
SESSION_NONCE = 0x4343424343444345
REGISTRY_SALT = 0x7265676973747279
PATH_DIGEST_SEED = SESSION_NONCE ^ 0x504154482D494E49
CAPABILITY_SEED = SESSION_NONCE ^ 0x4341502D494E4954
AUDIT_ROOT_SEED = SESSION_NONCE ^ 0x41554449542D494E
CAPSULE_CHAIN_SEED = SESSION_NONCE ^ 0x43415053554C4521
RUNTIME_FD_SHARE = 0x8F2C3A14D6E1B905
RUNTIME_TLS_SHARE = 0x41B7E3C8925AF06D
RUNTIME_SHM_SHARE = 0xD3A95F0C7E21486B
PEER_PROOF_SALT = (SESSION_NONCE ^ 0x504545522D53414C) & 0xFFFFFFFFFFFFFFFF
# Mirrors sizeof(TokenSlot) on the Linux x86_64 target used by the challenge.
TOKEN_SLOT_SIZE = 48
STAGING_CAPACITY = (4 * 4096) // TOKEN_SLOT_SIZE


@dataclass(frozen=True)
class StickerPos:
    x: int
    y: int
    z: int
    nx: int
    ny: int
    nz: int


@dataclass
class StickerToken:
    visible_color: int
    orientation: int
    generation: int
    hidden_secret: int
    capability_seed: int


@dataclass
class AnchorThreadState:
    running_digest: int
    wake_count: int


@dataclass
class MoveOp:
    axis_onehot: int
    layer_mask: int
    quarter_turns: int
    move_code: int
    is_global_rotation: int
    is_wide: int


@dataclass
class CubeCell:
    pos: StickerPos
    token: StickerToken


@dataclass
class CubeState:
    cells: list[CubeCell]


@dataclass
class FdOwnerEntry:
    pos: StickerPos
    pos_hash: int
    logical_owner: int
    logical_slot: int
    fd_generation: int
    mailbox_kind: int
    ownership_tag: int


@dataclass
class EvaluationDetails:
    visible_digest: int
    hidden_digest: int
    orientation_digest: int
    edge_pair_parity: int
    center_anchor_parity: int
    fd_generation_parity: int
    thread_lifecycle_digest: int
    distributed_route_digest: int
    distributed_tls_mesh_digest: int
    path_digest: int
    capability_chain: int
    step_trace_digest: int
    fd_digest: int
    audit_root: int
    anchor_digest: int
    parser_digest: int
    poison: int


@dataclass
class BlockCapsuleContext:
    block_index: int
    move_count: int
    broker_move_macs: tuple[int, int, int]
    broker_auth: int
    expected_step_receipt: int
    path_digest: int
    capability_chain: int
    anchor_digest: int
    distributed_route_digest: int
    distributed_tls_mesh_digest: int
    last_step_receipt: int
    path_digest_after_block: int
    capability_chain_after_block: int
    anchor_digest_after_block: int
    distributed_route_digest_after_block: int
    distributed_tls_mesh_digest_after_block: int
    capsule_chain_digest_after_block: int
    final_auth: int


_FACE_SLOT_MATERIALS: dict[tuple[int, int], tuple[StickerPos, int, int, int]] = {}
_LINE_POSITIONS_CACHE: dict[tuple[int, int, int], list[StickerPos]] = {}
_FACE_ANCHOR_SLOTS_CACHE: dict[int, list[int]] = {}
_FACE_DECOY_SLOTS_CACHE: dict[int, list[int]] = {}
_SOLVED_STATE_TEMPLATE: CubeState | None = None


def build_rebound_shadow_state() -> list[dict[int, int]]:
    return [dict() for _ in range(FACE_COUNT)]


def splitmix64(state: int) -> tuple[int, int]:
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    z ^= z >> 31
    return z & 0xFFFFFFFFFFFFFFFF, state


def hash64_bytes(data: bytes, seed: int) -> int:
    state = (seed ^ 0x243F6A8885A308D3 ^ len(data)) & 0xFFFFFFFFFFFFFFFF
    for byte in data:
        state ^= (byte + 0x9E3779B97F4A7C15 + ((state << 6) & 0xFFFFFFFFFFFFFFFF) + (state >> 2)) & 0xFFFFFFFFFFFFFFFF
        state, _ = splitmix64(state)
    return state


def hash64_u64(seed: int, value: int) -> int:
    z = (seed + value + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    z ^= z >> 31
    return z & 0xFFFFFFFFFFFFFFFF


def challenge_material_seed(answer: str, scramble: str, session_nonce: int = SESSION_NONCE) -> int:
    material = (
        answer.encode("utf-8")
        + b"\x00"
        + scramble.encode("utf-8")
        + b"\x00"
        + session_nonce.to_bytes(8, "little")
    )
    return hash64_bytes(material, session_nonce ^ 0x4348414C4C2D3655)


def registry_pos_hash(pos: StickerPos, session_nonce: int = SESSION_NONCE, registry_salt: int = REGISTRY_SALT) -> int:
    digest = session_nonce ^ 0x5245474953545259
    digest = hash64_u64(digest, registry_salt)
    digest = hash64_u64(digest, pos.x)
    digest = hash64_u64(digest, pos.y)
    digest = hash64_u64(digest, pos.z)
    digest = hash64_u64(digest, pos.nx + 1)
    digest = hash64_u64(digest, pos.ny + 1)
    digest = hash64_u64(digest, pos.nz + 1)
    return digest


def face_from_normal(nx: int, ny: int, nz: int) -> int:
    if (nx, ny, nz) == (0, 1, 0):
        return FACE_U
    if (nx, ny, nz) == (0, -1, 0):
        return FACE_D
    if (nx, ny, nz) == (0, 0, 1):
        return FACE_F
    if (nx, ny, nz) == (0, 0, -1):
        return FACE_B
    if (nx, ny, nz) == (1, 0, 0):
        return FACE_R
    if (nx, ny, nz) == (-1, 0, 0):
        return FACE_L
    raise ValueError("invalid normal")


def color_char(color: int) -> str:
    return "WYGBRO"[color]


def orientation_from_normal(nx: int, ny: int, nz: int) -> int:
    return face_from_normal(nx, ny, nz)


def face_color(face: int) -> int:
    return [COLOR_W, COLOR_Y, COLOR_G, COLOR_B, COLOR_R, COLOR_O][face]


def centered(value: int) -> int:
    return value * 2 - (CUBE_N - 1)


def from_centered(value: int) -> int:
    return (value + (CUBE_N - 1)) // 2


def rotate_axis_step(a: int, b: int, turns: int) -> tuple[int, int]:
    if turns == 1:
        return b, -a
    if turns == -1:
        return -b, a
    if abs(turns) == 2:
        return -a, -b
    return a, b


def sticker_in_layer(pos: StickerPos, move: MoveOp) -> bool:
    if move.is_global_rotation:
        return True
    coord = {AXIS_X: pos.x, AXIS_Y: pos.y, AXIS_Z: pos.z}[move.axis_onehot]
    return ((move.layer_mask >> coord) & 1) != 0


def rotate_pos(pos: StickerPos, move: MoveOp) -> StickerPos:
    if not sticker_in_layer(pos, move):
        return pos

    x, y, z = centered(pos.x), centered(pos.y), centered(pos.z)
    nx, ny, nz = pos.nx, pos.ny, pos.nz
    turns = 2 if move.quarter_turns == -2 else move.quarter_turns

    if move.axis_onehot == AXIS_X:
        y, z = rotate_axis_step(y, z, turns)
        ny, nz = rotate_axis_step(ny, nz, turns)
    elif move.axis_onehot == AXIS_Y:
        z, x = rotate_axis_step(z, x, turns)
        nz, nx = rotate_axis_step(nz, nx, turns)
    elif move.axis_onehot == AXIS_Z:
        x, y = rotate_axis_step(x, y, turns)
        nx, ny = rotate_axis_step(nx, ny, turns)
    else:
        raise ValueError("invalid axis")

    return StickerPos(from_centered(x), from_centered(y), from_centered(z), nx, ny, nz)


def parse_move(token: str) -> MoveOp:
    if not token or len(token) > 5:
        raise ValueError(f"bad token: {token!r}")

    index = 0
    prefix = 0
    if token[index] in {"2", "3"}:
        prefix = int(token[index])
        index += 1

    if index >= len(token):
        raise ValueError(token)

    face = token[index]
    index += 1
    if face not in "UDFBLRxyz":
        raise ValueError(token)

    wide = False
    if index < len(token) and token[index] == "w":
        wide = True
        index += 1

    if face in "xyz":
        if prefix or wide:
            raise ValueError(token)
        is_global_rotation = 1
        layer_mask = 0x3F
        base_turn = 1
    elif wide:
        width = prefix or 2
        if width not in {2, 3}:
            raise ValueError(token)
        is_global_rotation = 0
        layer_mask = layer_mask_for_span(face, width)
        base_turn = 1 if face in "UFR" else -1
    elif prefix:
        if prefix not in {2, 3}:
            raise ValueError(token)
        is_global_rotation = 0
        layer_mask = 1 << single_layer_for_face(face, prefix)
        base_turn = 1 if face in "UFR" else -1
    else:
        is_global_rotation = 0
        layer_mask = layer_mask_for_span(face, 1)
        base_turn = 1 if face in "UFR" else -1

    suffix = token[index:] if index < len(token) else ""
    if suffix == "":
        quarter_turns = base_turn
    elif suffix == "'":
        quarter_turns = -base_turn
    elif suffix == "2":
        quarter_turns = 2
    else:
        raise ValueError(token)

    axis = {"L": AXIS_X, "R": AXIS_X, "x": AXIS_X, "U": AXIS_Y, "D": AXIS_Y, "y": AXIS_Y, "F": AXIS_Z, "B": AXIS_Z, "z": AXIS_Z}[face]
    return MoveOp(
        axis_onehot=axis,
        layer_mask=layer_mask,
        quarter_turns=quarter_turns,
        move_code=token_move_code(token),
        is_global_rotation=is_global_rotation,
        is_wide=1 if wide else 0,
    )


def token_move_code(token: str) -> int:
    hash_value = 2166136261
    for ch in token.encode():
        hash_value ^= ch
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    return ((hash_value >> 16) ^ hash_value) & 0xFFFF


def single_layer_for_face(face: str, layer_number: int) -> int:
    if face in "UFR":
        return CUBE_N - layer_number
    return layer_number - 1


def layer_mask_for_span(face: str, width: int) -> int:
    mask = 0
    if face in "UFR":
        for i in range(width):
            mask |= 1 << (CUBE_N - 1 - i)
    else:
        for i in range(width):
            mask |= 1 << i
    return mask


def parse_move_line(line: str) -> list[MoveOp]:
    return [parse_move(token) for token in line.split()] if line.strip() else []


def parser_digest_for_moves(moves: list[MoveOp], session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x5041525345522D44
    digest = hash64_u64(digest, len(moves))
    for index, move in enumerate(moves):
        digest = hash64_u64(digest, index)
        digest = hash64_u64(digest, move.move_code)
        digest = hash64_u64(digest, move.axis_onehot)
        digest = hash64_u64(digest, move.layer_mask)
        digest = hash64_u64(digest, move.quarter_turns & 0xFF)
        digest = hash64_u64(digest, move.is_global_rotation)
        digest = hash64_u64(digest, move.is_wide)
    return digest


def move_to_string(move: MoveOp) -> str:
    if move.is_global_rotation:
        face = {AXIS_X: "x", AXIS_Y: "y", AXIS_Z: "z"}[move.axis_onehot]
        return face + ("2" if move.quarter_turns == 2 else "'" if move.quarter_turns == -1 else "")

    layers = [i for i in range(CUBE_N) if (move.layer_mask >> i) & 1]
    positive_face = max(layers) >= CUBE_N // 2
    face = {
        AXIS_X: "R" if positive_face else "L",
        AXIS_Y: "U" if positive_face else "D",
        AXIS_Z: "F" if positive_face else "B",
    }[move.axis_onehot]

    suffix = "2" if move.quarter_turns == 2 else "'" if move.quarter_turns == (-1 if positive_face else 1) else ""

    if len(layers) == 1:
        layer_number = CUBE_N - max(layers) if positive_face else min(layers) + 1
        return f"{face}{suffix}" if layer_number == 1 else f"{layer_number}{face}{suffix}"
    if len(layers) == 2:
        return f"{face}w{suffix}"
    if len(layers) == 3:
        return f"3{face}w{suffix}"
    raise ValueError("unsupported layer mask")


def inverse_move(move: MoveOp) -> MoveOp:
    turns = move.quarter_turns
    if turns == 2:
        inverse_turns = 2
    else:
        inverse_turns = -turns
    return MoveOp(
        axis_onehot=move.axis_onehot,
        layer_mask=move.layer_mask,
        quarter_turns=inverse_turns,
        move_code=move.move_code,
        is_global_rotation=move.is_global_rotation,
        is_wide=move.is_wide,
    )


def inverse_move_line(line: str) -> str:
    moves = parse_move_line(line)
    return " ".join(move_to_string(inverse_move(move)) for move in reversed(moves))


def slice_worker_key(axis_onehot: int, layer_index: int, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x534C4943452D3655
    digest = hash64_u64(digest, axis_onehot)
    digest = hash64_u64(digest, layer_index)
    return digest


def slice_participates(axis_onehot: int, layer_index: int, move: MoveOp) -> bool:
    if move.is_global_rotation:
        return True
    if move.axis_onehot != axis_onehot:
        return False
    return ((move.layer_mask >> layer_index) & 1) != 0


def active_slice_worker_keys(move: MoveOp) -> list[tuple[int, int]]:
    return [
        (axis_onehot, layer_index)
        for axis_onehot in (AXIS_X, AXIS_Y, AXIS_Z)
        for layer_index in range(CUBE_N)
        if slice_participates(axis_onehot, layer_index, move)
    ]


def slice_payload_digest(axis_onehot: int, layer_index: int, move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    worker_key = slice_worker_key(axis_onehot, layer_index, session_nonce)
    digest = worker_key ^ 0x534C494345444947
    digest = hash64_u64(digest, axis_onehot)
    digest = hash64_u64(digest, layer_index)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, move.layer_mask)
    digest = hash64_u64(digest, move.quarter_turns & 0xFF)
    digest = hash64_u64(digest, move.is_global_rotation)
    digest = hash64_u64(digest, move.is_wide)
    return digest


def slice_ack_digest(worker_key: int, payload_digest: int, epoch: int) -> int:
    digest = worker_key ^ 0x41434B2D534C4943
    digest = hash64_u64(digest, payload_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def slice_stage_digests(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> tuple[int, int]:
    orbit = session_nonce ^ 0x4F524249542D3655
    ack_aggregate = session_nonce ^ 0x41434B2D36554C4C
    registry_digest = session_nonce ^ 0x5245472D534C4943
    slice_trace_digest = session_nonce ^ 0x534C4958452D5452
    registry_digest = hash64_u64(registry_digest, epoch)
    registry_digest = hash64_u64(registry_digest, move.move_code)

    for cell in solved_state().cells:
        target_pos = rotate_pos(cell.pos, move)
        source_pos_hash = registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT)
        target_pos_hash = registry_pos_hash(target_pos, session_nonce, REGISTRY_SALT)
        if not sticker_in_layer(cell.pos, move):
            continue
        source_face, _, _ = face_row_col(cell.pos)
        target_face, _, _ = face_row_col(target_pos)
        source_capability_mask = hash64_u64(session_nonce ^ 0x4341502D4D41534B, source_pos_hash)
        target_capability_mask = hash64_u64(session_nonce ^ 0x4341502D4D41534B, target_pos_hash)
        source_integrity_tag = hash64_u64(source_capability_mask, source_pos_hash)
        target_integrity_tag = hash64_u64(target_capability_mask, target_pos_hash)
        registry_digest = hash64_u64(registry_digest, source_pos_hash)
        registry_digest = hash64_u64(registry_digest, target_pos_hash)
        registry_digest = hash64_u64(registry_digest, source_integrity_tag)
        registry_digest = hash64_u64(registry_digest, target_integrity_tag)
        registry_digest = hash64_u64(registry_digest, source_face)
        registry_digest = hash64_u64(registry_digest, target_face)

    orbit = hash64_u64(orbit, registry_digest)
    slice_trace_digest = hash64_u64(slice_trace_digest, registry_digest)
    slice_trace_digest = hash64_u64(slice_trace_digest, epoch)
    slice_trace_digest = hash64_u64(slice_trace_digest, move.move_code)

    for axis, layer_index in active_slice_worker_keys(move):
        worker_key = slice_worker_key(axis, layer_index, session_nonce)
        payload = slice_payload_digest(axis, layer_index, move, epoch, session_nonce)
        capability = hash64_u64(
            worker_key ^ slice_ack_digest(worker_key, payload, epoch),
            payload ^ ((axis << 32) | layer_index),
        )
        orbit = hash64_u64(orbit, payload)
        ack_aggregate = hash64_u64(ack_aggregate, slice_ack_digest(worker_key, payload, epoch))
        slice_trace_digest = hash64_u64(slice_trace_digest, payload)
        slice_trace_digest = hash64_u64(slice_trace_digest, slice_ack_digest(worker_key, payload, epoch))
        slice_trace_digest = hash64_u64(slice_trace_digest, capability)

    return hash64_u64(orbit, ack_aggregate), hash64_u64(slice_trace_digest, ack_aggregate)


def orbit_digest_for_move(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    return slice_stage_digests(move, epoch, session_nonce)[0]


def face_worker_key(face_id: int, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x464143452D574B52
    digest = hash64_u64(digest, face_id)
    return digest


def line_worker_key(session_nonce: int, face_id: int, is_row: int, line_index: int) -> int:
    digest = session_nonce ^ 0x4C494E452D574B52
    digest = hash64_u64(digest, face_id)
    digest = hash64_u64(digest, is_row)
    digest = hash64_u64(digest, line_index)
    return digest


def face_mailboxes_for_line(is_row: int, line_index: int) -> list[int]:
    return [line_index * 6 + i for i in range(6)] if is_row else [line_index + i * 6 for i in range(6)]


def face_mailbox_kind(sticker_index: int, face_id: int | None = None) -> int:
    if face_id is not None and sticker_index in set(face_decoy_slots(face_id)):
        return 2
    row, col = divmod(sticker_index, CUBE_N)
    top_or_bottom = row in {0, CUBE_N - 1}
    left_or_right = col in {0, CUBE_N - 1}
    if (top_or_bottom or left_or_right) and not (top_or_bottom and left_or_right):
        return 1
    return 0


def face_anchor_slots(face_id: int) -> list[int]:
    if face_id in _FACE_ANCHOR_SLOTS_CACHE:
        return list(_FACE_ANCHOR_SLOTS_CACHE[face_id])

    candidates: list[tuple[int, int]] = []
    state = solved_state()
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face != face_id or not (1 <= row <= 4 and 1 <= col <= 4):
            continue
        slot = row * 6 + col
        score = SESSION_NONCE ^ REGISTRY_SALT ^ 0x414E43484F522D53
        score = hash64_u64(score, face)
        score = hash64_u64(score, row)
        score = hash64_u64(score, col)
        score = hash64_u64(score, registry_pos_hash(cell.pos))
        candidates.append((score, slot))
    candidates.sort(key=lambda item: item[0])
    _FACE_ANCHOR_SLOTS_CACHE[face_id] = [slot for _, slot in candidates[:4]]
    return list(_FACE_ANCHOR_SLOTS_CACHE[face_id])


def face_decoy_slots(face_id: int) -> list[int]:
    if face_id in _FACE_DECOY_SLOTS_CACHE:
        return list(_FACE_DECOY_SLOTS_CACHE[face_id])

    anchors = set(face_anchor_slots(face_id))
    candidates: list[tuple[int, int]] = []
    state = solved_state()
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face != face_id or not (1 <= row <= 4 and 1 <= col <= 4):
            continue
        slot = row * 6 + col
        if slot in anchors:
            continue
        score = SESSION_NONCE ^ REGISTRY_SALT ^ 0x4445434F592D534C
        score = hash64_u64(score, face)
        score = hash64_u64(score, row)
        score = hash64_u64(score, col)
        score = hash64_u64(score, registry_pos_hash(cell.pos))
        candidates.append((score, slot))
    candidates.sort(key=lambda item: item[0])
    _FACE_DECOY_SLOTS_CACHE[face_id] = [slot for _, slot in candidates[:4]]
    return list(_FACE_DECOY_SLOTS_CACHE[face_id])


def line_positions(face_id: int, is_row: int, line_index: int) -> list[StickerPos]:
    key = (face_id, is_row, line_index)
    if key in _LINE_POSITIONS_CACHE:
        return list(_LINE_POSITIONS_CACHE[key])

    positions: list[StickerPos] = []
    state = solved_state()

    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face == face_id and ((is_row and row == line_index) or (not is_row and col == line_index)):
            positions.append(cell.pos)
    _LINE_POSITIONS_CACHE[key] = list(positions)
    return positions


def face_is_on_move_axis(face_id: int, axis_onehot: int) -> bool:
    return (
        (axis_onehot == AXIS_X and face_id in {FACE_R, FACE_L}) or
        (axis_onehot == AXIS_Y and face_id in {FACE_U, FACE_D}) or
        (axis_onehot == AXIS_Z and face_id in {FACE_F, FACE_B})
    )


def line_active(face_id: int, is_row: int, line_index: int, move: MoveOp) -> bool:
    positions = line_positions(face_id, is_row, line_index)

    if move.is_global_rotation:
        return True
    if face_is_on_move_axis(face_id, move.axis_onehot):
        return is_row == 1 and all(sticker_in_layer(pos, move) for pos in positions)
    return all(sticker_in_layer(pos, move) for pos in positions)


def active_line_worker_keys(move: MoveOp) -> list[tuple[int, int, int]]:
    active: list[tuple[int, int, int]] = []
    for face_id in range(FACE_COUNT):
        for slot in range(12):
            is_row = 1 if slot < 6 else 0
            line_index = slot if is_row else slot - 6
            if line_active(face_id, is_row, line_index, move):
                active.append((face_id, is_row, line_index))
    return active


def clone_token(token: StickerToken) -> StickerToken:
    return StickerToken(
        visible_color=token.visible_color,
        orientation=token.orientation,
        generation=token.generation,
        hidden_secret=token.hidden_secret,
        capability_seed=token.capability_seed,
    )


def clone_state(state: CubeState) -> CubeState:
    return CubeState(
        [
            CubeCell(
                pos=cell.pos,
                token=clone_token(cell.token),
            )
            for cell in state.cells
        ]
    )


def build_face_thread_tokens(state: CubeState | None = None) -> list[list[StickerToken]]:
    if state is None:
        state = solved_state()

    face_tokens: list[list[StickerToken]] = [
        [StickerToken(0, 0, 0, 0, 0) for _ in range(STICKERS_PER_FACE)]
        for _ in range(FACE_COUNT)
    ]
    for cell in state.cells:
        face_id, row, col = face_row_col(cell.pos)
        face_tokens[face_id][row * 6 + col] = clone_token(cell.token)
    return face_tokens


def build_anchor_thread_states() -> list[dict[int, AnchorThreadState]]:
    states: list[dict[int, AnchorThreadState]] = []
    for face_id in range(FACE_COUNT):
        face_state: dict[int, AnchorThreadState] = {}
        for sticker_index in face_anchor_slots(face_id):
            _, _, running_seed = anchor_thread_material(face_id, sticker_index)
            face_state[sticker_index] = AnchorThreadState(running_digest=running_seed, wake_count=0)
        states.append(face_state)
    return states


def face_sticker_material(face_id: int, sticker_index: int) -> tuple[StickerPos, int, int, int]:
    key = (face_id, sticker_index)
    if key in _FACE_SLOT_MATERIALS:
        return _FACE_SLOT_MATERIALS[key]

    state = solved_state()
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face == face_id and row * 6 + col == sticker_index:
            position_hash = registry_pos_hash(cell.pos)
            token_secret = hash64_u64(position_hash ^ 0x535449434B455254, sticker_index)
            capability_seed = hash64_u64(token_secret ^ 0x4341502D54485244, face_id)
            _FACE_SLOT_MATERIALS[key] = (cell.pos, position_hash, token_secret, capability_seed)
            return _FACE_SLOT_MATERIALS[key]
    raise ValueError("sticker index not found")


def anchor_thread_material(face_id: int, sticker_index: int) -> tuple[int, int, int]:
    _, position_hash, token_secret, capability_seed = face_sticker_material(face_id, sticker_index)
    anchor_secret = hash64_u64(position_hash ^ SESSION_NONCE, face_id)
    anchor_parity = hash64_u64(anchor_secret, sticker_index)
    running_seed = hash64_u64(anchor_parity, position_hash)
    return anchor_secret, anchor_parity, running_seed


def anchor_thread_ack(
    face_id: int,
    sticker_index: int,
    epoch: int,
    line_slot: int,
    move_code: int,
    fd_digest_before_rebind: int,
    anchor_thread_states: list[dict[int, AnchorThreadState]],
) -> int:
    _, position_hash, _, _ = face_sticker_material(face_id, sticker_index)
    anchor_secret, anchor_parity, running_seed = anchor_thread_material(face_id, sticker_index)
    state = anchor_thread_states[face_id].setdefault(
        sticker_index,
        AnchorThreadState(running_digest=running_seed, wake_count=0),
    )
    running_digest = state.running_digest
    running_digest = hash64_u64(running_digest ^ anchor_secret, epoch)
    running_digest = hash64_u64(running_digest, line_slot)
    running_digest = hash64_u64(running_digest, move_code)
    running_digest = hash64_u64(running_digest, fd_digest_before_rebind)
    running_digest = hash64_u64(running_digest, anchor_parity)
    running_digest = hash64_u64(running_digest, position_hash)
    state.running_digest = running_digest
    state.wake_count += 1
    return hash64_u64(running_digest, state.wake_count)


def sticker_ack_tag(
    position_hash: int,
    token_secret: int,
    capability_seed: int,
    mailbox_kind: int,
    generation: int,
    orientation: int,
    epoch: int,
    line_slot: int,
    move_code: int,
    fd_digest_before_rebind: int,
) -> int:
    local_digest = hash64_u64(position_hash ^ capability_seed, epoch)
    local_digest = hash64_u64(local_digest, line_slot)
    local_digest = hash64_u64(local_digest, move_code)
    local_digest = hash64_u64(local_digest, fd_digest_before_rebind)
    local_digest = hash64_u64(local_digest, mailbox_kind)
    local_digest = hash64_u64(local_digest, generation)
    local_digest = hash64_u64(local_digest, orientation)
    ack_tag = hash64_u64(local_digest ^ token_secret, capability_seed)
    ack_tag = hash64_u64(ack_tag, epoch)
    return ack_tag


def sticker_commit_tag(prepare_ack: int, target_staging_slot: int, epoch: int, token: StickerToken) -> int:
    digest = hash64_u64(prepare_ack ^ 0x434F4D4D49542D21, target_staging_slot)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, token.hidden_secret)
    digest = hash64_u64(digest, token.capability_seed)
    digest = hash64_u64(digest, token.generation)
    digest = hash64_u64(digest, token.orientation)
    digest = hash64_u64(digest, token.visible_color)
    return digest


def staging_slots_for_face_epoch(epoch: int, face_id: int, capacity: int = STAGING_CAPACITY) -> list[int]:
    base = ((epoch - 1) * FACE_COUNT * 6) + (face_id * 6)
    return [((base + offset) % capacity) for offset in range(6)]


def face_line_shift(move: MoveOp) -> int:
    if abs(move.quarter_turns) == 2:
        return 3
    if move.quarter_turns == -1:
        return 5
    return 1


def tx_trace_step(trace: int, state: int, value: int) -> int:
    trace = hash64_u64(trace, state)
    trace = hash64_u64(trace, value)
    return trace


def face_tx_trace_digest(
    epoch: int,
    line_slot: int,
    move: MoveOp,
    fd_digest_before_rebind: int,
    staging_digest: int,
    ack_digest: int,
    swap_digest: int,
    face_digest_after: int,
) -> int:
    tx_id = epoch ^ (line_slot << 16)
    trace = 0x54582D434F524F55
    trace = hash64_u64(trace, tx_id)
    trace = hash64_u64(trace, epoch)
    trace = hash64_u64(trace, move.move_code)
    trace = tx_trace_step(trace, 2, fd_digest_before_rebind)
    trace = tx_trace_step(trace, 2, fd_digest_before_rebind ^ line_slot)
    trace = tx_trace_step(trace, 1, staging_digest)
    trace = tx_trace_step(trace, 3, ack_digest)
    trace = tx_trace_step(trace, 4, swap_digest)
    trace = tx_trace_step(trace, 5, face_digest_after)
    trace = tx_trace_step(trace, 6, tx_id ^ face_digest_after)
    return trace


def face_digest_components(
    worker_key: int,
    face_id: int,
    epoch: int,
    move: MoveOp,
    line_slot: int,
    line_index: int,
    is_row: int,
    fd_digest_before_rebind: int,
    face_thread_tokens: list[list[StickerToken]],
    anchor_thread_states: list[dict[int, AnchorThreadState]],
    rebound_shadow_state: list[dict[int, int]] | None = None,
) -> tuple[int, int, int]:
    ready_mask = 0
    ack_digest = worker_key ^ 0x41434B2D46414345
    commit_digest = worker_key ^ 0x434F4D4D49542D21
    staging_digest = worker_key ^ 0x53544147494E472D
    anchor_slots = set(face_anchor_slots(face_id))
    line_slots = face_mailboxes_for_line(is_row, line_index)
    staging_slots = staging_slots_for_face_epoch(epoch, face_id)
    shift = face_line_shift(move)
    prepare_acks: list[int] = []
    staging_tokens: list[StickerToken] = []
    for logical in line_slots:
        ready_mask |= 1 << logical
        token = clone_token(face_thread_tokens[face_id][logical])
        _, position_hash, _, _ = face_sticker_material(face_id, logical)
        staging_tokens.append(token)
        prepare_ack = sticker_ack_tag(
            position_hash,
            token.hidden_secret,
            token.capability_seed,
            face_mailbox_kind(logical, face_id),
            token.generation,
            token.orientation,
            epoch,
            line_slot,
            move.move_code,
            fd_digest_before_rebind,
        )
        prepare_acks.append(prepare_ack)
        staging_digest = hash64_u64(staging_digest, position_hash)
        staging_digest = hash64_u64(staging_digest, token.visible_color)
        staging_digest = hash64_u64(staging_digest, token.orientation)
        staging_digest = hash64_u64(staging_digest, token.generation)
        staging_digest = hash64_u64(staging_digest, token.hidden_secret)
        staging_digest = hash64_u64(staging_digest, token.capability_seed)
        staging_digest = hash64_u64(staging_digest, prepare_ack)
        ack_digest = hash64_u64(ack_digest, prepare_ack)
        if rebound_shadow_state is not None and logical in rebound_shadow_state[face_id]:
            ack_digest = hash64_u64(ack_digest, rebound_shadow_state[face_id][logical])
            ack_digest = hash64_u64(ack_digest, 1)
        if logical in anchor_slots:
            ack_digest = hash64_u64(
                ack_digest,
                anchor_thread_ack(
                    face_id,
                    logical,
                    epoch,
                    line_slot,
                    move.move_code,
                    fd_digest_before_rebind,
                    anchor_thread_states,
                ),
            )
    for i, prepare_ack in enumerate(prepare_acks):
        committed = clone_token(staging_tokens[(i + 6 - shift) % 6])
        target_pos, _, _, _ = face_sticker_material(face_id, line_slots[i])
        committed.generation = (committed.generation + 1) & 0xFFFF
        committed.orientation = orientation_from_normal(target_pos.nx, target_pos.ny, target_pos.nz)
        face_thread_tokens[face_id][line_slots[i]] = committed
        target_staging_slot = staging_slots[(i + 6 - shift) % 6]
        commit_digest = hash64_u64(
            commit_digest,
            sticker_commit_tag(prepare_ack, target_staging_slot, epoch, committed),
        )

    digest = worker_key ^ 0x464143452D444947
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, line_slot)
    digest = hash64_u64(digest, line_index)
    digest = hash64_u64(digest, is_row)
    digest = hash64_u64(digest, fd_digest_before_rebind)
    digest = hash64_u64(digest, ready_mask)
    digest = hash64_u64(digest, staging_digest)
    digest = hash64_u64(digest, ack_digest)
    digest = hash64_u64(digest, commit_digest)
    ack_commit_digest = hash64_u64(ack_digest ^ 0x434F4D4D49542D21, commit_digest)
    swap_capability = hash64_u64(staging_digest ^ ready_mask, ack_digest)
    tx_trace = face_tx_trace_digest(
        epoch,
        line_slot,
        move,
        fd_digest_before_rebind,
        staging_digest,
        ack_digest,
        hash64_u64(staging_digest ^ ack_digest, swap_capability),
        commit_digest ^ ready_mask,
    )
    face_route_digest = hash64_u64(tx_trace ^ worker_key, digest)
    face_route_digest = hash64_u64(face_route_digest, ack_commit_digest)
    face_route_digest = hash64_u64(face_route_digest, commit_digest)
    return digest, ack_commit_digest, face_route_digest


def line_digest(
    worker_key: int,
    move: MoveOp,
    epoch: int,
    face_digest_value: int,
    face_id: int,
    is_row: int,
    line_index: int,
) -> int:
    digest = worker_key ^ 0x4C494E452D444947
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, face_digest_value)
    digest = hash64_u64(digest, face_id)
    digest = hash64_u64(digest, is_row)
    digest = hash64_u64(digest, line_index)
    return digest


def line_reply_capability(
    face_route_digest: int,
    line_digest_value: int,
    ack_digest: int,
    face_id: int,
    is_row: int,
    line_index: int,
) -> int:
    digest = hash64_u64(face_route_digest ^ line_digest_value, ack_digest)
    digest = hash64_u64(digest, (face_id << 16) | (is_row << 8) | line_index)
    return digest


def watchdog_key(session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x5741544348444F47
    digest = hash64_u64(digest, 0x4E4F4953452D4644)
    return digest


def watchdog_event_index(move: MoveOp, epoch: int) -> int:
    digest = 0x5741544348494E44
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    return digest % 8


def watchdog_noise_digest(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    worker_key = watchdog_key(session_nonce)
    event_index = watchdog_event_index(move, epoch)
    counter_value = 1
    signal_number = 10  # SIGUSR1 on Linux

    digest = worker_key ^ 0x5741544348444447
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, event_index)
    digest = hash64_u64(digest, counter_value)
    digest = hash64_u64(digest, signal_number)
    return digest


def watchdog_trace_digest(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    worker_key = watchdog_key(session_nonce)
    noise_digest = watchdog_noise_digest(move, epoch, session_nonce)
    payload1 = (watchdog_event_index(move, epoch) << 32) | 10
    capability = hash64_u64(worker_key ^ noise_digest, epoch)
    digest = session_nonce ^ 0x5741544348545243
    digest = hash64_u64(digest, noise_digest)
    digest = hash64_u64(digest, payload1)
    digest = hash64_u64(digest, capability)
    return digest


def line_stage_digests(
    move: MoveOp,
    epoch: int,
    slice_orbit: int,
    fd_digest_before_rebind: int,
    face_thread_tokens: list[list[StickerToken]] | None = None,
    anchor_thread_states: list[dict[int, AnchorThreadState]] | None = None,
    rebound_shadow_state: list[dict[int, int]] | None = None,
    session_nonce: int = SESSION_NONCE,
) -> tuple[int, int]:
    line_aggregate = session_nonce ^ 0x4C494E452D414747
    line_trace_digest = session_nonce ^ 0x4C494E4554524143
    line_trace_digest = hash64_u64(line_trace_digest, epoch)
    line_trace_digest = hash64_u64(line_trace_digest, move.move_code)
    if face_thread_tokens is None:
        face_thread_tokens = build_face_thread_tokens()
    if anchor_thread_states is None:
        anchor_thread_states = build_anchor_thread_states()

    for face_id, is_row, line_index in active_line_worker_keys(move):
        slot = line_index if is_row else line_index + 6
        f_digest, ack_digest, face_route_digest = face_digest_components(
            face_worker_key(face_id, session_nonce),
            face_id,
            epoch,
            move,
            slot,
            line_index,
            is_row,
            fd_digest_before_rebind,
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        l_digest = line_digest(
            line_worker_key(session_nonce, face_id, is_row, line_index),
            move,
            epoch,
            f_digest,
            face_id,
            is_row,
            line_index,
        )
        line_capability = line_reply_capability(
            face_route_digest,
            l_digest,
            ack_digest,
            face_id,
            is_row,
            line_index,
        )
        line_aggregate = hash64_u64(line_aggregate, l_digest)
        line_aggregate = hash64_u64(line_aggregate, ack_digest)
        line_trace_digest = hash64_u64(line_trace_digest, l_digest)
        line_trace_digest = hash64_u64(line_trace_digest, ack_digest)
        line_trace_digest = hash64_u64(line_trace_digest, line_capability)

    return (
        hash64_u64(slice_orbit ^ 0x4C494E452D464F4C, line_aggregate),
        hash64_u64(line_trace_digest, line_aggregate),
    )


def full_orbit_digest_for_move(
    move: MoveOp,
    epoch: int,
    fd_digest_before_rebind: int,
    face_thread_tokens: list[list[StickerToken]] | None = None,
    anchor_thread_states: list[dict[int, AnchorThreadState]] | None = None,
    rebound_shadow_state: list[dict[int, int]] | None = None,
    session_nonce: int = SESSION_NONCE,
) -> int:
    slice_orbit, _ = slice_stage_digests(move, epoch, session_nonce)
    line_orbit, _ = line_stage_digests(
        move,
        epoch,
        slice_orbit,
        fd_digest_before_rebind,
        face_thread_tokens,
        anchor_thread_states,
        rebound_shadow_state,
        session_nonce,
    )
    return hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch, session_nonce))


def fd_owner_tag(entry: FdOwnerEntry) -> int:
    digest = entry.pos_hash ^ 0x46444F574E455231
    digest = hash64_u64(digest, entry.logical_owner)
    digest = hash64_u64(digest, entry.logical_slot)
    digest = hash64_u64(digest, entry.fd_generation)
    digest = hash64_u64(digest, entry.mailbox_kind)
    digest = hash64_u64(digest, entry.pos.x)
    digest = hash64_u64(digest, entry.pos.y)
    digest = hash64_u64(digest, entry.pos.z)
    digest = hash64_u64(digest, entry.pos.nx + 1)
    digest = hash64_u64(digest, entry.pos.ny + 1)
    digest = hash64_u64(digest, entry.pos.nz + 1)
    return digest


def anchor_hint_from_state(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x414E43484F522D44
    chosen: list[list[tuple[int, CubeCell, int, int]]] = [[] for _ in range(FACE_COUNT)]

    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if not (1 <= row <= 4 and 1 <= col <= 4):
            continue
        pos_hash = registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT)
        score = session_nonce ^ 0x414E43484F522D53
        score = hash64_u64(score, face)
        score = hash64_u64(score, row)
        score = hash64_u64(score, col)
        score = hash64_u64(score, pos_hash)
        chosen[face].append((score, cell, row, col))

    for face in range(FACE_COUNT):
        anchors = sorted(chosen[face], key=lambda item: item[0])[:4]
        for slot, (score, cell, row, col) in enumerate(anchors):
            digest = hash64_u64(digest, face)
            digest = hash64_u64(digest, slot)
            digest = hash64_u64(digest, row)
            digest = hash64_u64(digest, col)
            digest = hash64_u64(digest, score)
            digest = hash64_u64(digest, cell.token.hidden_secret)
            digest = hash64_u64(digest, cell.token.capability_seed)
            digest = hash64_u64(digest, cell.token.generation)
            digest = hash64_u64(digest, cell.token.orientation)
            digest = hash64_u64(digest, cell.token.visible_color)
    return digest


def courier_key(session_nonce: int = SESSION_NONCE) -> int:
    return hash64_u64(session_nonce ^ 0x4355524945522D54, 0x4C53312D434F5552)


def courier_seed(session_nonce: int = SESSION_NONCE) -> int:
    return hash64_u64(courier_key(session_nonce), session_nonce)


def courier_digest_step(
    running_digest: int,
    anchor_hint: int,
    epoch: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    running_digest = hash64_u64(running_digest ^ courier_key(session_nonce), anchor_hint)
    return hash64_u64(running_digest, epoch)


def fd_owners_digest(entries: list[FdOwnerEntry]) -> int:
    digest = 0x46444F574E2D4447
    for entry in entries:
        digest = hash64_u64(digest, entry.pos_hash)
        digest = hash64_u64(digest, entry.logical_owner)
        digest = hash64_u64(digest, entry.logical_slot)
        digest = hash64_u64(digest, entry.fd_generation)
        digest = hash64_u64(digest, entry.ownership_tag)
    return digest


def fd_owner_index_for_pos(entries: list[FdOwnerEntry], pos: StickerPos) -> int:
    for index, entry in enumerate(entries):
        if entry.pos == pos:
            return index
    raise ValueError(f"fd owner position not found: {pos!r}")


def build_fd_owners() -> list[FdOwnerEntry]:
    state = solved_state()
    entries: list[FdOwnerEntry] = []
    for index, cell in enumerate(state.cells):
        entry = FdOwnerEntry(
            pos=cell.pos,
            pos_hash=registry_pos_hash(cell.pos),
            logical_owner=face_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz),
            logical_slot=index % STICKERS_PER_FACE,
            fd_generation=0,
            mailbox_kind=face_mailbox_kind(index % STICKERS_PER_FACE, face_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz)),
            ownership_tag=0,
        )
        entry.ownership_tag = fd_owner_tag(entry)
        entries.append(entry)
    return entries


def rebind_fd_owners(entries: list[FdOwnerEntry], move: MoveOp) -> tuple[list[FdOwnerEntry], int]:
    next_entries, digest, _, _, _ = rebind_fd_owners_with_sample(entries, move)
    return next_entries, digest


def rebind_fd_owners_with_sample(entries: list[FdOwnerEntry], move: MoveOp) -> tuple[list[FdOwnerEntry], int, int, int, int]:
    next_entries = [
        FdOwnerEntry(
            pos=entry.pos,
            pos_hash=entry.pos_hash,
            logical_owner=entry.logical_owner,
            logical_slot=entry.logical_slot,
            fd_generation=entry.fd_generation,
            mailbox_kind=entry.mailbox_kind,
            ownership_tag=entry.ownership_tag,
        )
        for entry in entries
    ]
    sample_owner_face = -1
    sample_local_slot = -1
    sample_generation = 0

    for entry in entries:
        dst_pos = rotate_pos(entry.pos, move)
        dst_index = fd_owner_index_for_pos(entries, dst_pos)
        moved = sticker_in_layer(entry.pos, move)
        next_entries[dst_index].logical_owner = entry.logical_owner
        next_entries[dst_index].logical_slot = entry.logical_slot
        next_entries[dst_index].mailbox_kind = entry.mailbox_kind
        next_entries[dst_index].fd_generation = entry.fd_generation + (1 if moved else 0)
        if moved and next_entries[dst_index].mailbox_kind != 2 and sample_owner_face < 0:
            sample_owner_face = next_entries[dst_index].logical_owner
            sample_local_slot = next_entries[dst_index].logical_slot
            sample_generation = next_entries[dst_index].fd_generation

    for entry in next_entries:
        entry.ownership_tag = fd_owner_tag(entry)
    return next_entries, fd_owners_digest(next_entries), sample_owner_face, sample_local_slot, sample_generation


def broker_trace_digest(
    fd_digest: int,
    sample_owner_face: int,
    sample_local_slot: int,
    sample_generation: int,
    epoch: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    worker_key = hash64_u64(session_nonce ^ 0x42524F4B45522D36, 0x46442D4F574E4552)
    payload1 = (
        ((sample_owner_face & 0xFF) << 56)
        | ((sample_local_slot & 0xFF) << 48)
        | (1 << 32)
        | (sample_generation & 0xFFFFFFFF)
    )
    capability = hash64_u64(worker_key ^ fd_digest, payload1 ^ epoch)
    digest = session_nonce ^ 0x42524F4B45525452
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, payload1)
    digest = hash64_u64(digest, capability)
    digest = hash64_u64(digest, 1)
    return digest


def capability_step(
    capability_chain: int,
    move: MoveOp,
    orbit_digest: int,
    fd_digest: int,
    anchor_digest: int,
    epoch: int,
    visible: int,
    hidden: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = capability_chain ^ 0x4341502D43484149
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, orbit_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, session_nonce)
    return digest


def epoch_key_seed(session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x45504F43484B4559
    digest = hash64_u64(digest, 0x535445502D534545)
    return digest


def step_proof(
    capability_chain: int,
    path_digest_before: int,
    anchor_digest: int,
    fd_digest: int,
    epoch_key: int,
    move: MoveOp,
    epoch: int,
    visible: int,
    hidden: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = epoch_key ^ 0x535445502D505246
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    return digest


def epoch_key_step(
    epoch_key: int,
    proof: int,
    capability_chain: int,
    path_digest_before: int,
    anchor_digest: int,
    fd_digest: int,
    epoch: int,
) -> int:
    digest = epoch_key ^ 0x45504F43484B4559
    digest = hash64_u64(digest, proof)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def step_token(
    proof: int,
    epoch_key: int,
    path_digest_before: int,
    anchor_digest: int,
    fd_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    epoch: int,
) -> int:
    digest = epoch_key ^ 0x535445502D544B4E
    digest = hash64_u64(digest, proof)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def step_trace_step(
    step_trace_digest: int,
    token: int,
    proof: int,
    path_digest_before: int,
    capability_chain: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    epoch: int,
) -> int:
    digest = step_trace_digest ^ 0x535452434D495443
    digest = hash64_u64(digest, token)
    digest = hash64_u64(digest, proof)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def path_step(
    path_digest: int,
    move: MoveOp,
    orbit_digest: int,
    fd_digest: int,
    anchor_digest: int,
    epoch: int,
    visible: int,
    hidden: int,
    capability_chain: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = path_digest ^ 0x504154482D364344
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, orbit_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def audit_root_step(
    audit_root: int,
    epoch: int,
    move: MoveOp,
    orbit_digest: int,
    fd_digest: int,
    visible: int,
    hidden: int,
    path_digest: int,
    capability_chain: int,
    poison: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = audit_root ^ 0x41554449542D524F
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, orbit_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, poison)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def step_receipt(
    step_proof_value: int,
    path_digest: int,
    audit_root: int,
    poison: int,
    epoch_key: int,
    epoch: int,
) -> int:
    digest = epoch_key ^ 0x535445502D524350
    digest = hash64_u64(digest, step_proof_value)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, audit_root)
    digest = hash64_u64(digest, poison)
    digest = hash64_u64(digest, epoch)
    return digest


def peer_proof_for_environment(
    seed_commitment: int,
    peer_ok: bool,
    peer_proof_salt: int = PEER_PROOF_SALT,
) -> int:
    digest = SESSION_NONCE ^ 0x504545522D505246
    digest = hash64_u64(digest, peer_proof_salt)
    digest = hash64_u64(digest, seed_commitment)
    digest = hash64_u64(digest, RUNTIME_FD_SHARE)
    digest = hash64_u64(digest, RUNTIME_TLS_SHARE)
    digest = hash64_u64(digest, RUNTIME_SHM_SHARE)
    digest = hash64_u64(digest, 1 if peer_ok else 0)
    return digest


def move_mac_seed_for_block(
    block_index: int,
    receipt_seed: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x4D4F56452D4D4143
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, receipt_seed)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, peer_proof)
    return digest


def move_mac_for_slot(
    mac_seed: int,
    slot_index: int,
    move_code: int,
) -> int:
    digest = mac_seed ^ 0x4D4F56452D534C54
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, move_code)
    return digest


def move_mac_seed(
    block_index: int,
    receipt_seed: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    peer_proof: int,
) -> int:
    return move_mac_seed_for_block(
        block_index,
        receipt_seed,
        path_digest,
        capability_chain,
        anchor_digest,
        distributed_route_digest,
        distributed_tls_mesh_digest,
        peer_proof,
    )


def move_mac(
    mac_seed: int,
    slot_index: int,
    move_code: int,
) -> int:
    return move_mac_for_slot(mac_seed, slot_index, move_code)


def slot_witness(
    block_index: int,
    slot_index: int,
    path_digest_before_move: int,
    capability_chain_after_move: int,
    anchor_digest_after_move: int,
    fd_digest_after_move: int,
    distributed_route_digest_after_move: int,
    distributed_tls_mesh_digest_after_move: int,
    step_receipt_value: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x5749544E45535321
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, path_digest_before_move)
    digest = hash64_u64(digest, capability_chain_after_move)
    digest = hash64_u64(digest, anchor_digest_after_move)
    digest = hash64_u64(digest, fd_digest_after_move)
    digest = hash64_u64(digest, distributed_route_digest_after_move)
    digest = hash64_u64(digest, distributed_tls_mesh_digest_after_move)
    digest = hash64_u64(digest, step_receipt_value)
    digest = hash64_u64(digest, peer_proof)
    return digest


def witness_auth(
    block_index: int,
    move_count: int,
    slot_witnesses: tuple[int, int, int],
    expected_step_receipt: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x5749544E2D415554
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for value in slot_witnesses:
        digest = hash64_u64(digest, value)
    digest = hash64_u64(digest, expected_step_receipt)
    digest = hash64_u64(digest, peer_proof)
    return digest


def tls_slot_mask(
    block_index: int,
    slot_index: int,
    capability_chain_after_move: int,
    distributed_tls_mesh_digest_after_move: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x544c532d534c4f54
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, capability_chain_after_move)
    digest = hash64_u64(digest, distributed_tls_mesh_digest_after_move)
    digest = hash64_u64(digest, peer_proof)
    return digest


def shm_slot_mask(
    block_index: int,
    slot_index: int,
    path_digest_before_move: int,
    fd_digest_after_move: int,
    distributed_route_digest_after_move: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x53484d2d534c4f54
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, path_digest_before_move)
    digest = hash64_u64(digest, fd_digest_after_move)
    digest = hash64_u64(digest, distributed_route_digest_after_move)
    digest = hash64_u64(digest, peer_proof)
    return digest


def broker_auth(
    block_index: int,
    move_count: int,
    broker_move_macs: tuple[int, int, int],
    expected_step_receipt: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x42524f4b2d415554
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for value in broker_move_macs:
        digest = hash64_u64(digest, value)
    digest = hash64_u64(digest, expected_step_receipt)
    digest = hash64_u64(digest, peer_proof)
    return digest


def capsule_chain_seed(
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = session_nonce ^ 0x43415053554C4521
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def capsule_digest(
    block_index: int,
    move_count: int,
    broker_move_macs: tuple[int, int, int],
    broker_auth_value: int,
    expected_step_receipt: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = session_nonce ^ 0x434150532D424C4B
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for move_mac_value in broker_move_macs:
        digest = hash64_u64(digest, move_mac_value)
    digest = hash64_u64(digest, broker_auth_value)
    digest = hash64_u64(digest, expected_step_receipt)
    return digest


def capsule_chain_step(
    chain_digest: int,
    block_index: int,
    move_count: int,
    masked_move_macs: tuple[int, int, int],
    witness_auth_value: int,
    expected_step_receipt: int,
    path_digest: int,
    capability_chain: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = chain_digest ^ 0x434150432D434841
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for move_mac_value in masked_move_macs:
        digest = hash64_u64(digest, move_mac_value)
    digest = hash64_u64(digest, witness_auth_value)
    digest = hash64_u64(digest, expected_step_receipt)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def final_capsule_auth(
    capsule_chain_digest: int,
    move_count: int,
    last_step_receipt: int,
    audit_root: int,
    path_digest: int,
    capability_chain: int,
    parser_digest: int,
    anchor_digest: int,
    peer_proof: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = session_nonce ^ 0x46494E2D43415053
    digest = hash64_u64(digest, capsule_chain_digest)
    digest = hash64_u64(digest, move_count)
    digest = hash64_u64(digest, last_step_receipt)
    digest = hash64_u64(digest, audit_root)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, parser_digest)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, peer_proof)
    return digest


def derive_block_capsule_key(
    block_index: int,
    fd_share: int,
    tls_share: int,
    shm_share: int,
    receipt_seed: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    peer_proof: int,
) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"CubeIPC-6-block-capsule")
    hasher.update(block_index.to_bytes(4, "little"))
    hasher.update(fd_share.to_bytes(8, "little"))
    hasher.update(tls_share.to_bytes(8, "little"))
    hasher.update(shm_share.to_bytes(8, "little"))
    hasher.update(receipt_seed.to_bytes(8, "little"))
    hasher.update(path_digest.to_bytes(8, "little"))
    hasher.update(capability_chain.to_bytes(8, "little"))
    hasher.update(anchor_digest.to_bytes(8, "little"))
    hasher.update(distributed_route_digest.to_bytes(8, "little"))
    hasher.update(distributed_tls_mesh_digest.to_bytes(8, "little"))
    hasher.update(peer_proof.to_bytes(8, "little"))
    return hasher.digest()


def derive_final_capsule_key(
    fd_share: int,
    tls_share: int,
    shm_share: int,
    last_step_receipt: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    capsule_chain_digest: int,
    peer_proof: int,
) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"CubeIPC-6-final-capsule")
    hasher.update(fd_share.to_bytes(8, "little"))
    hasher.update(tls_share.to_bytes(8, "little"))
    hasher.update(shm_share.to_bytes(8, "little"))
    hasher.update(last_step_receipt.to_bytes(8, "little"))
    hasher.update(path_digest.to_bytes(8, "little"))
    hasher.update(capability_chain.to_bytes(8, "little"))
    hasher.update(anchor_digest.to_bytes(8, "little"))
    hasher.update(distributed_route_digest.to_bytes(8, "little"))
    hasher.update(distributed_tls_mesh_digest.to_bytes(8, "little"))
    hasher.update(capsule_chain_digest.to_bytes(8, "little"))
    hasher.update(peer_proof.to_bytes(8, "little"))
    return hasher.digest()


def derive_block_capsule_nonce(block_index: int) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"block-capsule")
    hasher.update(block_index.to_bytes(4, "little"))
    hasher.update(SESSION_NONCE.to_bytes(8, "little"))
    return hasher.digest()[:12]


def derive_final_capsule_nonce() -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"final-capsule")
    hasher.update(SESSION_NONCE.to_bytes(8, "little"))
    return hasher.digest()[:12]


def commit_salt_for_epoch(epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x53414C542D45504F
    digest = hash64_u64(digest, epoch)
    return digest


def commitment_for_capability(capability_chain: int, salt: int) -> int:
    return hash64_u64(capability_chain, salt)


def supported_move_tokens() -> list[str]:
    tokens: list[str] = []
    outer_faces = ["U", "D", "F", "B", "L", "R"]
    rotations = ["x", "y", "z"]

    for face in outer_faces:
        tokens.extend([face, f"{face}'", f"{face}2"])
    for depth in (2, 3):
        for face in outer_faces:
            tokens.extend([f"{depth}{face}", f"{depth}{face}'", f"{depth}{face}2"])
    for width in ("", "3"):
        for face in outer_faces:
            prefix = f"{width}{face}w"
            tokens.extend([prefix, f"{prefix}'", f"{prefix}2"])
    for rot in rotations:
        tokens.extend([rot, f"{rot}'", f"{rot}2"])
    return tokens


def compute_step_proofs(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
) -> list[int]:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(answer, scramble))
    fd_entries = build_fd_owners()
    proofs: list[int] = []
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    epoch = 0

    apply_moves(state, parse_move_line(scramble))
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    for move in parse_move_line(answer):
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        proofs.append(
            step_proof(
                capability_chain,
                path_digest,
                anchor_digest,
                fd_digest,
                epoch_key,
                move,
                epoch,
                visible,
                hidden,
                distributed_route_digest_value,
                distributed_tls_mesh_digest_value,
            )
        )
        epoch_key = epoch_key_step(
            epoch_key,
            proofs[-1],
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )

    return proofs


def compute_step_tokens(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
) -> list[int]:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(answer, scramble))
    fd_entries = build_fd_owners()
    tokens: list[int] = []
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    epoch = 0

    apply_moves(state, parse_move_line(scramble))
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    for move in parse_move_line(answer):
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        proof = step_proof(
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch_key,
            move,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        tokens.append(
            step_token(
                proof,
                epoch_key,
                path_digest,
                anchor_digest,
                fd_digest,
                distributed_route_digest_value,
                distributed_tls_mesh_digest_value,
                epoch,
            )
        )
        epoch_key = epoch_key_step(
            epoch_key,
            proof,
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )

    return tokens


def compute_commitments(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
) -> tuple[list[int], list[int]]:
    tokens = compute_step_tokens(scramble, answer, initial_state=initial_state)
    salts = [commit_salt_for_epoch(index + 1) for index in range(len(tokens))]
    return tokens, salts


def block_capsule_contexts(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
    peer_ok: bool = True,
) -> list[BlockCapsuleContext]:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(answer, scramble))
    fd_entries = build_fd_owners()
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    audit_root = AUDIT_ROOT_SEED
    poison = 0
    epoch = 0
    last_step_receipt = 0
    parsed_moves = parse_move_line(answer)
    parser_digest = parser_digest_for_moves(parsed_moves)
    contexts: list[BlockCapsuleContext] = []
    seed_commitment = hash64_u64(SESSION_NONCE, REGISTRY_SALT)
    peer_proof = peer_proof_for_environment(seed_commitment, peer_ok)

    apply_moves(state, parse_move_line(scramble))
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    capsule_chain_digest_value = capsule_chain_seed(
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    )
    initial_block_anchor_digest = hash64_u64(SESSION_NONCE ^ 0x414E43482D534545, anchor_hint_value)
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    block_move_codes: list[int] = []
    block_broker_move_macs: list[int] = []
    block_slot_witnesses: list[int] = []
    block_receipt_seed = seed_commitment
    pre_path_digest = path_digest
    pre_capability_chain = capability_chain
    pre_anchor_digest = initial_block_anchor_digest
    pre_distributed_route_digest = distributed_route_digest_value
    pre_distributed_tls_mesh_digest = distributed_tls_mesh_digest_value

    for move_index, move in enumerate(parsed_moves):
        visible = 0
        hidden = 0
        proof = 0
        fd_digest = 0
        orbit = 0
        epoch += 1
        if move_index % 3 == 0:
            pre_path_digest = path_digest
            pre_capability_chain = capability_chain
            pre_anchor_digest = initial_block_anchor_digest if move_index == 0 else anchor_digest
            pre_distributed_route_digest = distributed_route_digest_value
            pre_distributed_tls_mesh_digest = distributed_tls_mesh_digest_value
            block_move_codes = []
            block_broker_move_macs = []
            block_slot_witnesses = []
        path_digest_before_move = path_digest
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        proof = step_proof(
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch_key,
            move,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        epoch_key = epoch_key_step(
            epoch_key,
            proof,
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        audit_root = audit_root_step(
            audit_root,
            epoch,
            move,
            orbit,
            fd_digest,
            visible,
            hidden,
            path_digest,
            capability_chain,
            poison,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        last_step_receipt = step_receipt(
            proof,
            path_digest,
            audit_root,
            poison,
            epoch_key,
            epoch,
        )
        block_move_codes.append(move.move_code)
        slot_index = len(block_move_codes) - 1
        block_mac_value = move_mac(
            move_mac_seed_for_block(
                len(contexts),
                block_receipt_seed,
                pre_path_digest,
                pre_capability_chain,
                pre_anchor_digest,
                pre_distributed_route_digest,
                pre_distributed_tls_mesh_digest,
                peer_proof,
            ),
            slot_index,
            move.move_code,
        )
        slot_witness_value = slot_witness(
            len(contexts),
            slot_index,
            path_digest_before_move,
            capability_chain,
            anchor_digest,
            fd_digest,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            last_step_receipt,
            peer_proof,
        )
        block_slot_witnesses.append(slot_witness_value)
        block_broker_move_macs.append(
            block_mac_value
            ^ tls_slot_mask(
                len(contexts),
                slot_index,
                capability_chain,
                distributed_tls_mesh_digest_value,
                peer_proof,
            )
            ^ shm_slot_mask(
                len(contexts),
                slot_index,
                path_digest_before_move,
                fd_digest,
                distributed_route_digest_value,
                peer_proof,
            )
        )
        if ((move_index + 1) % 3) == 0 or (move_index + 1) == len(parsed_moves):
            padded_broker = tuple(block_broker_move_macs + [0] * (3 - len(block_broker_move_macs)))
            padded_witnesses = tuple(block_slot_witnesses + [0] * (3 - len(block_slot_witnesses)))
            move_count = len(block_move_codes)
            broker_auth_value = broker_auth(
                len(contexts),
                move_count,
                padded_broker,
                last_step_receipt,
                peer_proof,
            )
            capsule_chain_digest_value = capsule_chain_step(
                capsule_chain_digest_value,
                len(contexts),
                move_count,
                padded_broker,
                broker_auth_value,
                last_step_receipt,
                path_digest,
                capability_chain,
                distributed_route_digest_value,
                distributed_tls_mesh_digest_value,
            )
            contexts.append(
                BlockCapsuleContext(
                    block_index=len(contexts),
                    move_count=move_count,
                    broker_move_macs=padded_broker,
                    broker_auth=broker_auth_value,
                    expected_step_receipt=last_step_receipt,
                    path_digest=pre_path_digest,
                    capability_chain=pre_capability_chain,
                    anchor_digest=pre_anchor_digest,
                    distributed_route_digest=pre_distributed_route_digest,
                    distributed_tls_mesh_digest=pre_distributed_tls_mesh_digest,
                    last_step_receipt=last_step_receipt,
                    path_digest_after_block=path_digest,
                    capability_chain_after_block=capability_chain,
                    anchor_digest_after_block=anchor_digest,
                    distributed_route_digest_after_block=distributed_route_digest_value,
                    distributed_tls_mesh_digest_after_block=distributed_tls_mesh_digest_value,
                    capsule_chain_digest_after_block=capsule_chain_digest_value,
                    final_auth=0,
                )
            )
            block_receipt_seed = last_step_receipt

    if contexts:
        contexts[-1].final_auth = final_capsule_auth(
            capsule_chain_digest_value,
            len(parsed_moves),
            last_step_receipt,
            audit_root,
            path_digest,
            capability_chain,
            parser_digest,
            anchor_digest,
            peer_proof,
        )
    return contexts


def solved_state() -> CubeState:
    global _SOLVED_STATE_TEMPLATE

    if _SOLVED_STATE_TEMPLATE is not None:
        return clone_state(_SOLVED_STATE_TEMPLATE)

    cells: list[CubeCell] = []

    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(col, CUBE_N - 1, CUBE_N - 1 - row, 0, 1, 0), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(col, 0, row, 0, -1, 0), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(col, CUBE_N - 1 - row, CUBE_N - 1, 0, 0, 1), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(CUBE_N - 1 - col, CUBE_N - 1 - row, 0, 0, 0, -1), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(CUBE_N - 1, CUBE_N - 1 - row, CUBE_N - 1 - col, 1, 0, 0), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(0, CUBE_N - 1 - row, col, -1, 0, 0), None))  # type: ignore[arg-type]

    seed = 0xC6E6000000000000
    for cell in cells:
        face = face_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz)
        hidden_secret, seed = splitmix64(seed)
        capability_seed, seed = splitmix64(seed)
        cell.token = StickerToken(
            visible_color=face_color(face),
            orientation=orientation_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz),
            generation=0,
            hidden_secret=hidden_secret,
            capability_seed=capability_seed,
        )

    _SOLVED_STATE_TEMPLATE = CubeState(cells)
    return clone_state(_SOLVED_STATE_TEMPLATE)


def build_challenge_base_state(answer: str, scramble: str) -> CubeState:
    state = solved_state()
    seed = challenge_material_seed(answer, scramble)

    for index, cell in enumerate(state.cells):
        position_hash = registry_pos_hash(cell.pos)
        cell.token.hidden_secret = hash64_u64(cell.token.hidden_secret ^ seed, position_hash)
        cell.token.capability_seed = hash64_u64(
            cell.token.capability_seed ^ (seed ^ 0x4341502D544F4B4E),
            index,
        )

    return state


def build_challenge_start_state(answer: str, scramble: str) -> CubeState:
    state = build_challenge_base_state(answer, scramble)
    apply_moves(state, parse_move_line(scramble))
    return state


def build_release_start_state(answer: str, scramble: str) -> CubeState:
    state = build_challenge_start_state(answer, scramble)
    for cell in state.cells:
        cell.token.generation = 0
    return state


def edge_pair_parity_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x454447452D504152
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        top_or_bottom = row in {0, CUBE_N - 1}
        left_or_right = col in {0, CUBE_N - 1}
        if not ((top_or_bottom or left_or_right) and not (top_or_bottom and left_or_right)):
            continue
        digest = hash64_u64(digest, face)
        digest = hash64_u64(digest, row)
        digest = hash64_u64(digest, col)
        digest = hash64_u64(digest, cell.token.hidden_secret)
        digest = hash64_u64(digest, cell.token.capability_seed)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.token.orientation)
        digest = hash64_u64(digest, cell.token.visible_color)
    return digest


def center_anchor_parity_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x43454E5445524150
    for face_id in range(FACE_COUNT):
        for anchor_index, slot in enumerate(face_anchor_slots(face_id)):
            row, col = divmod(slot, CUBE_N)
            for cell in state.cells:
                face, cell_row, cell_col = face_row_col(cell.pos)
                if face != face_id or cell_row != row or cell_col != col:
                    continue
                digest = hash64_u64(digest, face_id)
                digest = hash64_u64(digest, anchor_index)
                digest = hash64_u64(digest, cell.token.hidden_secret)
                digest = hash64_u64(digest, cell.token.capability_seed)
                digest = hash64_u64(digest, cell.token.generation)
                digest = hash64_u64(digest, cell.token.orientation)
                digest = hash64_u64(digest, cell.token.visible_color)
                break
    return digest


def fd_generation_parity_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x464447454E504152
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        local_index = row * CUBE_N + col
        mailbox_kind = face_mailbox_kind(local_index)
        digest = hash64_u64(digest, face)
        digest = hash64_u64(digest, local_index)
        digest = hash64_u64(digest, mailbox_kind)
        digest = hash64_u64(digest, registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT))
    return digest


def thread_lifecycle_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x5448524541444C46
    for index, cell in enumerate(state.cells):
        digest = hash64_u64(digest, index)
        digest = hash64_u64(digest, registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT))
        digest = hash64_u64(digest, cell.token.hidden_secret)
        digest = hash64_u64(digest, cell.token.capability_seed)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.token.orientation)
        digest = hash64_u64(digest, cell.token.visible_color)
    return digest


def hidden_runtime_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> tuple[int, int, int, int, int, int, int, int, int]:
    fd_generation = fd_generation_parity_seed(state, session_nonce)
    edge_pair = edge_pair_parity_seed(state, session_nonce)
    thread_lifecycle = thread_lifecycle_seed(state, session_nonce)
    anchor_hint = anchor_hint_from_state(state, session_nonce)
    distributed_route = session_nonce ^ 0x524F5554452D494E
    distributed_route = hash64_u64(distributed_route, fd_generation)
    distributed_route = hash64_u64(distributed_route, edge_pair)
    distributed_tls_mesh = session_nonce ^ 0x544C532D4D455348
    distributed_tls_mesh = hash64_u64(distributed_tls_mesh, thread_lifecycle)
    distributed_tls_mesh = hash64_u64(distributed_tls_mesh, anchor_hint)
    return (
        hidden_digest(state),
        orientation_digest(state),
        anchor_hint,
        edge_pair,
        center_anchor_parity_seed(state, session_nonce),
        fd_generation,
        thread_lifecycle,
        distributed_route,
        distributed_tls_mesh,
    )


def hidden_runtime_step(
    hidden_value: int,
    orientation_value: int,
    anchor_hint_value: int,
    edge_pair_parity_value: int,
    center_anchor_parity_value: int,
    fd_generation_parity_value: int,
    thread_lifecycle_digest_value: int,
    distributed_route_digest_value: int,
    distributed_tls_mesh_digest_value: int,
    move: MoveOp,
    epoch: int,
    orbit_digest: int,
    fd_digest: int,
    visible_digest_value: int,
    distributed_route_input: int,
    distributed_tls_mesh_input: int,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    hidden_next = hidden_value ^ 0x4849442D52544D45
    hidden_next = hash64_u64(hidden_next, epoch)
    hidden_next = hash64_u64(hidden_next, move.move_code)
    hidden_next = hash64_u64(hidden_next, orbit_digest)
    hidden_next = hash64_u64(hidden_next, fd_digest)
    hidden_next = hash64_u64(hidden_next, visible_digest_value)
    hidden_next = hash64_u64(hidden_next, move.layer_mask)
    hidden_next = hash64_u64(hidden_next, move.quarter_turns & 0xFF)

    orientation_next = orientation_value ^ 0x4F52492D52544D45
    orientation_next = hash64_u64(orientation_next, epoch)
    orientation_next = hash64_u64(orientation_next, move.move_code)
    orientation_next = hash64_u64(orientation_next, move.axis_onehot)
    orientation_next = hash64_u64(orientation_next, move.layer_mask)
    orientation_next = hash64_u64(orientation_next, move.is_global_rotation)
    orientation_next = hash64_u64(orientation_next, move.is_wide)
    orientation_next = hash64_u64(orientation_next, orbit_digest)

    anchor_next = anchor_hint_value ^ 0x414E432D52544D45
    anchor_next = hash64_u64(anchor_next, epoch)
    anchor_next = hash64_u64(anchor_next, move.move_code)
    anchor_next = hash64_u64(anchor_next, visible_digest_value)
    anchor_next = hash64_u64(anchor_next, fd_digest)
    anchor_next = hash64_u64(anchor_next, hidden_next)
    anchor_next = hash64_u64(anchor_next, orientation_next)

    edge_pair_parity_next = edge_pair_parity_value ^ 0x454447452D4D4F56
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, epoch)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, move.move_code)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, move.axis_onehot)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, move.layer_mask)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, orbit_digest)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, visible_digest_value)

    center_anchor_parity_next = center_anchor_parity_value ^ 0x43454E5445524D56
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, epoch)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, move.move_code)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, anchor_next)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, hidden_next)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, visible_digest_value)

    fd_generation_parity_next = fd_generation_parity_value ^ 0x464447454E4D4F56
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, epoch)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, fd_digest)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, move.move_code)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, move.layer_mask)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, move.is_global_rotation)

    thread_lifecycle_next = thread_lifecycle_digest_value ^ 0x5448524541444D56
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, epoch)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, move.move_code)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, orbit_digest)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, hidden_next)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, orientation_next)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, fd_digest)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, visible_digest_value)

    distributed_route_next = distributed_route_digest_value ^ 0x524F5554452D4D56
    distributed_route_next = hash64_u64(distributed_route_next, epoch)
    distributed_route_next = hash64_u64(distributed_route_next, move.move_code)
    distributed_route_next = hash64_u64(distributed_route_next, orbit_digest)
    distributed_route_next = hash64_u64(distributed_route_next, fd_digest)
    distributed_route_next = hash64_u64(distributed_route_next, distributed_route_input)
    distributed_route_next = hash64_u64(distributed_route_next, edge_pair_parity_next)
    distributed_route_next = hash64_u64(distributed_route_next, fd_generation_parity_next)

    distributed_tls_mesh_next = distributed_tls_mesh_digest_value ^ 0x544C532D4D56454E
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, epoch)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, move.move_code)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, distributed_tls_mesh_input)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, anchor_next)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, orientation_next)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, thread_lifecycle_next)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, distributed_route_next)

    return (
        hidden_next,
        orientation_next,
        anchor_next,
        edge_pair_parity_next,
        center_anchor_parity_next,
        fd_generation_parity_next,
        thread_lifecycle_next,
        distributed_route_next,
        distributed_tls_mesh_next,
    )


def find_cell_index(state: CubeState, pos: StickerPos) -> int:
    for index, cell in enumerate(state.cells):
        if cell.pos == pos:
            return index
    raise ValueError(f"position not found: {pos!r}")


def apply_move(state: CubeState, move: MoveOp) -> None:
    next_tokens: list[StickerToken | None] = [None] * TOTAL_STICKERS
    for cell in state.cells:
        dst_pos = rotate_pos(cell.pos, move)
        dst_index = find_cell_index(state, dst_pos)
        token = StickerToken(
            visible_color=cell.token.visible_color,
            orientation=cell.token.orientation,
            generation=cell.token.generation,
            hidden_secret=cell.token.hidden_secret,
            capability_seed=cell.token.capability_seed,
        )
        if sticker_in_layer(cell.pos, move):
            token.generation += 1
            token.orientation = orientation_from_normal(dst_pos.nx, dst_pos.ny, dst_pos.nz)
        next_tokens[dst_index] = token

    for index, token in enumerate(next_tokens):
        assert token is not None
        state.cells[index].token = token


def apply_moves(state: CubeState, moves: list[MoveOp]) -> None:
    for move in moves:
        apply_move(state, move)


def apply_moves_with_path_digest(state: CubeState, moves: list[MoveOp]) -> int:
    digest = PATH_DIGEST_SEED
    capability = CAPABILITY_SEED
    fd_entries = build_fd_owners()
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    anchor_digest = courier_seed()
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    epoch = 0
    for move in moves:
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability = capability_step(
            capability,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        digest = path_step(
            digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden_value,
            capability,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
    return digest


def visible_digest(state: CubeState) -> int:
    digest = 0x1234567890ABCDEF
    for cell in state.cells:
        digest = hash64_u64(digest, cell.token.visible_color)
        digest = hash64_u64(digest, cell.token.orientation)
    return digest


def hidden_digest(state: CubeState) -> int:
    digest = 0x0DDC0FFEEBADF00D
    for cell in state.cells:
        digest = hash64_u64(digest, cell.token.hidden_secret)
        digest = hash64_u64(digest, cell.token.capability_seed)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.token.orientation)
    return digest


def orientation_digest(state: CubeState) -> int:
    digest = 0x4F5249454E542D36
    for index, cell in enumerate(state.cells):
        digest = hash64_u64(digest, index)
        digest = hash64_u64(digest, cell.token.orientation)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.pos.x)
        digest = hash64_u64(digest, cell.pos.y)
        digest = hash64_u64(digest, cell.pos.z)
        digest = hash64_u64(digest, cell.pos.nx + 1)
        digest = hash64_u64(digest, cell.pos.ny + 1)
        digest = hash64_u64(digest, cell.pos.nz + 1)
    return digest


def face_row_col(pos: StickerPos) -> tuple[int, int, int]:
    face = face_from_normal(pos.nx, pos.ny, pos.nz)
    if face == FACE_U:
        return face, CUBE_N - 1 - pos.z, pos.x
    if face == FACE_D:
        return face, pos.z, pos.x
    if face == FACE_F:
        return face, CUBE_N - 1 - pos.y, pos.x
    if face == FACE_B:
        return face, CUBE_N - 1 - pos.y, CUBE_N - 1 - pos.x
    if face == FACE_R:
        return face, CUBE_N - 1 - pos.y, CUBE_N - 1 - pos.z
    if face == FACE_L:
        return face, CUBE_N - 1 - pos.y, pos.z
    raise ValueError("invalid face")


def render_visible(state: CubeState) -> str:
    labels = ["U", "D", "F", "B", "R", "L"]
    faces = [[["?" for _ in range(CUBE_N)] for _ in range(CUBE_N)] for _ in range(FACE_COUNT)]
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        faces[face][row][col] = color_char(cell.token.visible_color)

    parts: list[str] = []
    for face, label in enumerate(labels):
        parts.append(f"{label}:")
        for row in faces[face]:
            parts.append(" ".join(row))
        if face + 1 != FACE_COUNT:
            parts.append("")
    return "\n".join(parts)


def derive_final_key(
    visible: int,
    hidden: int,
    orientation: int,
    edge_pair_parity: int,
    center_anchor_parity: int,
    fd_generation_parity: int,
    thread_lifecycle_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    path_digest: int,
    capability_chain: int,
    step_trace_digest: int,
    fd_digest: int,
    audit_root: int,
    anchor_digest: int,
    parser_digest: int,
    poison: int,
) -> bytes:
    material = (
        int(visible & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(hidden & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(orientation & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(edge_pair_parity & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(center_anchor_parity & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(fd_generation_parity & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(thread_lifecycle_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(distributed_route_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(distributed_tls_mesh_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(path_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(capability_chain & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(step_trace_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(fd_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(audit_root & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(anchor_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(parser_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(poison & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + b"CubeIPC-6"
    )
    return hashlib.sha256(material).digest()


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state = constants + [int.from_bytes(key[i * 4 : i * 4 + 4], "little") for i in range(8)]
    state += [counter]
    state += [int.from_bytes(nonce[i * 4 : i * 4 + 4], "little") for i in range(3)]

    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    words = [((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16)]
    return b"".join(words)


def chacha20_xor(data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    output = bytearray(data)
    offset = 0
    block_counter = counter
    while offset < len(output):
        block = _chacha20_block(key, nonce, block_counter)
        take = min(64, len(output) - offset)
        for index in range(take):
            output[offset + index] ^= block[index]
        offset += take
        block_counter += 1
    return bytes(output)


def evaluate_sequence(
    scramble: str,
    moves: str,
    initial_state: CubeState | None = None,
) -> tuple[int, int, int, int, int, int, int]:
    details = evaluate_sequence_details(scramble, moves, initial_state=initial_state)
    return (
        details.visible_digest,
        details.hidden_digest,
        details.path_digest,
        details.capability_chain,
        details.fd_digest,
        details.audit_root,
        details.anchor_digest,
    )


def evaluate_sequence_details(
    scramble: str,
    moves: str,
    initial_state: CubeState | None = None,
) -> EvaluationDetails:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(moves, scramble))
    fd_entries = build_fd_owners()
    parsed_moves = parse_move_line(moves)
    apply_moves(state, parse_move_line(scramble))
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    fd_digest = fd_owners_digest(fd_entries)
    audit_root = AUDIT_ROOT_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    step_trace_digest = SESSION_NONCE ^ 0x5354455054524143
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    step_trace_digest = hash64_u64(step_trace_digest, distributed_route_digest_value)
    step_trace_digest = hash64_u64(step_trace_digest, distributed_tls_mesh_digest_value)
    poison = 0
    epoch = 0

    for move in parsed_moves:
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_digest,
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        watchdog_trace = watchdog_trace_digest(move, epoch)
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace)
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        current_step_proof = step_proof(
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch_key,
            move,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        token = step_token(
            current_step_proof,
            epoch_key,
            path_digest,
            anchor_digest,
            fd_digest,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            epoch,
        )
        if epoch > len(parsed_moves):
            poison = hash64_u64(poison ^ 0x504F49534F4E2D58, epoch)
        step_trace_digest = step_trace_step(
            step_trace_digest,
            token,
            current_step_proof,
            path_digest,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            epoch,
        )
        epoch_key = epoch_key_step(
            epoch_key,
            current_step_proof,
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        audit_root = audit_root_step(
            audit_root,
            epoch,
            move,
            orbit,
            fd_digest,
            visible,
            hidden,
            path_digest,
            capability_chain,
            poison,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )

    return EvaluationDetails(
        visible_digest=visible_digest(state),
        hidden_digest=hidden_value,
        orientation_digest=orientation_value,
        edge_pair_parity=edge_pair_parity_value,
        center_anchor_parity=center_anchor_parity_value,
        fd_generation_parity=fd_generation_parity_value,
        thread_lifecycle_digest=thread_lifecycle_digest_value,
        distributed_route_digest=distributed_route_digest_value,
        distributed_tls_mesh_digest=distributed_tls_mesh_digest_value,
        path_digest=path_digest,
        capability_chain=capability_chain,
        step_trace_digest=step_trace_digest,
        fd_digest=fd_digest,
        audit_root=audit_root,
        anchor_digest=anchor_digest,
        parser_digest=parser_digest_for_moves(parsed_moves),
        poison=poison,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scramble", default=DEV_SCRAMBLE)
    parser.add_argument("--moves", default="")
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()

    state = solved_state()
    apply_moves(state, parse_move_line(args.scramble))
    details = evaluate_sequence_details(args.scramble, args.moves)

    if args.render:
        state = solved_state()
        apply_moves(state, parse_move_line(args.scramble))
        apply_moves(state, parse_move_line(args.moves))
        print(render_visible(state))
        print()
    print(f"visible_digest=0x{details.visible_digest:016x}")
    print(f"hidden_digest=0x{details.hidden_digest:016x}")
    print(f"orientation_digest=0x{details.orientation_digest:016x}")
    print(f"distributed_route_digest=0x{details.distributed_route_digest:016x}")
    print(f"distributed_tls_mesh_digest=0x{details.distributed_tls_mesh_digest:016x}")
    print(f"path_digest=0x{details.path_digest:016x}")
    print(f"capability_chain=0x{details.capability_chain:016x}")
    print(f"step_trace_digest=0x{details.step_trace_digest:016x}")
    print(f"fd_ownership_digest=0x{details.fd_digest:016x}")
    print(f"audit_root=0x{details.audit_root:016x}")
    print(f"anchor_digest=0x{details.anchor_digest:016x}")
    print(f"parser_digest=0x{details.parser_digest:016x}")


if __name__ == "__main__":
    main()
'''
exec(_OFFLINE_SIM_SOURCE, offline_sim.__dict__)


import argparse
import hashlib
import shlex
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


offline_sim = ModuleType("offline_sim_embedded")
sys.modules[offline_sim.__name__] = offline_sim
_OFFLINE_SIM_SOURCE = r'''from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass


CUBE_N = 6
FACE_COUNT = 6
STICKERS_PER_FACE = 36
TOTAL_STICKERS = FACE_COUNT * STICKERS_PER_FACE

AXIS_X = 1
AXIS_Y = 2
AXIS_Z = 4

FACE_U = 0
FACE_D = 1
FACE_F = 2
FACE_B = 3
FACE_R = 4
FACE_L = 5

COLOR_W = 0
COLOR_Y = 1
COLOR_G = 2
COLOR_B = 3
COLOR_R = 4
COLOR_O = 5

DEV_SCRAMBLE = "3Rw U2 F 2L' z Rw2 B 3U"
SESSION_NONCE = 0x4343424343444345
REGISTRY_SALT = 0x7265676973747279
PATH_DIGEST_SEED = SESSION_NONCE ^ 0x504154482D494E49
CAPABILITY_SEED = SESSION_NONCE ^ 0x4341502D494E4954
AUDIT_ROOT_SEED = SESSION_NONCE ^ 0x41554449542D494E
CAPSULE_CHAIN_SEED = SESSION_NONCE ^ 0x43415053554C4521
RUNTIME_FD_SHARE = 0x8F2C3A14D6E1B905
RUNTIME_TLS_SHARE = 0x41B7E3C8925AF06D
RUNTIME_SHM_SHARE = 0xD3A95F0C7E21486B
PEER_PROOF_SALT = (SESSION_NONCE ^ 0x504545522D53414C) & 0xFFFFFFFFFFFFFFFF
# Mirrors sizeof(TokenSlot) on the Linux x86_64 target used by the challenge.
TOKEN_SLOT_SIZE = 48
STAGING_CAPACITY = (4 * 4096) // TOKEN_SLOT_SIZE


@dataclass(frozen=True)
class StickerPos:
    x: int
    y: int
    z: int
    nx: int
    ny: int
    nz: int


@dataclass
class StickerToken:
    visible_color: int
    orientation: int
    generation: int
    hidden_secret: int
    capability_seed: int


@dataclass
class AnchorThreadState:
    running_digest: int
    wake_count: int


@dataclass
class MoveOp:
    axis_onehot: int
    layer_mask: int
    quarter_turns: int
    move_code: int
    is_global_rotation: int
    is_wide: int


@dataclass
class CubeCell:
    pos: StickerPos
    token: StickerToken


@dataclass
class CubeState:
    cells: list[CubeCell]


@dataclass
class FdOwnerEntry:
    pos: StickerPos
    pos_hash: int
    logical_owner: int
    logical_slot: int
    fd_generation: int
    mailbox_kind: int
    ownership_tag: int


@dataclass
class EvaluationDetails:
    visible_digest: int
    hidden_digest: int
    orientation_digest: int
    edge_pair_parity: int
    center_anchor_parity: int
    fd_generation_parity: int
    thread_lifecycle_digest: int
    distributed_route_digest: int
    distributed_tls_mesh_digest: int
    path_digest: int
    capability_chain: int
    step_trace_digest: int
    fd_digest: int
    audit_root: int
    anchor_digest: int
    parser_digest: int
    poison: int


@dataclass
class BlockCapsuleContext:
    block_index: int
    move_count: int
    broker_move_macs: tuple[int, int, int]
    broker_auth: int
    expected_step_receipt: int
    path_digest: int
    capability_chain: int
    anchor_digest: int
    distributed_route_digest: int
    distributed_tls_mesh_digest: int
    last_step_receipt: int
    path_digest_after_block: int
    capability_chain_after_block: int
    anchor_digest_after_block: int
    distributed_route_digest_after_block: int
    distributed_tls_mesh_digest_after_block: int
    capsule_chain_digest_after_block: int
    final_auth: int


_FACE_SLOT_MATERIALS: dict[tuple[int, int], tuple[StickerPos, int, int, int]] = {}
_LINE_POSITIONS_CACHE: dict[tuple[int, int, int], list[StickerPos]] = {}
_FACE_ANCHOR_SLOTS_CACHE: dict[int, list[int]] = {}
_FACE_DECOY_SLOTS_CACHE: dict[int, list[int]] = {}
_SOLVED_STATE_TEMPLATE: CubeState | None = None


def build_rebound_shadow_state() -> list[dict[int, int]]:
    return [dict() for _ in range(FACE_COUNT)]


def splitmix64(state: int) -> tuple[int, int]:
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    z ^= z >> 31
    return z & 0xFFFFFFFFFFFFFFFF, state


def hash64_bytes(data: bytes, seed: int) -> int:
    state = (seed ^ 0x243F6A8885A308D3 ^ len(data)) & 0xFFFFFFFFFFFFFFFF
    for byte in data:
        state ^= (byte + 0x9E3779B97F4A7C15 + ((state << 6) & 0xFFFFFFFFFFFFFFFF) + (state >> 2)) & 0xFFFFFFFFFFFFFFFF
        state, _ = splitmix64(state)
    return state


def hash64_u64(seed: int, value: int) -> int:
    z = (seed + value + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    z ^= z >> 31
    return z & 0xFFFFFFFFFFFFFFFF


def challenge_material_seed(answer: str, scramble: str, session_nonce: int = SESSION_NONCE) -> int:
    material = (
        answer.encode("utf-8")
        + b"\x00"
        + scramble.encode("utf-8")
        + b"\x00"
        + session_nonce.to_bytes(8, "little")
    )
    return hash64_bytes(material, session_nonce ^ 0x4348414C4C2D3655)


def registry_pos_hash(pos: StickerPos, session_nonce: int = SESSION_NONCE, registry_salt: int = REGISTRY_SALT) -> int:
    digest = session_nonce ^ 0x5245474953545259
    digest = hash64_u64(digest, registry_salt)
    digest = hash64_u64(digest, pos.x)
    digest = hash64_u64(digest, pos.y)
    digest = hash64_u64(digest, pos.z)
    digest = hash64_u64(digest, pos.nx + 1)
    digest = hash64_u64(digest, pos.ny + 1)
    digest = hash64_u64(digest, pos.nz + 1)
    return digest


def face_from_normal(nx: int, ny: int, nz: int) -> int:
    if (nx, ny, nz) == (0, 1, 0):
        return FACE_U
    if (nx, ny, nz) == (0, -1, 0):
        return FACE_D
    if (nx, ny, nz) == (0, 0, 1):
        return FACE_F
    if (nx, ny, nz) == (0, 0, -1):
        return FACE_B
    if (nx, ny, nz) == (1, 0, 0):
        return FACE_R
    if (nx, ny, nz) == (-1, 0, 0):
        return FACE_L
    raise ValueError("invalid normal")


def color_char(color: int) -> str:
    return "WYGBRO"[color]


def orientation_from_normal(nx: int, ny: int, nz: int) -> int:
    return face_from_normal(nx, ny, nz)


def face_color(face: int) -> int:
    return [COLOR_W, COLOR_Y, COLOR_G, COLOR_B, COLOR_R, COLOR_O][face]


def centered(value: int) -> int:
    return value * 2 - (CUBE_N - 1)


def from_centered(value: int) -> int:
    return (value + (CUBE_N - 1)) // 2


def rotate_axis_step(a: int, b: int, turns: int) -> tuple[int, int]:
    if turns == 1:
        return b, -a
    if turns == -1:
        return -b, a
    if abs(turns) == 2:
        return -a, -b
    return a, b


def sticker_in_layer(pos: StickerPos, move: MoveOp) -> bool:
    if move.is_global_rotation:
        return True
    coord = {AXIS_X: pos.x, AXIS_Y: pos.y, AXIS_Z: pos.z}[move.axis_onehot]
    return ((move.layer_mask >> coord) & 1) != 0


def rotate_pos(pos: StickerPos, move: MoveOp) -> StickerPos:
    if not sticker_in_layer(pos, move):
        return pos

    x, y, z = centered(pos.x), centered(pos.y), centered(pos.z)
    nx, ny, nz = pos.nx, pos.ny, pos.nz
    turns = 2 if move.quarter_turns == -2 else move.quarter_turns

    if move.axis_onehot == AXIS_X:
        y, z = rotate_axis_step(y, z, turns)
        ny, nz = rotate_axis_step(ny, nz, turns)
    elif move.axis_onehot == AXIS_Y:
        z, x = rotate_axis_step(z, x, turns)
        nz, nx = rotate_axis_step(nz, nx, turns)
    elif move.axis_onehot == AXIS_Z:
        x, y = rotate_axis_step(x, y, turns)
        nx, ny = rotate_axis_step(nx, ny, turns)
    else:
        raise ValueError("invalid axis")

    return StickerPos(from_centered(x), from_centered(y), from_centered(z), nx, ny, nz)


def parse_move(token: str) -> MoveOp:
    if not token or len(token) > 5:
        raise ValueError(f"bad token: {token!r}")

    index = 0
    prefix = 0
    if token[index] in {"2", "3"}:
        prefix = int(token[index])
        index += 1

    if index >= len(token):
        raise ValueError(token)

    face = token[index]
    index += 1
    if face not in "UDFBLRxyz":
        raise ValueError(token)

    wide = False
    if index < len(token) and token[index] == "w":
        wide = True
        index += 1

    if face in "xyz":
        if prefix or wide:
            raise ValueError(token)
        is_global_rotation = 1
        layer_mask = 0x3F
        base_turn = 1
    elif wide:
        width = prefix or 2
        if width not in {2, 3}:
            raise ValueError(token)
        is_global_rotation = 0
        layer_mask = layer_mask_for_span(face, width)
        base_turn = 1 if face in "UFR" else -1
    elif prefix:
        if prefix not in {2, 3}:
            raise ValueError(token)
        is_global_rotation = 0
        layer_mask = 1 << single_layer_for_face(face, prefix)
        base_turn = 1 if face in "UFR" else -1
    else:
        is_global_rotation = 0
        layer_mask = layer_mask_for_span(face, 1)
        base_turn = 1 if face in "UFR" else -1

    suffix = token[index:] if index < len(token) else ""
    if suffix == "":
        quarter_turns = base_turn
    elif suffix == "'":
        quarter_turns = -base_turn
    elif suffix == "2":
        quarter_turns = 2
    else:
        raise ValueError(token)

    axis = {"L": AXIS_X, "R": AXIS_X, "x": AXIS_X, "U": AXIS_Y, "D": AXIS_Y, "y": AXIS_Y, "F": AXIS_Z, "B": AXIS_Z, "z": AXIS_Z}[face]
    return MoveOp(
        axis_onehot=axis,
        layer_mask=layer_mask,
        quarter_turns=quarter_turns,
        move_code=token_move_code(token),
        is_global_rotation=is_global_rotation,
        is_wide=1 if wide else 0,
    )


def token_move_code(token: str) -> int:
    hash_value = 2166136261
    for ch in token.encode():
        hash_value ^= ch
        hash_value = (hash_value * 16777619) & 0xFFFFFFFF
    return ((hash_value >> 16) ^ hash_value) & 0xFFFF


def single_layer_for_face(face: str, layer_number: int) -> int:
    if face in "UFR":
        return CUBE_N - layer_number
    return layer_number - 1


def layer_mask_for_span(face: str, width: int) -> int:
    mask = 0
    if face in "UFR":
        for i in range(width):
            mask |= 1 << (CUBE_N - 1 - i)
    else:
        for i in range(width):
            mask |= 1 << i
    return mask


def parse_move_line(line: str) -> list[MoveOp]:
    return [parse_move(token) for token in line.split()] if line.strip() else []


def parser_digest_for_moves(moves: list[MoveOp], session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x5041525345522D44
    digest = hash64_u64(digest, len(moves))
    for index, move in enumerate(moves):
        digest = hash64_u64(digest, index)
        digest = hash64_u64(digest, move.move_code)
        digest = hash64_u64(digest, move.axis_onehot)
        digest = hash64_u64(digest, move.layer_mask)
        digest = hash64_u64(digest, move.quarter_turns & 0xFF)
        digest = hash64_u64(digest, move.is_global_rotation)
        digest = hash64_u64(digest, move.is_wide)
    return digest


def move_to_string(move: MoveOp) -> str:
    if move.is_global_rotation:
        face = {AXIS_X: "x", AXIS_Y: "y", AXIS_Z: "z"}[move.axis_onehot]
        return face + ("2" if move.quarter_turns == 2 else "'" if move.quarter_turns == -1 else "")

    layers = [i for i in range(CUBE_N) if (move.layer_mask >> i) & 1]
    positive_face = max(layers) >= CUBE_N // 2
    face = {
        AXIS_X: "R" if positive_face else "L",
        AXIS_Y: "U" if positive_face else "D",
        AXIS_Z: "F" if positive_face else "B",
    }[move.axis_onehot]

    suffix = "2" if move.quarter_turns == 2 else "'" if move.quarter_turns == (-1 if positive_face else 1) else ""

    if len(layers) == 1:
        layer_number = CUBE_N - max(layers) if positive_face else min(layers) + 1
        return f"{face}{suffix}" if layer_number == 1 else f"{layer_number}{face}{suffix}"
    if len(layers) == 2:
        return f"{face}w{suffix}"
    if len(layers) == 3:
        return f"3{face}w{suffix}"
    raise ValueError("unsupported layer mask")


def inverse_move(move: MoveOp) -> MoveOp:
    turns = move.quarter_turns
    if turns == 2:
        inverse_turns = 2
    else:
        inverse_turns = -turns
    return MoveOp(
        axis_onehot=move.axis_onehot,
        layer_mask=move.layer_mask,
        quarter_turns=inverse_turns,
        move_code=move.move_code,
        is_global_rotation=move.is_global_rotation,
        is_wide=move.is_wide,
    )


def inverse_move_line(line: str) -> str:
    moves = parse_move_line(line)
    return " ".join(move_to_string(inverse_move(move)) for move in reversed(moves))


def slice_worker_key(axis_onehot: int, layer_index: int, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x534C4943452D3655
    digest = hash64_u64(digest, axis_onehot)
    digest = hash64_u64(digest, layer_index)
    return digest


def slice_participates(axis_onehot: int, layer_index: int, move: MoveOp) -> bool:
    if move.is_global_rotation:
        return True
    if move.axis_onehot != axis_onehot:
        return False
    return ((move.layer_mask >> layer_index) & 1) != 0


def active_slice_worker_keys(move: MoveOp) -> list[tuple[int, int]]:
    return [
        (axis_onehot, layer_index)
        for axis_onehot in (AXIS_X, AXIS_Y, AXIS_Z)
        for layer_index in range(CUBE_N)
        if slice_participates(axis_onehot, layer_index, move)
    ]


def slice_payload_digest(axis_onehot: int, layer_index: int, move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    worker_key = slice_worker_key(axis_onehot, layer_index, session_nonce)
    digest = worker_key ^ 0x534C494345444947
    digest = hash64_u64(digest, axis_onehot)
    digest = hash64_u64(digest, layer_index)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, move.layer_mask)
    digest = hash64_u64(digest, move.quarter_turns & 0xFF)
    digest = hash64_u64(digest, move.is_global_rotation)
    digest = hash64_u64(digest, move.is_wide)
    return digest


def slice_ack_digest(worker_key: int, payload_digest: int, epoch: int) -> int:
    digest = worker_key ^ 0x41434B2D534C4943
    digest = hash64_u64(digest, payload_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def slice_stage_digests(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> tuple[int, int]:
    orbit = session_nonce ^ 0x4F524249542D3655
    ack_aggregate = session_nonce ^ 0x41434B2D36554C4C
    registry_digest = session_nonce ^ 0x5245472D534C4943
    slice_trace_digest = session_nonce ^ 0x534C4958452D5452
    registry_digest = hash64_u64(registry_digest, epoch)
    registry_digest = hash64_u64(registry_digest, move.move_code)

    for cell in solved_state().cells:
        target_pos = rotate_pos(cell.pos, move)
        source_pos_hash = registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT)
        target_pos_hash = registry_pos_hash(target_pos, session_nonce, REGISTRY_SALT)
        if not sticker_in_layer(cell.pos, move):
            continue
        source_face, _, _ = face_row_col(cell.pos)
        target_face, _, _ = face_row_col(target_pos)
        source_capability_mask = hash64_u64(session_nonce ^ 0x4341502D4D41534B, source_pos_hash)
        target_capability_mask = hash64_u64(session_nonce ^ 0x4341502D4D41534B, target_pos_hash)
        source_integrity_tag = hash64_u64(source_capability_mask, source_pos_hash)
        target_integrity_tag = hash64_u64(target_capability_mask, target_pos_hash)
        registry_digest = hash64_u64(registry_digest, source_pos_hash)
        registry_digest = hash64_u64(registry_digest, target_pos_hash)
        registry_digest = hash64_u64(registry_digest, source_integrity_tag)
        registry_digest = hash64_u64(registry_digest, target_integrity_tag)
        registry_digest = hash64_u64(registry_digest, source_face)
        registry_digest = hash64_u64(registry_digest, target_face)

    orbit = hash64_u64(orbit, registry_digest)
    slice_trace_digest = hash64_u64(slice_trace_digest, registry_digest)
    slice_trace_digest = hash64_u64(slice_trace_digest, epoch)
    slice_trace_digest = hash64_u64(slice_trace_digest, move.move_code)

    for axis, layer_index in active_slice_worker_keys(move):
        worker_key = slice_worker_key(axis, layer_index, session_nonce)
        payload = slice_payload_digest(axis, layer_index, move, epoch, session_nonce)
        capability = hash64_u64(
            worker_key ^ slice_ack_digest(worker_key, payload, epoch),
            payload ^ ((axis << 32) | layer_index),
        )
        orbit = hash64_u64(orbit, payload)
        ack_aggregate = hash64_u64(ack_aggregate, slice_ack_digest(worker_key, payload, epoch))
        slice_trace_digest = hash64_u64(slice_trace_digest, payload)
        slice_trace_digest = hash64_u64(slice_trace_digest, slice_ack_digest(worker_key, payload, epoch))
        slice_trace_digest = hash64_u64(slice_trace_digest, capability)

    return hash64_u64(orbit, ack_aggregate), hash64_u64(slice_trace_digest, ack_aggregate)


def orbit_digest_for_move(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    return slice_stage_digests(move, epoch, session_nonce)[0]


def face_worker_key(face_id: int, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x464143452D574B52
    digest = hash64_u64(digest, face_id)
    return digest


def line_worker_key(session_nonce: int, face_id: int, is_row: int, line_index: int) -> int:
    digest = session_nonce ^ 0x4C494E452D574B52
    digest = hash64_u64(digest, face_id)
    digest = hash64_u64(digest, is_row)
    digest = hash64_u64(digest, line_index)
    return digest


def face_mailboxes_for_line(is_row: int, line_index: int) -> list[int]:
    return [line_index * 6 + i for i in range(6)] if is_row else [line_index + i * 6 for i in range(6)]


def face_mailbox_kind(sticker_index: int, face_id: int | None = None) -> int:
    if face_id is not None and sticker_index in set(face_decoy_slots(face_id)):
        return 2
    row, col = divmod(sticker_index, CUBE_N)
    top_or_bottom = row in {0, CUBE_N - 1}
    left_or_right = col in {0, CUBE_N - 1}
    if (top_or_bottom or left_or_right) and not (top_or_bottom and left_or_right):
        return 1
    return 0


def face_anchor_slots(face_id: int) -> list[int]:
    if face_id in _FACE_ANCHOR_SLOTS_CACHE:
        return list(_FACE_ANCHOR_SLOTS_CACHE[face_id])

    candidates: list[tuple[int, int]] = []
    state = solved_state()
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face != face_id or not (1 <= row <= 4 and 1 <= col <= 4):
            continue
        slot = row * 6 + col
        score = SESSION_NONCE ^ REGISTRY_SALT ^ 0x414E43484F522D53
        score = hash64_u64(score, face)
        score = hash64_u64(score, row)
        score = hash64_u64(score, col)
        score = hash64_u64(score, registry_pos_hash(cell.pos))
        candidates.append((score, slot))
    candidates.sort(key=lambda item: item[0])
    _FACE_ANCHOR_SLOTS_CACHE[face_id] = [slot for _, slot in candidates[:4]]
    return list(_FACE_ANCHOR_SLOTS_CACHE[face_id])


def face_decoy_slots(face_id: int) -> list[int]:
    if face_id in _FACE_DECOY_SLOTS_CACHE:
        return list(_FACE_DECOY_SLOTS_CACHE[face_id])

    anchors = set(face_anchor_slots(face_id))
    candidates: list[tuple[int, int]] = []
    state = solved_state()
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face != face_id or not (1 <= row <= 4 and 1 <= col <= 4):
            continue
        slot = row * 6 + col
        if slot in anchors:
            continue
        score = SESSION_NONCE ^ REGISTRY_SALT ^ 0x4445434F592D534C
        score = hash64_u64(score, face)
        score = hash64_u64(score, row)
        score = hash64_u64(score, col)
        score = hash64_u64(score, registry_pos_hash(cell.pos))
        candidates.append((score, slot))
    candidates.sort(key=lambda item: item[0])
    _FACE_DECOY_SLOTS_CACHE[face_id] = [slot for _, slot in candidates[:4]]
    return list(_FACE_DECOY_SLOTS_CACHE[face_id])


def line_positions(face_id: int, is_row: int, line_index: int) -> list[StickerPos]:
    key = (face_id, is_row, line_index)
    if key in _LINE_POSITIONS_CACHE:
        return list(_LINE_POSITIONS_CACHE[key])

    positions: list[StickerPos] = []
    state = solved_state()

    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face == face_id and ((is_row and row == line_index) or (not is_row and col == line_index)):
            positions.append(cell.pos)
    _LINE_POSITIONS_CACHE[key] = list(positions)
    return positions


def face_is_on_move_axis(face_id: int, axis_onehot: int) -> bool:
    return (
        (axis_onehot == AXIS_X and face_id in {FACE_R, FACE_L}) or
        (axis_onehot == AXIS_Y and face_id in {FACE_U, FACE_D}) or
        (axis_onehot == AXIS_Z and face_id in {FACE_F, FACE_B})
    )


def line_active(face_id: int, is_row: int, line_index: int, move: MoveOp) -> bool:
    positions = line_positions(face_id, is_row, line_index)

    if move.is_global_rotation:
        return True
    if face_is_on_move_axis(face_id, move.axis_onehot):
        return is_row == 1 and all(sticker_in_layer(pos, move) for pos in positions)
    return all(sticker_in_layer(pos, move) for pos in positions)


def active_line_worker_keys(move: MoveOp) -> list[tuple[int, int, int]]:
    active: list[tuple[int, int, int]] = []
    for face_id in range(FACE_COUNT):
        for slot in range(12):
            is_row = 1 if slot < 6 else 0
            line_index = slot if is_row else slot - 6
            if line_active(face_id, is_row, line_index, move):
                active.append((face_id, is_row, line_index))
    return active


def clone_token(token: StickerToken) -> StickerToken:
    return StickerToken(
        visible_color=token.visible_color,
        orientation=token.orientation,
        generation=token.generation,
        hidden_secret=token.hidden_secret,
        capability_seed=token.capability_seed,
    )


def clone_state(state: CubeState) -> CubeState:
    return CubeState(
        [
            CubeCell(
                pos=cell.pos,
                token=clone_token(cell.token),
            )
            for cell in state.cells
        ]
    )


def build_face_thread_tokens(state: CubeState | None = None) -> list[list[StickerToken]]:
    if state is None:
        state = solved_state()

    face_tokens: list[list[StickerToken]] = [
        [StickerToken(0, 0, 0, 0, 0) for _ in range(STICKERS_PER_FACE)]
        for _ in range(FACE_COUNT)
    ]
    for cell in state.cells:
        face_id, row, col = face_row_col(cell.pos)
        face_tokens[face_id][row * 6 + col] = clone_token(cell.token)
    return face_tokens


def build_anchor_thread_states() -> list[dict[int, AnchorThreadState]]:
    states: list[dict[int, AnchorThreadState]] = []
    for face_id in range(FACE_COUNT):
        face_state: dict[int, AnchorThreadState] = {}
        for sticker_index in face_anchor_slots(face_id):
            _, _, running_seed = anchor_thread_material(face_id, sticker_index)
            face_state[sticker_index] = AnchorThreadState(running_digest=running_seed, wake_count=0)
        states.append(face_state)
    return states


def face_sticker_material(face_id: int, sticker_index: int) -> tuple[StickerPos, int, int, int]:
    key = (face_id, sticker_index)
    if key in _FACE_SLOT_MATERIALS:
        return _FACE_SLOT_MATERIALS[key]

    state = solved_state()
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if face == face_id and row * 6 + col == sticker_index:
            position_hash = registry_pos_hash(cell.pos)
            token_secret = hash64_u64(position_hash ^ 0x535449434B455254, sticker_index)
            capability_seed = hash64_u64(token_secret ^ 0x4341502D54485244, face_id)
            _FACE_SLOT_MATERIALS[key] = (cell.pos, position_hash, token_secret, capability_seed)
            return _FACE_SLOT_MATERIALS[key]
    raise ValueError("sticker index not found")


def anchor_thread_material(face_id: int, sticker_index: int) -> tuple[int, int, int]:
    _, position_hash, token_secret, capability_seed = face_sticker_material(face_id, sticker_index)
    anchor_secret = hash64_u64(position_hash ^ SESSION_NONCE, face_id)
    anchor_parity = hash64_u64(anchor_secret, sticker_index)
    running_seed = hash64_u64(anchor_parity, position_hash)
    return anchor_secret, anchor_parity, running_seed


def anchor_thread_ack(
    face_id: int,
    sticker_index: int,
    epoch: int,
    line_slot: int,
    move_code: int,
    fd_digest_before_rebind: int,
    anchor_thread_states: list[dict[int, AnchorThreadState]],
) -> int:
    _, position_hash, _, _ = face_sticker_material(face_id, sticker_index)
    anchor_secret, anchor_parity, running_seed = anchor_thread_material(face_id, sticker_index)
    state = anchor_thread_states[face_id].setdefault(
        sticker_index,
        AnchorThreadState(running_digest=running_seed, wake_count=0),
    )
    running_digest = state.running_digest
    running_digest = hash64_u64(running_digest ^ anchor_secret, epoch)
    running_digest = hash64_u64(running_digest, line_slot)
    running_digest = hash64_u64(running_digest, move_code)
    running_digest = hash64_u64(running_digest, fd_digest_before_rebind)
    running_digest = hash64_u64(running_digest, anchor_parity)
    running_digest = hash64_u64(running_digest, position_hash)
    state.running_digest = running_digest
    state.wake_count += 1
    return hash64_u64(running_digest, state.wake_count)


def sticker_ack_tag(
    position_hash: int,
    token_secret: int,
    capability_seed: int,
    mailbox_kind: int,
    generation: int,
    orientation: int,
    epoch: int,
    line_slot: int,
    move_code: int,
    fd_digest_before_rebind: int,
) -> int:
    local_digest = hash64_u64(position_hash ^ capability_seed, epoch)
    local_digest = hash64_u64(local_digest, line_slot)
    local_digest = hash64_u64(local_digest, move_code)
    local_digest = hash64_u64(local_digest, fd_digest_before_rebind)
    local_digest = hash64_u64(local_digest, mailbox_kind)
    local_digest = hash64_u64(local_digest, generation)
    local_digest = hash64_u64(local_digest, orientation)
    ack_tag = hash64_u64(local_digest ^ token_secret, capability_seed)
    ack_tag = hash64_u64(ack_tag, epoch)
    return ack_tag


def sticker_commit_tag(prepare_ack: int, target_staging_slot: int, epoch: int, token: StickerToken) -> int:
    digest = hash64_u64(prepare_ack ^ 0x434F4D4D49542D21, target_staging_slot)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, token.hidden_secret)
    digest = hash64_u64(digest, token.capability_seed)
    digest = hash64_u64(digest, token.generation)
    digest = hash64_u64(digest, token.orientation)
    digest = hash64_u64(digest, token.visible_color)
    return digest


def staging_slots_for_face_epoch(epoch: int, face_id: int, capacity: int = STAGING_CAPACITY) -> list[int]:
    base = ((epoch - 1) * FACE_COUNT * 6) + (face_id * 6)
    return [((base + offset) % capacity) for offset in range(6)]


def face_line_shift(move: MoveOp) -> int:
    if abs(move.quarter_turns) == 2:
        return 3
    if move.quarter_turns == -1:
        return 5
    return 1


def tx_trace_step(trace: int, state: int, value: int) -> int:
    trace = hash64_u64(trace, state)
    trace = hash64_u64(trace, value)
    return trace


def face_tx_trace_digest(
    epoch: int,
    line_slot: int,
    move: MoveOp,
    fd_digest_before_rebind: int,
    staging_digest: int,
    ack_digest: int,
    swap_digest: int,
    face_digest_after: int,
) -> int:
    tx_id = epoch ^ (line_slot << 16)
    trace = 0x54582D434F524F55
    trace = hash64_u64(trace, tx_id)
    trace = hash64_u64(trace, epoch)
    trace = hash64_u64(trace, move.move_code)
    trace = tx_trace_step(trace, 2, fd_digest_before_rebind)
    trace = tx_trace_step(trace, 2, fd_digest_before_rebind ^ line_slot)
    trace = tx_trace_step(trace, 1, staging_digest)
    trace = tx_trace_step(trace, 3, ack_digest)
    trace = tx_trace_step(trace, 4, swap_digest)
    trace = tx_trace_step(trace, 5, face_digest_after)
    trace = tx_trace_step(trace, 6, tx_id ^ face_digest_after)
    return trace


def face_digest_components(
    worker_key: int,
    face_id: int,
    epoch: int,
    move: MoveOp,
    line_slot: int,
    line_index: int,
    is_row: int,
    fd_digest_before_rebind: int,
    face_thread_tokens: list[list[StickerToken]],
    anchor_thread_states: list[dict[int, AnchorThreadState]],
    rebound_shadow_state: list[dict[int, int]] | None = None,
) -> tuple[int, int, int]:
    ready_mask = 0
    ack_digest = worker_key ^ 0x41434B2D46414345
    commit_digest = worker_key ^ 0x434F4D4D49542D21
    staging_digest = worker_key ^ 0x53544147494E472D
    anchor_slots = set(face_anchor_slots(face_id))
    line_slots = face_mailboxes_for_line(is_row, line_index)
    staging_slots = staging_slots_for_face_epoch(epoch, face_id)
    shift = face_line_shift(move)
    prepare_acks: list[int] = []
    staging_tokens: list[StickerToken] = []
    for logical in line_slots:
        ready_mask |= 1 << logical
        token = clone_token(face_thread_tokens[face_id][logical])
        _, position_hash, _, _ = face_sticker_material(face_id, logical)
        staging_tokens.append(token)
        prepare_ack = sticker_ack_tag(
            position_hash,
            token.hidden_secret,
            token.capability_seed,
            face_mailbox_kind(logical, face_id),
            token.generation,
            token.orientation,
            epoch,
            line_slot,
            move.move_code,
            fd_digest_before_rebind,
        )
        prepare_acks.append(prepare_ack)
        staging_digest = hash64_u64(staging_digest, position_hash)
        staging_digest = hash64_u64(staging_digest, token.visible_color)
        staging_digest = hash64_u64(staging_digest, token.orientation)
        staging_digest = hash64_u64(staging_digest, token.generation)
        staging_digest = hash64_u64(staging_digest, token.hidden_secret)
        staging_digest = hash64_u64(staging_digest, token.capability_seed)
        staging_digest = hash64_u64(staging_digest, prepare_ack)
        ack_digest = hash64_u64(ack_digest, prepare_ack)
        if rebound_shadow_state is not None and logical in rebound_shadow_state[face_id]:
            ack_digest = hash64_u64(ack_digest, rebound_shadow_state[face_id][logical])
            ack_digest = hash64_u64(ack_digest, 1)
        if logical in anchor_slots:
            ack_digest = hash64_u64(
                ack_digest,
                anchor_thread_ack(
                    face_id,
                    logical,
                    epoch,
                    line_slot,
                    move.move_code,
                    fd_digest_before_rebind,
                    anchor_thread_states,
                ),
            )
    for i, prepare_ack in enumerate(prepare_acks):
        committed = clone_token(staging_tokens[(i + 6 - shift) % 6])
        target_pos, _, _, _ = face_sticker_material(face_id, line_slots[i])
        committed.generation = (committed.generation + 1) & 0xFFFF
        committed.orientation = orientation_from_normal(target_pos.nx, target_pos.ny, target_pos.nz)
        face_thread_tokens[face_id][line_slots[i]] = committed
        target_staging_slot = staging_slots[(i + 6 - shift) % 6]
        commit_digest = hash64_u64(
            commit_digest,
            sticker_commit_tag(prepare_ack, target_staging_slot, epoch, committed),
        )

    digest = worker_key ^ 0x464143452D444947
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, line_slot)
    digest = hash64_u64(digest, line_index)
    digest = hash64_u64(digest, is_row)
    digest = hash64_u64(digest, fd_digest_before_rebind)
    digest = hash64_u64(digest, ready_mask)
    digest = hash64_u64(digest, staging_digest)
    digest = hash64_u64(digest, ack_digest)
    digest = hash64_u64(digest, commit_digest)
    ack_commit_digest = hash64_u64(ack_digest ^ 0x434F4D4D49542D21, commit_digest)
    swap_capability = hash64_u64(staging_digest ^ ready_mask, ack_digest)
    tx_trace = face_tx_trace_digest(
        epoch,
        line_slot,
        move,
        fd_digest_before_rebind,
        staging_digest,
        ack_digest,
        hash64_u64(staging_digest ^ ack_digest, swap_capability),
        commit_digest ^ ready_mask,
    )
    face_route_digest = hash64_u64(tx_trace ^ worker_key, digest)
    face_route_digest = hash64_u64(face_route_digest, ack_commit_digest)
    face_route_digest = hash64_u64(face_route_digest, commit_digest)
    return digest, ack_commit_digest, face_route_digest


def line_digest(
    worker_key: int,
    move: MoveOp,
    epoch: int,
    face_digest_value: int,
    face_id: int,
    is_row: int,
    line_index: int,
) -> int:
    digest = worker_key ^ 0x4C494E452D444947
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, face_digest_value)
    digest = hash64_u64(digest, face_id)
    digest = hash64_u64(digest, is_row)
    digest = hash64_u64(digest, line_index)
    return digest


def line_reply_capability(
    face_route_digest: int,
    line_digest_value: int,
    ack_digest: int,
    face_id: int,
    is_row: int,
    line_index: int,
) -> int:
    digest = hash64_u64(face_route_digest ^ line_digest_value, ack_digest)
    digest = hash64_u64(digest, (face_id << 16) | (is_row << 8) | line_index)
    return digest


def watchdog_key(session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x5741544348444F47
    digest = hash64_u64(digest, 0x4E4F4953452D4644)
    return digest


def watchdog_event_index(move: MoveOp, epoch: int) -> int:
    digest = 0x5741544348494E44
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    return digest % 8


def watchdog_noise_digest(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    worker_key = watchdog_key(session_nonce)
    event_index = watchdog_event_index(move, epoch)
    counter_value = 1
    signal_number = 10  # SIGUSR1 on Linux

    digest = worker_key ^ 0x5741544348444447
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, event_index)
    digest = hash64_u64(digest, counter_value)
    digest = hash64_u64(digest, signal_number)
    return digest


def watchdog_trace_digest(move: MoveOp, epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    worker_key = watchdog_key(session_nonce)
    noise_digest = watchdog_noise_digest(move, epoch, session_nonce)
    payload1 = (watchdog_event_index(move, epoch) << 32) | 10
    capability = hash64_u64(worker_key ^ noise_digest, epoch)
    digest = session_nonce ^ 0x5741544348545243
    digest = hash64_u64(digest, noise_digest)
    digest = hash64_u64(digest, payload1)
    digest = hash64_u64(digest, capability)
    return digest


def line_stage_digests(
    move: MoveOp,
    epoch: int,
    slice_orbit: int,
    fd_digest_before_rebind: int,
    face_thread_tokens: list[list[StickerToken]] | None = None,
    anchor_thread_states: list[dict[int, AnchorThreadState]] | None = None,
    rebound_shadow_state: list[dict[int, int]] | None = None,
    session_nonce: int = SESSION_NONCE,
) -> tuple[int, int]:
    line_aggregate = session_nonce ^ 0x4C494E452D414747
    line_trace_digest = session_nonce ^ 0x4C494E4554524143
    line_trace_digest = hash64_u64(line_trace_digest, epoch)
    line_trace_digest = hash64_u64(line_trace_digest, move.move_code)
    if face_thread_tokens is None:
        face_thread_tokens = build_face_thread_tokens()
    if anchor_thread_states is None:
        anchor_thread_states = build_anchor_thread_states()

    for face_id, is_row, line_index in active_line_worker_keys(move):
        slot = line_index if is_row else line_index + 6
        f_digest, ack_digest, face_route_digest = face_digest_components(
            face_worker_key(face_id, session_nonce),
            face_id,
            epoch,
            move,
            slot,
            line_index,
            is_row,
            fd_digest_before_rebind,
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        l_digest = line_digest(
            line_worker_key(session_nonce, face_id, is_row, line_index),
            move,
            epoch,
            f_digest,
            face_id,
            is_row,
            line_index,
        )
        line_capability = line_reply_capability(
            face_route_digest,
            l_digest,
            ack_digest,
            face_id,
            is_row,
            line_index,
        )
        line_aggregate = hash64_u64(line_aggregate, l_digest)
        line_aggregate = hash64_u64(line_aggregate, ack_digest)
        line_trace_digest = hash64_u64(line_trace_digest, l_digest)
        line_trace_digest = hash64_u64(line_trace_digest, ack_digest)
        line_trace_digest = hash64_u64(line_trace_digest, line_capability)

    return (
        hash64_u64(slice_orbit ^ 0x4C494E452D464F4C, line_aggregate),
        hash64_u64(line_trace_digest, line_aggregate),
    )


def full_orbit_digest_for_move(
    move: MoveOp,
    epoch: int,
    fd_digest_before_rebind: int,
    face_thread_tokens: list[list[StickerToken]] | None = None,
    anchor_thread_states: list[dict[int, AnchorThreadState]] | None = None,
    rebound_shadow_state: list[dict[int, int]] | None = None,
    session_nonce: int = SESSION_NONCE,
) -> int:
    slice_orbit, _ = slice_stage_digests(move, epoch, session_nonce)
    line_orbit, _ = line_stage_digests(
        move,
        epoch,
        slice_orbit,
        fd_digest_before_rebind,
        face_thread_tokens,
        anchor_thread_states,
        rebound_shadow_state,
        session_nonce,
    )
    return hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch, session_nonce))


def fd_owner_tag(entry: FdOwnerEntry) -> int:
    digest = entry.pos_hash ^ 0x46444F574E455231
    digest = hash64_u64(digest, entry.logical_owner)
    digest = hash64_u64(digest, entry.logical_slot)
    digest = hash64_u64(digest, entry.fd_generation)
    digest = hash64_u64(digest, entry.mailbox_kind)
    digest = hash64_u64(digest, entry.pos.x)
    digest = hash64_u64(digest, entry.pos.y)
    digest = hash64_u64(digest, entry.pos.z)
    digest = hash64_u64(digest, entry.pos.nx + 1)
    digest = hash64_u64(digest, entry.pos.ny + 1)
    digest = hash64_u64(digest, entry.pos.nz + 1)
    return digest


def anchor_hint_from_state(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x414E43484F522D44
    chosen: list[list[tuple[int, CubeCell, int, int]]] = [[] for _ in range(FACE_COUNT)]

    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        if not (1 <= row <= 4 and 1 <= col <= 4):
            continue
        pos_hash = registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT)
        score = session_nonce ^ 0x414E43484F522D53
        score = hash64_u64(score, face)
        score = hash64_u64(score, row)
        score = hash64_u64(score, col)
        score = hash64_u64(score, pos_hash)
        chosen[face].append((score, cell, row, col))

    for face in range(FACE_COUNT):
        anchors = sorted(chosen[face], key=lambda item: item[0])[:4]
        for slot, (score, cell, row, col) in enumerate(anchors):
            digest = hash64_u64(digest, face)
            digest = hash64_u64(digest, slot)
            digest = hash64_u64(digest, row)
            digest = hash64_u64(digest, col)
            digest = hash64_u64(digest, score)
            digest = hash64_u64(digest, cell.token.hidden_secret)
            digest = hash64_u64(digest, cell.token.capability_seed)
            digest = hash64_u64(digest, cell.token.generation)
            digest = hash64_u64(digest, cell.token.orientation)
            digest = hash64_u64(digest, cell.token.visible_color)
    return digest


def courier_key(session_nonce: int = SESSION_NONCE) -> int:
    return hash64_u64(session_nonce ^ 0x4355524945522D54, 0x4C53312D434F5552)


def courier_seed(session_nonce: int = SESSION_NONCE) -> int:
    return hash64_u64(courier_key(session_nonce), session_nonce)


def courier_digest_step(
    running_digest: int,
    anchor_hint: int,
    epoch: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    running_digest = hash64_u64(running_digest ^ courier_key(session_nonce), anchor_hint)
    return hash64_u64(running_digest, epoch)


def fd_owners_digest(entries: list[FdOwnerEntry]) -> int:
    digest = 0x46444F574E2D4447
    for entry in entries:
        digest = hash64_u64(digest, entry.pos_hash)
        digest = hash64_u64(digest, entry.logical_owner)
        digest = hash64_u64(digest, entry.logical_slot)
        digest = hash64_u64(digest, entry.fd_generation)
        digest = hash64_u64(digest, entry.ownership_tag)
    return digest


def fd_owner_index_for_pos(entries: list[FdOwnerEntry], pos: StickerPos) -> int:
    for index, entry in enumerate(entries):
        if entry.pos == pos:
            return index
    raise ValueError(f"fd owner position not found: {pos!r}")


def build_fd_owners() -> list[FdOwnerEntry]:
    state = solved_state()
    entries: list[FdOwnerEntry] = []
    for index, cell in enumerate(state.cells):
        entry = FdOwnerEntry(
            pos=cell.pos,
            pos_hash=registry_pos_hash(cell.pos),
            logical_owner=face_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz),
            logical_slot=index % STICKERS_PER_FACE,
            fd_generation=0,
            mailbox_kind=face_mailbox_kind(index % STICKERS_PER_FACE, face_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz)),
            ownership_tag=0,
        )
        entry.ownership_tag = fd_owner_tag(entry)
        entries.append(entry)
    return entries


def rebind_fd_owners(entries: list[FdOwnerEntry], move: MoveOp) -> tuple[list[FdOwnerEntry], int]:
    next_entries, digest, _, _, _ = rebind_fd_owners_with_sample(entries, move)
    return next_entries, digest


def rebind_fd_owners_with_sample(entries: list[FdOwnerEntry], move: MoveOp) -> tuple[list[FdOwnerEntry], int, int, int, int]:
    next_entries = [
        FdOwnerEntry(
            pos=entry.pos,
            pos_hash=entry.pos_hash,
            logical_owner=entry.logical_owner,
            logical_slot=entry.logical_slot,
            fd_generation=entry.fd_generation,
            mailbox_kind=entry.mailbox_kind,
            ownership_tag=entry.ownership_tag,
        )
        for entry in entries
    ]
    sample_owner_face = -1
    sample_local_slot = -1
    sample_generation = 0

    for entry in entries:
        dst_pos = rotate_pos(entry.pos, move)
        dst_index = fd_owner_index_for_pos(entries, dst_pos)
        moved = sticker_in_layer(entry.pos, move)
        next_entries[dst_index].logical_owner = entry.logical_owner
        next_entries[dst_index].logical_slot = entry.logical_slot
        next_entries[dst_index].mailbox_kind = entry.mailbox_kind
        next_entries[dst_index].fd_generation = entry.fd_generation + (1 if moved else 0)
        if moved and next_entries[dst_index].mailbox_kind != 2 and sample_owner_face < 0:
            sample_owner_face = next_entries[dst_index].logical_owner
            sample_local_slot = next_entries[dst_index].logical_slot
            sample_generation = next_entries[dst_index].fd_generation

    for entry in next_entries:
        entry.ownership_tag = fd_owner_tag(entry)
    return next_entries, fd_owners_digest(next_entries), sample_owner_face, sample_local_slot, sample_generation


def broker_trace_digest(
    fd_digest: int,
    sample_owner_face: int,
    sample_local_slot: int,
    sample_generation: int,
    epoch: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    worker_key = hash64_u64(session_nonce ^ 0x42524F4B45522D36, 0x46442D4F574E4552)
    payload1 = (
        ((sample_owner_face & 0xFF) << 56)
        | ((sample_local_slot & 0xFF) << 48)
        | (1 << 32)
        | (sample_generation & 0xFFFFFFFF)
    )
    capability = hash64_u64(worker_key ^ fd_digest, payload1 ^ epoch)
    digest = session_nonce ^ 0x42524F4B45525452
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, payload1)
    digest = hash64_u64(digest, capability)
    digest = hash64_u64(digest, 1)
    return digest


def capability_step(
    capability_chain: int,
    move: MoveOp,
    orbit_digest: int,
    fd_digest: int,
    anchor_digest: int,
    epoch: int,
    visible: int,
    hidden: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = capability_chain ^ 0x4341502D43484149
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, orbit_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, session_nonce)
    return digest


def epoch_key_seed(session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x45504F43484B4559
    digest = hash64_u64(digest, 0x535445502D534545)
    return digest


def step_proof(
    capability_chain: int,
    path_digest_before: int,
    anchor_digest: int,
    fd_digest: int,
    epoch_key: int,
    move: MoveOp,
    epoch: int,
    visible: int,
    hidden: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = epoch_key ^ 0x535445502D505246
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, epoch)
    return digest


def epoch_key_step(
    epoch_key: int,
    proof: int,
    capability_chain: int,
    path_digest_before: int,
    anchor_digest: int,
    fd_digest: int,
    epoch: int,
) -> int:
    digest = epoch_key ^ 0x45504F43484B4559
    digest = hash64_u64(digest, proof)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def step_token(
    proof: int,
    epoch_key: int,
    path_digest_before: int,
    anchor_digest: int,
    fd_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    epoch: int,
) -> int:
    digest = epoch_key ^ 0x535445502D544B4E
    digest = hash64_u64(digest, proof)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def step_trace_step(
    step_trace_digest: int,
    token: int,
    proof: int,
    path_digest_before: int,
    capability_chain: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    epoch: int,
) -> int:
    digest = step_trace_digest ^ 0x535452434D495443
    digest = hash64_u64(digest, token)
    digest = hash64_u64(digest, proof)
    digest = hash64_u64(digest, path_digest_before)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, epoch)
    return digest


def path_step(
    path_digest: int,
    move: MoveOp,
    orbit_digest: int,
    fd_digest: int,
    anchor_digest: int,
    epoch: int,
    visible: int,
    hidden: int,
    capability_chain: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = path_digest ^ 0x504154482D364344
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, orbit_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def audit_root_step(
    audit_root: int,
    epoch: int,
    move: MoveOp,
    orbit_digest: int,
    fd_digest: int,
    visible: int,
    hidden: int,
    path_digest: int,
    capability_chain: int,
    poison: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = audit_root ^ 0x41554449542D524F
    digest = hash64_u64(digest, epoch)
    digest = hash64_u64(digest, move.move_code)
    digest = hash64_u64(digest, orbit_digest)
    digest = hash64_u64(digest, fd_digest)
    digest = hash64_u64(digest, visible)
    digest = hash64_u64(digest, hidden)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, poison)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def step_receipt(
    step_proof_value: int,
    path_digest: int,
    audit_root: int,
    poison: int,
    epoch_key: int,
    epoch: int,
) -> int:
    digest = epoch_key ^ 0x535445502D524350
    digest = hash64_u64(digest, step_proof_value)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, audit_root)
    digest = hash64_u64(digest, poison)
    digest = hash64_u64(digest, epoch)
    return digest


def peer_proof_for_environment(
    seed_commitment: int,
    peer_ok: bool,
    peer_proof_salt: int = PEER_PROOF_SALT,
) -> int:
    digest = SESSION_NONCE ^ 0x504545522D505246
    digest = hash64_u64(digest, peer_proof_salt)
    digest = hash64_u64(digest, seed_commitment)
    digest = hash64_u64(digest, RUNTIME_FD_SHARE)
    digest = hash64_u64(digest, RUNTIME_TLS_SHARE)
    digest = hash64_u64(digest, RUNTIME_SHM_SHARE)
    digest = hash64_u64(digest, 1 if peer_ok else 0)
    return digest


def move_mac_seed_for_block(
    block_index: int,
    receipt_seed: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x4D4F56452D4D4143
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, receipt_seed)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    digest = hash64_u64(digest, peer_proof)
    return digest


def move_mac_for_slot(
    mac_seed: int,
    slot_index: int,
    move_code: int,
) -> int:
    digest = mac_seed ^ 0x4D4F56452D534C54
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, move_code)
    return digest


def move_mac_seed(
    block_index: int,
    receipt_seed: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    peer_proof: int,
) -> int:
    return move_mac_seed_for_block(
        block_index,
        receipt_seed,
        path_digest,
        capability_chain,
        anchor_digest,
        distributed_route_digest,
        distributed_tls_mesh_digest,
        peer_proof,
    )


def move_mac(
    mac_seed: int,
    slot_index: int,
    move_code: int,
) -> int:
    return move_mac_for_slot(mac_seed, slot_index, move_code)


def slot_witness(
    block_index: int,
    slot_index: int,
    path_digest_before_move: int,
    capability_chain_after_move: int,
    anchor_digest_after_move: int,
    fd_digest_after_move: int,
    distributed_route_digest_after_move: int,
    distributed_tls_mesh_digest_after_move: int,
    step_receipt_value: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x5749544E45535321
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, path_digest_before_move)
    digest = hash64_u64(digest, capability_chain_after_move)
    digest = hash64_u64(digest, anchor_digest_after_move)
    digest = hash64_u64(digest, fd_digest_after_move)
    digest = hash64_u64(digest, distributed_route_digest_after_move)
    digest = hash64_u64(digest, distributed_tls_mesh_digest_after_move)
    digest = hash64_u64(digest, step_receipt_value)
    digest = hash64_u64(digest, peer_proof)
    return digest


def witness_auth(
    block_index: int,
    move_count: int,
    slot_witnesses: tuple[int, int, int],
    expected_step_receipt: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x5749544E2D415554
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for value in slot_witnesses:
        digest = hash64_u64(digest, value)
    digest = hash64_u64(digest, expected_step_receipt)
    digest = hash64_u64(digest, peer_proof)
    return digest


def tls_slot_mask(
    block_index: int,
    slot_index: int,
    capability_chain_after_move: int,
    distributed_tls_mesh_digest_after_move: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x544c532d534c4f54
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, capability_chain_after_move)
    digest = hash64_u64(digest, distributed_tls_mesh_digest_after_move)
    digest = hash64_u64(digest, peer_proof)
    return digest


def shm_slot_mask(
    block_index: int,
    slot_index: int,
    path_digest_before_move: int,
    fd_digest_after_move: int,
    distributed_route_digest_after_move: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x53484d2d534c4f54
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, slot_index)
    digest = hash64_u64(digest, path_digest_before_move)
    digest = hash64_u64(digest, fd_digest_after_move)
    digest = hash64_u64(digest, distributed_route_digest_after_move)
    digest = hash64_u64(digest, peer_proof)
    return digest


def broker_auth(
    block_index: int,
    move_count: int,
    broker_move_macs: tuple[int, int, int],
    expected_step_receipt: int,
    peer_proof: int,
) -> int:
    digest = SESSION_NONCE ^ 0x42524f4b2d415554
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for value in broker_move_macs:
        digest = hash64_u64(digest, value)
    digest = hash64_u64(digest, expected_step_receipt)
    digest = hash64_u64(digest, peer_proof)
    return digest


def capsule_chain_seed(
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = session_nonce ^ 0x43415053554C4521
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def capsule_digest(
    block_index: int,
    move_count: int,
    broker_move_macs: tuple[int, int, int],
    broker_auth_value: int,
    expected_step_receipt: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = session_nonce ^ 0x434150532D424C4B
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for move_mac_value in broker_move_macs:
        digest = hash64_u64(digest, move_mac_value)
    digest = hash64_u64(digest, broker_auth_value)
    digest = hash64_u64(digest, expected_step_receipt)
    return digest


def capsule_chain_step(
    chain_digest: int,
    block_index: int,
    move_count: int,
    masked_move_macs: tuple[int, int, int],
    witness_auth_value: int,
    expected_step_receipt: int,
    path_digest: int,
    capability_chain: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
) -> int:
    digest = chain_digest ^ 0x434150432D434841
    digest = hash64_u64(digest, block_index)
    digest = hash64_u64(digest, move_count)
    for move_mac_value in masked_move_macs:
        digest = hash64_u64(digest, move_mac_value)
    digest = hash64_u64(digest, witness_auth_value)
    digest = hash64_u64(digest, expected_step_receipt)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, distributed_route_digest)
    digest = hash64_u64(digest, distributed_tls_mesh_digest)
    return digest


def final_capsule_auth(
    capsule_chain_digest: int,
    move_count: int,
    last_step_receipt: int,
    audit_root: int,
    path_digest: int,
    capability_chain: int,
    parser_digest: int,
    anchor_digest: int,
    peer_proof: int,
    session_nonce: int = SESSION_NONCE,
) -> int:
    digest = session_nonce ^ 0x46494E2D43415053
    digest = hash64_u64(digest, capsule_chain_digest)
    digest = hash64_u64(digest, move_count)
    digest = hash64_u64(digest, last_step_receipt)
    digest = hash64_u64(digest, audit_root)
    digest = hash64_u64(digest, path_digest)
    digest = hash64_u64(digest, capability_chain)
    digest = hash64_u64(digest, parser_digest)
    digest = hash64_u64(digest, anchor_digest)
    digest = hash64_u64(digest, peer_proof)
    return digest


def derive_block_capsule_key(
    block_index: int,
    fd_share: int,
    tls_share: int,
    shm_share: int,
    receipt_seed: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    peer_proof: int,
) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"CubeIPC-6-block-capsule")
    hasher.update(block_index.to_bytes(4, "little"))
    hasher.update(fd_share.to_bytes(8, "little"))
    hasher.update(tls_share.to_bytes(8, "little"))
    hasher.update(shm_share.to_bytes(8, "little"))
    hasher.update(receipt_seed.to_bytes(8, "little"))
    hasher.update(path_digest.to_bytes(8, "little"))
    hasher.update(capability_chain.to_bytes(8, "little"))
    hasher.update(anchor_digest.to_bytes(8, "little"))
    hasher.update(distributed_route_digest.to_bytes(8, "little"))
    hasher.update(distributed_tls_mesh_digest.to_bytes(8, "little"))
    hasher.update(peer_proof.to_bytes(8, "little"))
    return hasher.digest()


def derive_final_capsule_key(
    fd_share: int,
    tls_share: int,
    shm_share: int,
    last_step_receipt: int,
    path_digest: int,
    capability_chain: int,
    anchor_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    capsule_chain_digest: int,
    peer_proof: int,
) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"CubeIPC-6-final-capsule")
    hasher.update(fd_share.to_bytes(8, "little"))
    hasher.update(tls_share.to_bytes(8, "little"))
    hasher.update(shm_share.to_bytes(8, "little"))
    hasher.update(last_step_receipt.to_bytes(8, "little"))
    hasher.update(path_digest.to_bytes(8, "little"))
    hasher.update(capability_chain.to_bytes(8, "little"))
    hasher.update(anchor_digest.to_bytes(8, "little"))
    hasher.update(distributed_route_digest.to_bytes(8, "little"))
    hasher.update(distributed_tls_mesh_digest.to_bytes(8, "little"))
    hasher.update(capsule_chain_digest.to_bytes(8, "little"))
    hasher.update(peer_proof.to_bytes(8, "little"))
    return hasher.digest()


def derive_block_capsule_nonce(block_index: int) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"block-capsule")
    hasher.update(block_index.to_bytes(4, "little"))
    hasher.update(SESSION_NONCE.to_bytes(8, "little"))
    return hasher.digest()[:12]


def derive_final_capsule_nonce() -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"final-capsule")
    hasher.update(SESSION_NONCE.to_bytes(8, "little"))
    return hasher.digest()[:12]


def commit_salt_for_epoch(epoch: int, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x53414C542D45504F
    digest = hash64_u64(digest, epoch)
    return digest


def commitment_for_capability(capability_chain: int, salt: int) -> int:
    return hash64_u64(capability_chain, salt)


def supported_move_tokens() -> list[str]:
    tokens: list[str] = []
    outer_faces = ["U", "D", "F", "B", "L", "R"]
    rotations = ["x", "y", "z"]

    for face in outer_faces:
        tokens.extend([face, f"{face}'", f"{face}2"])
    for depth in (2, 3):
        for face in outer_faces:
            tokens.extend([f"{depth}{face}", f"{depth}{face}'", f"{depth}{face}2"])
    for width in ("", "3"):
        for face in outer_faces:
            prefix = f"{width}{face}w"
            tokens.extend([prefix, f"{prefix}'", f"{prefix}2"])
    for rot in rotations:
        tokens.extend([rot, f"{rot}'", f"{rot}2"])
    return tokens


def compute_step_proofs(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
) -> list[int]:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(answer, scramble))
    fd_entries = build_fd_owners()
    proofs: list[int] = []
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    epoch = 0

    apply_moves(state, parse_move_line(scramble))
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    for move in parse_move_line(answer):
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        proofs.append(
            step_proof(
                capability_chain,
                path_digest,
                anchor_digest,
                fd_digest,
                epoch_key,
                move,
                epoch,
                visible,
                hidden,
                distributed_route_digest_value,
                distributed_tls_mesh_digest_value,
            )
        )
        epoch_key = epoch_key_step(
            epoch_key,
            proofs[-1],
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )

    return proofs


def compute_step_tokens(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
) -> list[int]:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(answer, scramble))
    fd_entries = build_fd_owners()
    tokens: list[int] = []
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    epoch = 0

    apply_moves(state, parse_move_line(scramble))
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    for move in parse_move_line(answer):
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        proof = step_proof(
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch_key,
            move,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        tokens.append(
            step_token(
                proof,
                epoch_key,
                path_digest,
                anchor_digest,
                fd_digest,
                distributed_route_digest_value,
                distributed_tls_mesh_digest_value,
                epoch,
            )
        )
        epoch_key = epoch_key_step(
            epoch_key,
            proof,
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )

    return tokens


def compute_commitments(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
) -> tuple[list[int], list[int]]:
    tokens = compute_step_tokens(scramble, answer, initial_state=initial_state)
    salts = [commit_salt_for_epoch(index + 1) for index in range(len(tokens))]
    return tokens, salts


def block_capsule_contexts(
    scramble: str,
    answer: str,
    initial_state: CubeState | None = None,
    peer_ok: bool = True,
) -> list[BlockCapsuleContext]:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(answer, scramble))
    fd_entries = build_fd_owners()
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    audit_root = AUDIT_ROOT_SEED
    poison = 0
    epoch = 0
    last_step_receipt = 0
    parsed_moves = parse_move_line(answer)
    parser_digest = parser_digest_for_moves(parsed_moves)
    contexts: list[BlockCapsuleContext] = []
    seed_commitment = hash64_u64(SESSION_NONCE, REGISTRY_SALT)
    peer_proof = peer_proof_for_environment(seed_commitment, peer_ok)

    apply_moves(state, parse_move_line(scramble))
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    capsule_chain_digest_value = capsule_chain_seed(
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    )
    initial_block_anchor_digest = hash64_u64(SESSION_NONCE ^ 0x414E43482D534545, anchor_hint_value)
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    block_move_codes: list[int] = []
    block_broker_move_macs: list[int] = []
    block_slot_witnesses: list[int] = []
    block_receipt_seed = seed_commitment
    pre_path_digest = path_digest
    pre_capability_chain = capability_chain
    pre_anchor_digest = initial_block_anchor_digest
    pre_distributed_route_digest = distributed_route_digest_value
    pre_distributed_tls_mesh_digest = distributed_tls_mesh_digest_value

    for move_index, move in enumerate(parsed_moves):
        visible = 0
        hidden = 0
        proof = 0
        fd_digest = 0
        orbit = 0
        epoch += 1
        if move_index % 3 == 0:
            pre_path_digest = path_digest
            pre_capability_chain = capability_chain
            pre_anchor_digest = initial_block_anchor_digest if move_index == 0 else anchor_digest
            pre_distributed_route_digest = distributed_route_digest_value
            pre_distributed_tls_mesh_digest = distributed_tls_mesh_digest_value
            block_move_codes = []
            block_broker_move_macs = []
            block_slot_witnesses = []
        path_digest_before_move = path_digest
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        proof = step_proof(
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch_key,
            move,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        epoch_key = epoch_key_step(
            epoch_key,
            proof,
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        audit_root = audit_root_step(
            audit_root,
            epoch,
            move,
            orbit,
            fd_digest,
            visible,
            hidden,
            path_digest,
            capability_chain,
            poison,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        last_step_receipt = step_receipt(
            proof,
            path_digest,
            audit_root,
            poison,
            epoch_key,
            epoch,
        )
        block_move_codes.append(move.move_code)
        slot_index = len(block_move_codes) - 1
        block_mac_value = move_mac(
            move_mac_seed_for_block(
                len(contexts),
                block_receipt_seed,
                pre_path_digest,
                pre_capability_chain,
                pre_anchor_digest,
                pre_distributed_route_digest,
                pre_distributed_tls_mesh_digest,
                peer_proof,
            ),
            slot_index,
            move.move_code,
        )
        slot_witness_value = slot_witness(
            len(contexts),
            slot_index,
            path_digest_before_move,
            capability_chain,
            anchor_digest,
            fd_digest,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            last_step_receipt,
            peer_proof,
        )
        block_slot_witnesses.append(slot_witness_value)
        block_broker_move_macs.append(
            block_mac_value
            ^ tls_slot_mask(
                len(contexts),
                slot_index,
                capability_chain,
                distributed_tls_mesh_digest_value,
                peer_proof,
            )
            ^ shm_slot_mask(
                len(contexts),
                slot_index,
                path_digest_before_move,
                fd_digest,
                distributed_route_digest_value,
                peer_proof,
            )
        )
        if ((move_index + 1) % 3) == 0 or (move_index + 1) == len(parsed_moves):
            padded_broker = tuple(block_broker_move_macs + [0] * (3 - len(block_broker_move_macs)))
            padded_witnesses = tuple(block_slot_witnesses + [0] * (3 - len(block_slot_witnesses)))
            move_count = len(block_move_codes)
            broker_auth_value = broker_auth(
                len(contexts),
                move_count,
                padded_broker,
                last_step_receipt,
                peer_proof,
            )
            capsule_chain_digest_value = capsule_chain_step(
                capsule_chain_digest_value,
                len(contexts),
                move_count,
                padded_broker,
                broker_auth_value,
                last_step_receipt,
                path_digest,
                capability_chain,
                distributed_route_digest_value,
                distributed_tls_mesh_digest_value,
            )
            contexts.append(
                BlockCapsuleContext(
                    block_index=len(contexts),
                    move_count=move_count,
                    broker_move_macs=padded_broker,
                    broker_auth=broker_auth_value,
                    expected_step_receipt=last_step_receipt,
                    path_digest=pre_path_digest,
                    capability_chain=pre_capability_chain,
                    anchor_digest=pre_anchor_digest,
                    distributed_route_digest=pre_distributed_route_digest,
                    distributed_tls_mesh_digest=pre_distributed_tls_mesh_digest,
                    last_step_receipt=last_step_receipt,
                    path_digest_after_block=path_digest,
                    capability_chain_after_block=capability_chain,
                    anchor_digest_after_block=anchor_digest,
                    distributed_route_digest_after_block=distributed_route_digest_value,
                    distributed_tls_mesh_digest_after_block=distributed_tls_mesh_digest_value,
                    capsule_chain_digest_after_block=capsule_chain_digest_value,
                    final_auth=0,
                )
            )
            block_receipt_seed = last_step_receipt

    if contexts:
        contexts[-1].final_auth = final_capsule_auth(
            capsule_chain_digest_value,
            len(parsed_moves),
            last_step_receipt,
            audit_root,
            path_digest,
            capability_chain,
            parser_digest,
            anchor_digest,
            peer_proof,
        )
    return contexts


def solved_state() -> CubeState:
    global _SOLVED_STATE_TEMPLATE

    if _SOLVED_STATE_TEMPLATE is not None:
        return clone_state(_SOLVED_STATE_TEMPLATE)

    cells: list[CubeCell] = []

    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(col, CUBE_N - 1, CUBE_N - 1 - row, 0, 1, 0), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(col, 0, row, 0, -1, 0), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(col, CUBE_N - 1 - row, CUBE_N - 1, 0, 0, 1), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(CUBE_N - 1 - col, CUBE_N - 1 - row, 0, 0, 0, -1), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(CUBE_N - 1, CUBE_N - 1 - row, CUBE_N - 1 - col, 1, 0, 0), None))  # type: ignore[arg-type]
    for row in range(CUBE_N):
        for col in range(CUBE_N):
            cells.append(CubeCell(StickerPos(0, CUBE_N - 1 - row, col, -1, 0, 0), None))  # type: ignore[arg-type]

    seed = 0xC6E6000000000000
    for cell in cells:
        face = face_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz)
        hidden_secret, seed = splitmix64(seed)
        capability_seed, seed = splitmix64(seed)
        cell.token = StickerToken(
            visible_color=face_color(face),
            orientation=orientation_from_normal(cell.pos.nx, cell.pos.ny, cell.pos.nz),
            generation=0,
            hidden_secret=hidden_secret,
            capability_seed=capability_seed,
        )

    _SOLVED_STATE_TEMPLATE = CubeState(cells)
    return clone_state(_SOLVED_STATE_TEMPLATE)


def build_challenge_base_state(answer: str, scramble: str) -> CubeState:
    state = solved_state()
    seed = challenge_material_seed(answer, scramble)

    for index, cell in enumerate(state.cells):
        position_hash = registry_pos_hash(cell.pos)
        cell.token.hidden_secret = hash64_u64(cell.token.hidden_secret ^ seed, position_hash)
        cell.token.capability_seed = hash64_u64(
            cell.token.capability_seed ^ (seed ^ 0x4341502D544F4B4E),
            index,
        )

    return state


def build_challenge_start_state(answer: str, scramble: str) -> CubeState:
    state = build_challenge_base_state(answer, scramble)
    apply_moves(state, parse_move_line(scramble))
    return state


def build_release_start_state(answer: str, scramble: str) -> CubeState:
    state = build_challenge_start_state(answer, scramble)
    for cell in state.cells:
        cell.token.generation = 0
    return state


def edge_pair_parity_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x454447452D504152
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        top_or_bottom = row in {0, CUBE_N - 1}
        left_or_right = col in {0, CUBE_N - 1}
        if not ((top_or_bottom or left_or_right) and not (top_or_bottom and left_or_right)):
            continue
        digest = hash64_u64(digest, face)
        digest = hash64_u64(digest, row)
        digest = hash64_u64(digest, col)
        digest = hash64_u64(digest, cell.token.hidden_secret)
        digest = hash64_u64(digest, cell.token.capability_seed)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.token.orientation)
        digest = hash64_u64(digest, cell.token.visible_color)
    return digest


def center_anchor_parity_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x43454E5445524150
    for face_id in range(FACE_COUNT):
        for anchor_index, slot in enumerate(face_anchor_slots(face_id)):
            row, col = divmod(slot, CUBE_N)
            for cell in state.cells:
                face, cell_row, cell_col = face_row_col(cell.pos)
                if face != face_id or cell_row != row or cell_col != col:
                    continue
                digest = hash64_u64(digest, face_id)
                digest = hash64_u64(digest, anchor_index)
                digest = hash64_u64(digest, cell.token.hidden_secret)
                digest = hash64_u64(digest, cell.token.capability_seed)
                digest = hash64_u64(digest, cell.token.generation)
                digest = hash64_u64(digest, cell.token.orientation)
                digest = hash64_u64(digest, cell.token.visible_color)
                break
    return digest


def fd_generation_parity_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x464447454E504152
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        local_index = row * CUBE_N + col
        mailbox_kind = face_mailbox_kind(local_index)
        digest = hash64_u64(digest, face)
        digest = hash64_u64(digest, local_index)
        digest = hash64_u64(digest, mailbox_kind)
        digest = hash64_u64(digest, registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT))
    return digest


def thread_lifecycle_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> int:
    digest = session_nonce ^ 0x5448524541444C46
    for index, cell in enumerate(state.cells):
        digest = hash64_u64(digest, index)
        digest = hash64_u64(digest, registry_pos_hash(cell.pos, session_nonce, REGISTRY_SALT))
        digest = hash64_u64(digest, cell.token.hidden_secret)
        digest = hash64_u64(digest, cell.token.capability_seed)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.token.orientation)
        digest = hash64_u64(digest, cell.token.visible_color)
    return digest


def hidden_runtime_seed(state: CubeState, session_nonce: int = SESSION_NONCE) -> tuple[int, int, int, int, int, int, int, int, int]:
    fd_generation = fd_generation_parity_seed(state, session_nonce)
    edge_pair = edge_pair_parity_seed(state, session_nonce)
    thread_lifecycle = thread_lifecycle_seed(state, session_nonce)
    anchor_hint = anchor_hint_from_state(state, session_nonce)
    distributed_route = session_nonce ^ 0x524F5554452D494E
    distributed_route = hash64_u64(distributed_route, fd_generation)
    distributed_route = hash64_u64(distributed_route, edge_pair)
    distributed_tls_mesh = session_nonce ^ 0x544C532D4D455348
    distributed_tls_mesh = hash64_u64(distributed_tls_mesh, thread_lifecycle)
    distributed_tls_mesh = hash64_u64(distributed_tls_mesh, anchor_hint)
    return (
        hidden_digest(state),
        orientation_digest(state),
        anchor_hint,
        edge_pair,
        center_anchor_parity_seed(state, session_nonce),
        fd_generation,
        thread_lifecycle,
        distributed_route,
        distributed_tls_mesh,
    )


def hidden_runtime_step(
    hidden_value: int,
    orientation_value: int,
    anchor_hint_value: int,
    edge_pair_parity_value: int,
    center_anchor_parity_value: int,
    fd_generation_parity_value: int,
    thread_lifecycle_digest_value: int,
    distributed_route_digest_value: int,
    distributed_tls_mesh_digest_value: int,
    move: MoveOp,
    epoch: int,
    orbit_digest: int,
    fd_digest: int,
    visible_digest_value: int,
    distributed_route_input: int,
    distributed_tls_mesh_input: int,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    hidden_next = hidden_value ^ 0x4849442D52544D45
    hidden_next = hash64_u64(hidden_next, epoch)
    hidden_next = hash64_u64(hidden_next, move.move_code)
    hidden_next = hash64_u64(hidden_next, orbit_digest)
    hidden_next = hash64_u64(hidden_next, fd_digest)
    hidden_next = hash64_u64(hidden_next, visible_digest_value)
    hidden_next = hash64_u64(hidden_next, move.layer_mask)
    hidden_next = hash64_u64(hidden_next, move.quarter_turns & 0xFF)

    orientation_next = orientation_value ^ 0x4F52492D52544D45
    orientation_next = hash64_u64(orientation_next, epoch)
    orientation_next = hash64_u64(orientation_next, move.move_code)
    orientation_next = hash64_u64(orientation_next, move.axis_onehot)
    orientation_next = hash64_u64(orientation_next, move.layer_mask)
    orientation_next = hash64_u64(orientation_next, move.is_global_rotation)
    orientation_next = hash64_u64(orientation_next, move.is_wide)
    orientation_next = hash64_u64(orientation_next, orbit_digest)

    anchor_next = anchor_hint_value ^ 0x414E432D52544D45
    anchor_next = hash64_u64(anchor_next, epoch)
    anchor_next = hash64_u64(anchor_next, move.move_code)
    anchor_next = hash64_u64(anchor_next, visible_digest_value)
    anchor_next = hash64_u64(anchor_next, fd_digest)
    anchor_next = hash64_u64(anchor_next, hidden_next)
    anchor_next = hash64_u64(anchor_next, orientation_next)

    edge_pair_parity_next = edge_pair_parity_value ^ 0x454447452D4D4F56
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, epoch)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, move.move_code)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, move.axis_onehot)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, move.layer_mask)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, orbit_digest)
    edge_pair_parity_next = hash64_u64(edge_pair_parity_next, visible_digest_value)

    center_anchor_parity_next = center_anchor_parity_value ^ 0x43454E5445524D56
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, epoch)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, move.move_code)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, anchor_next)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, hidden_next)
    center_anchor_parity_next = hash64_u64(center_anchor_parity_next, visible_digest_value)

    fd_generation_parity_next = fd_generation_parity_value ^ 0x464447454E4D4F56
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, epoch)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, fd_digest)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, move.move_code)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, move.layer_mask)
    fd_generation_parity_next = hash64_u64(fd_generation_parity_next, move.is_global_rotation)

    thread_lifecycle_next = thread_lifecycle_digest_value ^ 0x5448524541444D56
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, epoch)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, move.move_code)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, orbit_digest)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, hidden_next)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, orientation_next)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, fd_digest)
    thread_lifecycle_next = hash64_u64(thread_lifecycle_next, visible_digest_value)

    distributed_route_next = distributed_route_digest_value ^ 0x524F5554452D4D56
    distributed_route_next = hash64_u64(distributed_route_next, epoch)
    distributed_route_next = hash64_u64(distributed_route_next, move.move_code)
    distributed_route_next = hash64_u64(distributed_route_next, orbit_digest)
    distributed_route_next = hash64_u64(distributed_route_next, fd_digest)
    distributed_route_next = hash64_u64(distributed_route_next, distributed_route_input)
    distributed_route_next = hash64_u64(distributed_route_next, edge_pair_parity_next)
    distributed_route_next = hash64_u64(distributed_route_next, fd_generation_parity_next)

    distributed_tls_mesh_next = distributed_tls_mesh_digest_value ^ 0x544C532D4D56454E
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, epoch)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, move.move_code)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, distributed_tls_mesh_input)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, anchor_next)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, orientation_next)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, thread_lifecycle_next)
    distributed_tls_mesh_next = hash64_u64(distributed_tls_mesh_next, distributed_route_next)

    return (
        hidden_next,
        orientation_next,
        anchor_next,
        edge_pair_parity_next,
        center_anchor_parity_next,
        fd_generation_parity_next,
        thread_lifecycle_next,
        distributed_route_next,
        distributed_tls_mesh_next,
    )


def find_cell_index(state: CubeState, pos: StickerPos) -> int:
    for index, cell in enumerate(state.cells):
        if cell.pos == pos:
            return index
    raise ValueError(f"position not found: {pos!r}")


def apply_move(state: CubeState, move: MoveOp) -> None:
    next_tokens: list[StickerToken | None] = [None] * TOTAL_STICKERS
    for cell in state.cells:
        dst_pos = rotate_pos(cell.pos, move)
        dst_index = find_cell_index(state, dst_pos)
        token = StickerToken(
            visible_color=cell.token.visible_color,
            orientation=cell.token.orientation,
            generation=cell.token.generation,
            hidden_secret=cell.token.hidden_secret,
            capability_seed=cell.token.capability_seed,
        )
        if sticker_in_layer(cell.pos, move):
            token.generation += 1
            token.orientation = orientation_from_normal(dst_pos.nx, dst_pos.ny, dst_pos.nz)
        next_tokens[dst_index] = token

    for index, token in enumerate(next_tokens):
        assert token is not None
        state.cells[index].token = token


def apply_moves(state: CubeState, moves: list[MoveOp]) -> None:
    for move in moves:
        apply_move(state, move)


def apply_moves_with_path_digest(state: CubeState, moves: list[MoveOp]) -> int:
    digest = PATH_DIGEST_SEED
    capability = CAPABILITY_SEED
    fd_entries = build_fd_owners()
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    anchor_digest = courier_seed()
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    epoch = 0
    for move in moves:
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_owners_digest(fd_entries),
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace_digest(move, epoch))
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability = capability_step(
            capability,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        digest = path_step(
            digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden_value,
            capability,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
    return digest


def visible_digest(state: CubeState) -> int:
    digest = 0x1234567890ABCDEF
    for cell in state.cells:
        digest = hash64_u64(digest, cell.token.visible_color)
        digest = hash64_u64(digest, cell.token.orientation)
    return digest


def hidden_digest(state: CubeState) -> int:
    digest = 0x0DDC0FFEEBADF00D
    for cell in state.cells:
        digest = hash64_u64(digest, cell.token.hidden_secret)
        digest = hash64_u64(digest, cell.token.capability_seed)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.token.orientation)
    return digest


def orientation_digest(state: CubeState) -> int:
    digest = 0x4F5249454E542D36
    for index, cell in enumerate(state.cells):
        digest = hash64_u64(digest, index)
        digest = hash64_u64(digest, cell.token.orientation)
        digest = hash64_u64(digest, cell.token.generation)
        digest = hash64_u64(digest, cell.pos.x)
        digest = hash64_u64(digest, cell.pos.y)
        digest = hash64_u64(digest, cell.pos.z)
        digest = hash64_u64(digest, cell.pos.nx + 1)
        digest = hash64_u64(digest, cell.pos.ny + 1)
        digest = hash64_u64(digest, cell.pos.nz + 1)
    return digest


def face_row_col(pos: StickerPos) -> tuple[int, int, int]:
    face = face_from_normal(pos.nx, pos.ny, pos.nz)
    if face == FACE_U:
        return face, CUBE_N - 1 - pos.z, pos.x
    if face == FACE_D:
        return face, pos.z, pos.x
    if face == FACE_F:
        return face, CUBE_N - 1 - pos.y, pos.x
    if face == FACE_B:
        return face, CUBE_N - 1 - pos.y, CUBE_N - 1 - pos.x
    if face == FACE_R:
        return face, CUBE_N - 1 - pos.y, CUBE_N - 1 - pos.z
    if face == FACE_L:
        return face, CUBE_N - 1 - pos.y, pos.z
    raise ValueError("invalid face")


def render_visible(state: CubeState) -> str:
    labels = ["U", "D", "F", "B", "R", "L"]
    faces = [[["?" for _ in range(CUBE_N)] for _ in range(CUBE_N)] for _ in range(FACE_COUNT)]
    for cell in state.cells:
        face, row, col = face_row_col(cell.pos)
        faces[face][row][col] = color_char(cell.token.visible_color)

    parts: list[str] = []
    for face, label in enumerate(labels):
        parts.append(f"{label}:")
        for row in faces[face]:
            parts.append(" ".join(row))
        if face + 1 != FACE_COUNT:
            parts.append("")
    return "\n".join(parts)


def derive_final_key(
    visible: int,
    hidden: int,
    orientation: int,
    edge_pair_parity: int,
    center_anchor_parity: int,
    fd_generation_parity: int,
    thread_lifecycle_digest: int,
    distributed_route_digest: int,
    distributed_tls_mesh_digest: int,
    path_digest: int,
    capability_chain: int,
    step_trace_digest: int,
    fd_digest: int,
    audit_root: int,
    anchor_digest: int,
    parser_digest: int,
    poison: int,
) -> bytes:
    material = (
        int(visible & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(hidden & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(orientation & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(edge_pair_parity & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(center_anchor_parity & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(fd_generation_parity & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(thread_lifecycle_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(distributed_route_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(distributed_tls_mesh_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(path_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(capability_chain & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(step_trace_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(fd_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(audit_root & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(anchor_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(parser_digest & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + int(poison & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        + b"CubeIPC-6"
    )
    return hashlib.sha256(material).digest()


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def _chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state = constants + [int.from_bytes(key[i * 4 : i * 4 + 4], "little") for i in range(8)]
    state += [counter]
    state += [int.from_bytes(nonce[i * 4 : i * 4 + 4], "little") for i in range(3)]

    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    words = [((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16)]
    return b"".join(words)


def chacha20_xor(data: bytes, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    output = bytearray(data)
    offset = 0
    block_counter = counter
    while offset < len(output):
        block = _chacha20_block(key, nonce, block_counter)
        take = min(64, len(output) - offset)
        for index in range(take):
            output[offset + index] ^= block[index]
        offset += take
        block_counter += 1
    return bytes(output)


def evaluate_sequence(
    scramble: str,
    moves: str,
    initial_state: CubeState | None = None,
) -> tuple[int, int, int, int, int, int, int]:
    details = evaluate_sequence_details(scramble, moves, initial_state=initial_state)
    return (
        details.visible_digest,
        details.hidden_digest,
        details.path_digest,
        details.capability_chain,
        details.fd_digest,
        details.audit_root,
        details.anchor_digest,
    )


def evaluate_sequence_details(
    scramble: str,
    moves: str,
    initial_state: CubeState | None = None,
) -> EvaluationDetails:
    state = clone_state(initial_state if initial_state is not None else build_challenge_base_state(moves, scramble))
    fd_entries = build_fd_owners()
    parsed_moves = parse_move_line(moves)
    apply_moves(state, parse_move_line(scramble))
    face_thread_tokens = build_face_thread_tokens(state)
    anchor_thread_states = build_anchor_thread_states()
    rebound_shadow_state = build_rebound_shadow_state()
    path_digest = PATH_DIGEST_SEED
    capability_chain = CAPABILITY_SEED
    fd_digest = fd_owners_digest(fd_entries)
    audit_root = AUDIT_ROOT_SEED
    anchor_digest = courier_seed()
    epoch_key = epoch_key_seed()
    step_trace_digest = SESSION_NONCE ^ 0x5354455054524143
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = hidden_runtime_seed(state)
    step_trace_digest = hash64_u64(step_trace_digest, distributed_route_digest_value)
    step_trace_digest = hash64_u64(step_trace_digest, distributed_tls_mesh_digest_value)
    poison = 0
    epoch = 0

    for move in parsed_moves:
        epoch += 1
        slice_orbit, slice_trace_digest = slice_stage_digests(move, epoch)
        line_orbit, line_trace_digest = line_stage_digests(
            move,
            epoch,
            slice_orbit,
            fd_digest,
            face_thread_tokens,
            anchor_thread_states,
            rebound_shadow_state,
        )
        watchdog_trace = watchdog_trace_digest(move, epoch)
        orbit = hash64_u64(line_orbit ^ 0x5741544348444447, watchdog_noise_digest(move, epoch))
        apply_move(state, move)
        fd_entries, fd_digest, sample_owner_face, sample_local_slot, sample_generation = rebind_fd_owners_with_sample(fd_entries, move)
        broker_trace = broker_trace_digest(
            fd_digest,
            sample_owner_face,
            sample_local_slot,
            sample_generation,
            epoch,
        )
        if (
            sample_owner_face >= 0
            and sample_local_slot >= 0
            and face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
        ):
            rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
        visible = visible_digest(state)
        distributed_route_input = distributed_route_digest_value ^ 0x524F5554452D5354
        distributed_route_input = hash64_u64(distributed_route_input, slice_trace_digest)
        distributed_route_input = hash64_u64(distributed_route_input, broker_trace)
        distributed_route_input = hash64_u64(distributed_route_input, watchdog_trace)
        distributed_route_input = hash64_u64(distributed_route_input, orbit)
        distributed_route_input = hash64_u64(distributed_route_input, fd_digest)
        distributed_tls_mesh_input = distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, line_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_owner_face)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, sample_local_slot)
        distributed_tls_mesh_input = hash64_u64(distributed_tls_mesh_input, visible)
        (
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        ) = hidden_runtime_step(
            hidden_value,
            orientation_value,
            anchor_hint_value,
            edge_pair_parity_value,
            center_anchor_parity_value,
            fd_generation_parity_value,
            thread_lifecycle_digest_value,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            move,
            epoch,
            orbit,
            fd_digest,
            visible,
            distributed_route_input,
            distributed_tls_mesh_input,
        )
        hidden = hidden_value
        anchor_digest = courier_digest_step(anchor_digest, anchor_hint_value, epoch)
        capability_chain = capability_step(
            capability_chain,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        current_step_proof = step_proof(
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch_key,
            move,
            epoch,
            visible,
            hidden,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        token = step_token(
            current_step_proof,
            epoch_key,
            path_digest,
            anchor_digest,
            fd_digest,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            epoch,
        )
        if epoch > len(parsed_moves):
            poison = hash64_u64(poison ^ 0x504F49534F4E2D58, epoch)
        step_trace_digest = step_trace_step(
            step_trace_digest,
            token,
            current_step_proof,
            path_digest,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
            epoch,
        )
        epoch_key = epoch_key_step(
            epoch_key,
            current_step_proof,
            capability_chain,
            path_digest,
            anchor_digest,
            fd_digest,
            epoch,
        )
        path_digest = path_step(
            path_digest,
            move,
            orbit,
            fd_digest,
            anchor_digest,
            epoch,
            visible,
            hidden,
            capability_chain,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )
        audit_root = audit_root_step(
            audit_root,
            epoch,
            move,
            orbit,
            fd_digest,
            visible,
            hidden,
            path_digest,
            capability_chain,
            poison,
            distributed_route_digest_value,
            distributed_tls_mesh_digest_value,
        )

    return EvaluationDetails(
        visible_digest=visible_digest(state),
        hidden_digest=hidden_value,
        orientation_digest=orientation_value,
        edge_pair_parity=edge_pair_parity_value,
        center_anchor_parity=center_anchor_parity_value,
        fd_generation_parity=fd_generation_parity_value,
        thread_lifecycle_digest=thread_lifecycle_digest_value,
        distributed_route_digest=distributed_route_digest_value,
        distributed_tls_mesh_digest=distributed_tls_mesh_digest_value,
        path_digest=path_digest,
        capability_chain=capability_chain,
        step_trace_digest=step_trace_digest,
        fd_digest=fd_digest,
        audit_root=audit_root,
        anchor_digest=anchor_digest,
        parser_digest=parser_digest_for_moves(parsed_moves),
        poison=poison,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scramble", default=DEV_SCRAMBLE)
    parser.add_argument("--moves", default="")
    parser.add_argument("--render", action="store_true")
    args = parser.parse_args()

    state = solved_state()
    apply_moves(state, parse_move_line(args.scramble))
    details = evaluate_sequence_details(args.scramble, args.moves)

    if args.render:
        state = solved_state()
        apply_moves(state, parse_move_line(args.scramble))
        apply_moves(state, parse_move_line(args.moves))
        print(render_visible(state))
        print()
    print(f"visible_digest=0x{details.visible_digest:016x}")
    print(f"hidden_digest=0x{details.hidden_digest:016x}")
    print(f"orientation_digest=0x{details.orientation_digest:016x}")
    print(f"distributed_route_digest=0x{details.distributed_route_digest:016x}")
    print(f"distributed_tls_mesh_digest=0x{details.distributed_tls_mesh_digest:016x}")
    print(f"path_digest=0x{details.path_digest:016x}")
    print(f"capability_chain=0x{details.capability_chain:016x}")
    print(f"step_trace_digest=0x{details.step_trace_digest:016x}")
    print(f"fd_ownership_digest=0x{details.fd_digest:016x}")
    print(f"audit_root=0x{details.audit_root:016x}")
    print(f"anchor_digest=0x{details.anchor_digest:016x}")
    print(f"parser_digest=0x{details.parser_digest:016x}")


if __name__ == "__main__":
    main()
'''
exec(_OFFLINE_SIM_SOURCE, offline_sim.__dict__)


import argparse
import hashlib
import shlex
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path





OFFICIAL_SHA256 = "607b5b77dfbd587b293526efc6887583b18ea3fd27a6021f143f6d944c1c7e2e"
PUBLIC_SCRAMBLE = b""
COMMITMENT_COUNT = 36
INITIAL_TOKEN_BYTES = 4320
BLOCK_CAPSULE_BYTES = 56
BLOCK_CAPSULE_COUNT = 12
INITIAL_TOKENS_TAG = 0x8E27279C55A6ECD3
BLOCK_CAPSULE_TAGS = [
    0x9B42CF0FD5BFBA52,
    0xC3B7092AC0B0F795,
    0xE3B3865143F0476C,
    0xFE1B08CD8B14F20E,
    0x86F4EC018E0658D9,
    0xE885E3EC48F06285,
    0x239EBB9760A43BF4,
    0x8C561B61566BC4E2,
    0xCDEBDD7F58A9C652,
    0x95C5BBC60C0A4545,
    0xB3799B01737E1765,
    0x43C666EA2B3A8CD1,
]
INITIAL_TOKENS_PREFIX = bytes.fromhex(
    "4f891079bf370644cbd9c6643b16eadfdaaef765c5eb805a"
)
BLOCK_CAPSULES_PREFIX = bytes.fromhex(
    "5db029ebabe38ceaade4442e682e0fd28a58788fe4745dd6"
)


@dataclass
class BlockKeyContext:
    receipt_seed: int
    path_digest: int
    capability_chain: int
    anchor_digest: int
    distributed_route_digest: int
    distributed_tls_mesh_digest: int
    peer_proof: int


@dataclass
class DecodedBlock:
    block_index: int
    move_count: int
    broker_move_macs: tuple[int, int, int]
    broker_auth: int
    expected_step_receipt: int
    capsule_digest: int


@dataclass
class SearchCtx:
    state: offline_sim.CubeState
    fd_entries: list[offline_sim.FdOwnerEntry]
    face_thread_tokens: list[list[offline_sim.StickerToken]]
    anchor_thread_states: list[dict[int, offline_sim.AnchorThreadState]]
    rebound_shadow_state: list[dict[int, int]]
    path_digest: int
    capability_chain: int
    fd_digest: int
    anchor_digest: int
    epoch_key: int
    audit_root: int
    hidden_value: int
    orientation_value: int
    anchor_hint_value: int
    edge_pair_parity_value: int
    center_anchor_parity_value: int
    fd_generation_parity_value: int
    thread_lifecycle_digest_value: int
    distributed_route_digest_value: int
    distributed_tls_mesh_digest_value: int
    epoch: int
    move_count: int
    current_block_index: int
    block_receipt_seed: int
    block_entry_path_digest: int
    block_entry_capability_chain: int
    block_entry_anchor_digest: int
    block_entry_distributed_route_digest: int
    block_entry_distributed_tls_mesh_digest: int
    peer_proof: int
    pending_block_count: int
    pending_broker_move_macs: tuple[int, int, int]
    last_step_receipt: int


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive_material_key(label: str, commitment_count: int) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(label.encode("ascii"))
    hasher.update(PUBLIC_SCRAMBLE)
    hasher.update(offline_sim.SESSION_NONCE.to_bytes(8, "little"))
    hasher.update(commitment_count.to_bytes(8, "little"))
    return hasher.digest()


def derive_material_nonce(label: str) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(label.encode("ascii"))
    hasher.update(PUBLIC_SCRAMBLE)
    hasher.update(offline_sim.SESSION_NONCE.to_bytes(8, "little"))
    return hasher.digest()[:12]


def find_unique(data: bytes, needle: bytes, label: str) -> int:
    offset = data.find(needle)
    if offset < 0:
        raise ValueError(f"{label} signature not found")
    second = data.find(needle, offset + 1)
    if second >= 0:
        raise ValueError(f"{label} signature is not unique")
    return offset


def decode_initial_state(binary_data: bytes) -> offline_sim.CubeState:
    offset = find_unique(binary_data, INITIAL_TOKENS_PREFIX, "initial-tokens")
    key = derive_material_key("initial-tokens", COMMITMENT_COUNT)
    nonce = derive_material_nonce("initial-tokens")
    enc = binary_data[offset : offset + INITIAL_TOKEN_BYTES]
    plain = offline_sim.chacha20_xor(enc, key, nonce)
    tag_seed = int.from_bytes(key[:8], "little") ^ int.from_bytes(nonce[:8], "little")
    tag = offline_sim.hash64_bytes(plain, tag_seed)
    if tag != INITIAL_TOKENS_TAG:
        raise ValueError(f"initial-tokens tag mismatch: 0x{tag:016x}")

    state = offline_sim.solved_state()
    for index in range(offline_sim.TOTAL_STICKERS):
        base = index * 20
        state.cells[index].token.visible_color = plain[base]
        state.cells[index].token.orientation = plain[base + 1]
        state.cells[index].token.generation = int.from_bytes(plain[base + 2 : base + 4], "little")
        state.cells[index].token.hidden_secret = int.from_bytes(plain[base + 4 : base + 12], "little")
        state.cells[index].token.capability_seed = int.from_bytes(plain[base + 12 : base + 20], "little")
    return state


def clone_sticker_token(token: offline_sim.StickerToken) -> offline_sim.StickerToken:
    return offline_sim.StickerToken(
        visible_color=token.visible_color,
        orientation=token.orientation,
        generation=token.generation,
        hidden_secret=token.hidden_secret,
        capability_seed=token.capability_seed,
    )


def clone_state(state: offline_sim.CubeState) -> offline_sim.CubeState:
    return offline_sim.CubeState(
        [
            offline_sim.CubeCell(
                pos=cell.pos,
                token=clone_sticker_token(cell.token),
            )
            for cell in state.cells
        ]
    )


def clone_fd_entries(entries: list[offline_sim.FdOwnerEntry]) -> list[offline_sim.FdOwnerEntry]:
    return [
        offline_sim.FdOwnerEntry(
            pos=entry.pos,
            pos_hash=entry.pos_hash,
            logical_owner=entry.logical_owner,
            logical_slot=entry.logical_slot,
            fd_generation=entry.fd_generation,
            mailbox_kind=entry.mailbox_kind,
            ownership_tag=entry.ownership_tag,
        )
        for entry in entries
    ]


def clone_face_threads(face_threads: list[list[offline_sim.StickerToken]]) -> list[list[offline_sim.StickerToken]]:
    return [[clone_sticker_token(token) for token in face_tokens] for face_tokens in face_threads]


def clone_anchor_threads(
    anchor_threads: list[dict[int, offline_sim.AnchorThreadState]]
) -> list[dict[int, offline_sim.AnchorThreadState]]:
    return [
        {
            slot: offline_sim.AnchorThreadState(
                running_digest=state.running_digest,
                wake_count=state.wake_count,
            )
            for slot, state in face_states.items()
        }
        for face_states in anchor_threads
    ]


def clone_search_ctx(ctx: SearchCtx) -> SearchCtx:
    return SearchCtx(
        state=clone_state(ctx.state),
        fd_entries=clone_fd_entries(ctx.fd_entries),
        face_thread_tokens=clone_face_threads(ctx.face_thread_tokens),
        anchor_thread_states=clone_anchor_threads(ctx.anchor_thread_states),
        rebound_shadow_state=[dict(face_map) for face_map in ctx.rebound_shadow_state],
        path_digest=ctx.path_digest,
        capability_chain=ctx.capability_chain,
        fd_digest=ctx.fd_digest,
        anchor_digest=ctx.anchor_digest,
        epoch_key=ctx.epoch_key,
        audit_root=ctx.audit_root,
        hidden_value=ctx.hidden_value,
        orientation_value=ctx.orientation_value,
        anchor_hint_value=ctx.anchor_hint_value,
        edge_pair_parity_value=ctx.edge_pair_parity_value,
        center_anchor_parity_value=ctx.center_anchor_parity_value,
        fd_generation_parity_value=ctx.fd_generation_parity_value,
        thread_lifecycle_digest_value=ctx.thread_lifecycle_digest_value,
        distributed_route_digest_value=ctx.distributed_route_digest_value,
        distributed_tls_mesh_digest_value=ctx.distributed_tls_mesh_digest_value,
        epoch=ctx.epoch,
        move_count=ctx.move_count,
        current_block_index=ctx.current_block_index,
        block_receipt_seed=ctx.block_receipt_seed,
        block_entry_path_digest=ctx.block_entry_path_digest,
        block_entry_capability_chain=ctx.block_entry_capability_chain,
        block_entry_anchor_digest=ctx.block_entry_anchor_digest,
        block_entry_distributed_route_digest=ctx.block_entry_distributed_route_digest,
        block_entry_distributed_tls_mesh_digest=ctx.block_entry_distributed_tls_mesh_digest,
        peer_proof=ctx.peer_proof,
        pending_block_count=ctx.pending_block_count,
        pending_broker_move_macs=ctx.pending_broker_move_macs,
        last_step_receipt=ctx.last_step_receipt,
    )


def initial_block_context(start_state: offline_sim.CubeState) -> BlockKeyContext:
    (
        _hidden_value,
        _orientation_value,
        anchor_hint_value,
        _edge_pair_parity_value,
        _center_anchor_parity_value,
        _fd_generation_parity_value,
        _thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = offline_sim.hidden_runtime_seed(start_state)
    seed_commitment = offline_sim.hash64_u64(offline_sim.SESSION_NONCE, offline_sim.REGISTRY_SALT)
    return BlockKeyContext(
        receipt_seed=seed_commitment,
        path_digest=offline_sim.PATH_DIGEST_SEED,
        capability_chain=offline_sim.CAPABILITY_SEED,
        anchor_digest=offline_sim.hash64_u64(
            offline_sim.SESSION_NONCE ^ 0x414E43482D534545,
            anchor_hint_value,
        ),
        distributed_route_digest=distributed_route_digest_value,
        distributed_tls_mesh_digest=distributed_tls_mesh_digest_value,
        peer_proof=offline_sim.peer_proof_for_environment(seed_commitment, True),
    )


def make_initial_search_ctx(start_state: offline_sim.CubeState) -> SearchCtx:
    (
        hidden_value,
        orientation_value,
        anchor_hint_value,
        edge_pair_parity_value,
        center_anchor_parity_value,
        fd_generation_parity_value,
        thread_lifecycle_digest_value,
        distributed_route_digest_value,
        distributed_tls_mesh_digest_value,
    ) = offline_sim.hidden_runtime_seed(start_state)
    seed_commitment = offline_sim.hash64_u64(offline_sim.SESSION_NONCE, offline_sim.REGISTRY_SALT)
    block_entry_anchor_digest = offline_sim.hash64_u64(
        offline_sim.SESSION_NONCE ^ 0x414E43482D534545,
        anchor_hint_value,
    )
    anchor_digest = offline_sim.courier_seed()
    fd_entries = offline_sim.build_fd_owners()
    return SearchCtx(
        state=clone_state(start_state),
        fd_entries=fd_entries,
        face_thread_tokens=offline_sim.build_face_thread_tokens(start_state),
        anchor_thread_states=offline_sim.build_anchor_thread_states(),
        rebound_shadow_state=offline_sim.build_rebound_shadow_state(),
        path_digest=offline_sim.PATH_DIGEST_SEED,
        capability_chain=offline_sim.CAPABILITY_SEED,
        fd_digest=offline_sim.fd_owners_digest(fd_entries),
        anchor_digest=anchor_digest,
        epoch_key=offline_sim.epoch_key_seed(),
        audit_root=offline_sim.AUDIT_ROOT_SEED,
        hidden_value=hidden_value,
        orientation_value=orientation_value,
        anchor_hint_value=anchor_hint_value,
        edge_pair_parity_value=edge_pair_parity_value,
        center_anchor_parity_value=center_anchor_parity_value,
        fd_generation_parity_value=fd_generation_parity_value,
        thread_lifecycle_digest_value=thread_lifecycle_digest_value,
        distributed_route_digest_value=distributed_route_digest_value,
        distributed_tls_mesh_digest_value=distributed_tls_mesh_digest_value,
        epoch=0,
        move_count=0,
        current_block_index=0,
        block_receipt_seed=seed_commitment,
        block_entry_path_digest=offline_sim.PATH_DIGEST_SEED,
        block_entry_capability_chain=offline_sim.CAPABILITY_SEED,
        block_entry_anchor_digest=block_entry_anchor_digest,
        block_entry_distributed_route_digest=distributed_route_digest_value,
        block_entry_distributed_tls_mesh_digest=distributed_tls_mesh_digest_value,
        peer_proof=offline_sim.peer_proof_for_environment(seed_commitment, True),
        pending_block_count=0,
        pending_broker_move_macs=(0, 0, 0),
        last_step_receipt=0,
    )


def decode_block_capsule(
    binary_data: bytes,
    block_data_offset: int,
    block_index: int,
    ctx: BlockKeyContext,
) -> DecodedBlock:
    key = offline_sim.derive_block_capsule_key(
        block_index,
        offline_sim.RUNTIME_FD_SHARE,
        offline_sim.RUNTIME_TLS_SHARE,
        offline_sim.RUNTIME_SHM_SHARE,
        ctx.receipt_seed,
        ctx.path_digest,
        ctx.capability_chain,
        ctx.anchor_digest,
        ctx.distributed_route_digest,
        ctx.distributed_tls_mesh_digest,
        ctx.peer_proof,
    )
    nonce = offline_sim.derive_block_capsule_nonce(block_index)
    raw = binary_data[
        block_data_offset + (block_index * BLOCK_CAPSULE_BYTES) :
        block_data_offset + ((block_index + 1) * BLOCK_CAPSULE_BYTES)
    ]
    plain = offline_sim.chacha20_xor(raw, key, nonce)
    tag_seed = int.from_bytes(key[:8], "little") ^ int.from_bytes(nonce[:8], "little")
    tag = offline_sim.hash64_bytes(plain, tag_seed)
    if tag != BLOCK_CAPSULE_TAGS[block_index]:
        raise ValueError(f"block {block_index} tag mismatch: 0x{tag:016x}")

    decoded = struct.unpack("<IIQQQQQQ", plain)
    decoded_block_index = decoded[0]
    move_count = decoded[1]
    broker_move_macs = (decoded[2], decoded[3], decoded[4])
    broker_auth = decoded[5]
    expected_step_receipt = decoded[6]
    capsule_digest = decoded[7]

    if decoded_block_index != block_index:
        raise ValueError(
            f"block index mismatch: expected {block_index}, got {decoded_block_index}"
        )
    if move_count == 0 or move_count > 3:
        raise ValueError(f"invalid move_count in block {block_index}: {move_count}")

    expected_digest = offline_sim.capsule_digest(
        block_index,
        move_count,
        broker_move_macs,
        broker_auth,
        expected_step_receipt,
    )
    if capsule_digest != expected_digest:
        raise ValueError(
            f"block {block_index} capsule digest mismatch: "
            f"0x{capsule_digest:016x} != 0x{expected_digest:016x}"
        )

    return DecodedBlock(
        block_index=block_index,
        move_count=move_count,
        broker_move_macs=broker_move_macs,
        broker_auth=broker_auth,
        expected_step_receipt=expected_step_receipt,
        capsule_digest=capsule_digest,
    )


def advance_search_ctx(ctx: SearchCtx, token: str) -> SearchCtx:
    move = offline_sim.parse_move(token)
    next_ctx = clone_search_ctx(ctx)
    path_digest_before_move = next_ctx.path_digest

    next_ctx.epoch += 1
    slice_orbit, slice_trace_digest = offline_sim.slice_stage_digests(move, next_ctx.epoch)
    line_orbit, line_trace_digest = offline_sim.line_stage_digests(
        move,
        next_ctx.epoch,
        slice_orbit,
        offline_sim.fd_owners_digest(next_ctx.fd_entries),
        next_ctx.face_thread_tokens,
        next_ctx.anchor_thread_states,
        next_ctx.rebound_shadow_state,
    )
    orbit = offline_sim.hash64_u64(
        line_orbit ^ 0x5741544348444447,
        offline_sim.watchdog_noise_digest(move, next_ctx.epoch),
    )
    offline_sim.apply_move(next_ctx.state, move)
    (
        next_ctx.fd_entries,
        fd_digest,
        sample_owner_face,
        sample_local_slot,
        sample_generation,
    ) = offline_sim.rebind_fd_owners_with_sample(next_ctx.fd_entries, move)
    broker_trace = offline_sim.broker_trace_digest(
        fd_digest,
        sample_owner_face,
        sample_local_slot,
        sample_generation,
        next_ctx.epoch,
    )
    if (
        sample_owner_face >= 0
        and sample_local_slot >= 0
        and offline_sim.face_mailbox_kind(sample_local_slot, sample_owner_face) == 0
    ):
        next_ctx.rebound_shadow_state[sample_owner_face][sample_local_slot] = sample_generation
    visible = offline_sim.visible_digest(next_ctx.state)
    distributed_route_input = next_ctx.distributed_route_digest_value ^ 0x524F5554452D5354
    distributed_route_input = offline_sim.hash64_u64(distributed_route_input, slice_trace_digest)
    distributed_route_input = offline_sim.hash64_u64(distributed_route_input, broker_trace)
    distributed_route_input = offline_sim.hash64_u64(
        distributed_route_input,
        offline_sim.watchdog_trace_digest(move, next_ctx.epoch),
    )
    distributed_route_input = offline_sim.hash64_u64(distributed_route_input, orbit)
    distributed_route_input = offline_sim.hash64_u64(distributed_route_input, fd_digest)
    distributed_tls_mesh_input = next_ctx.distributed_tls_mesh_digest_value ^ 0x544C532D4D455348
    distributed_tls_mesh_input = offline_sim.hash64_u64(distributed_tls_mesh_input, line_trace_digest)
    distributed_tls_mesh_input = offline_sim.hash64_u64(distributed_tls_mesh_input, slice_trace_digest)
    distributed_tls_mesh_input = offline_sim.hash64_u64(distributed_tls_mesh_input, sample_owner_face)
    distributed_tls_mesh_input = offline_sim.hash64_u64(distributed_tls_mesh_input, sample_local_slot)
    distributed_tls_mesh_input = offline_sim.hash64_u64(distributed_tls_mesh_input, visible)
    (
        next_ctx.hidden_value,
        next_ctx.orientation_value,
        next_ctx.anchor_hint_value,
        next_ctx.edge_pair_parity_value,
        next_ctx.center_anchor_parity_value,
        next_ctx.fd_generation_parity_value,
        next_ctx.thread_lifecycle_digest_value,
        next_ctx.distributed_route_digest_value,
        next_ctx.distributed_tls_mesh_digest_value,
    ) = offline_sim.hidden_runtime_step(
        next_ctx.hidden_value,
        next_ctx.orientation_value,
        next_ctx.anchor_hint_value,
        next_ctx.edge_pair_parity_value,
        next_ctx.center_anchor_parity_value,
        next_ctx.fd_generation_parity_value,
        next_ctx.thread_lifecycle_digest_value,
        next_ctx.distributed_route_digest_value,
        next_ctx.distributed_tls_mesh_digest_value,
        move,
        next_ctx.epoch,
        orbit,
        fd_digest,
        visible,
        distributed_route_input,
        distributed_tls_mesh_input,
    )
    hidden = next_ctx.hidden_value
    next_ctx.anchor_digest = offline_sim.courier_digest_step(
        next_ctx.anchor_digest,
        next_ctx.anchor_hint_value,
        next_ctx.epoch,
    )
    next_ctx.capability_chain = offline_sim.capability_step(
        next_ctx.capability_chain,
        move,
        orbit,
        fd_digest,
        next_ctx.anchor_digest,
        next_ctx.epoch,
        visible,
        hidden,
        next_ctx.distributed_route_digest_value,
        next_ctx.distributed_tls_mesh_digest_value,
    )
    proof = offline_sim.step_proof(
        next_ctx.capability_chain,
        path_digest_before_move,
        next_ctx.anchor_digest,
        fd_digest,
        next_ctx.epoch_key,
        move,
        next_ctx.epoch,
        visible,
        hidden,
        next_ctx.distributed_route_digest_value,
        next_ctx.distributed_tls_mesh_digest_value,
    )
    next_ctx.epoch_key = offline_sim.epoch_key_step(
        next_ctx.epoch_key,
        proof,
        next_ctx.capability_chain,
        path_digest_before_move,
        next_ctx.anchor_digest,
        fd_digest,
        next_ctx.epoch,
    )
    next_ctx.path_digest = offline_sim.path_step(
        next_ctx.path_digest,
        move,
        orbit,
        fd_digest,
        next_ctx.anchor_digest,
        next_ctx.epoch,
        visible,
        hidden,
        next_ctx.capability_chain,
        next_ctx.distributed_route_digest_value,
        next_ctx.distributed_tls_mesh_digest_value,
    )
    next_ctx.audit_root = offline_sim.audit_root_step(
        next_ctx.audit_root,
        next_ctx.epoch,
        move,
        orbit,
        fd_digest,
        visible,
        hidden,
        next_ctx.path_digest,
        next_ctx.capability_chain,
        0,
        next_ctx.distributed_route_digest_value,
        next_ctx.distributed_tls_mesh_digest_value,
    )
    next_ctx.last_step_receipt = offline_sim.step_receipt(
        proof,
        next_ctx.path_digest,
        next_ctx.audit_root,
        0,
        next_ctx.epoch_key,
        next_ctx.epoch,
    )
    slot_index = next_ctx.pending_block_count
    direct_move_mac = offline_sim.move_mac_for_slot(
        offline_sim.move_mac_seed_for_block(
            next_ctx.current_block_index,
            next_ctx.block_receipt_seed,
            next_ctx.block_entry_path_digest,
            next_ctx.block_entry_capability_chain,
            next_ctx.block_entry_anchor_digest,
            next_ctx.block_entry_distributed_route_digest,
            next_ctx.block_entry_distributed_tls_mesh_digest,
            next_ctx.peer_proof,
        ),
        slot_index,
        move.move_code,
    )
    broker_value = (
        direct_move_mac
        ^ offline_sim.tls_slot_mask(
            next_ctx.current_block_index,
            slot_index,
            next_ctx.capability_chain,
            next_ctx.distributed_tls_mesh_digest_value,
            next_ctx.peer_proof,
        )
        ^ offline_sim.shm_slot_mask(
            next_ctx.current_block_index,
            slot_index,
            path_digest_before_move,
            fd_digest,
            next_ctx.distributed_route_digest_value,
            next_ctx.peer_proof,
        )
    )
    broker_list = list(next_ctx.pending_broker_move_macs)
    broker_list[slot_index] = broker_value
    next_ctx.pending_broker_move_macs = tuple(broker_list)
    next_ctx.pending_block_count += 1
    next_ctx.move_count += 1
    next_ctx.fd_digest = fd_digest
    return next_ctx


def promote_completed_block(ctx: SearchCtx) -> SearchCtx:
    next_ctx = clone_search_ctx(ctx)
    next_ctx.current_block_index += 1
    next_ctx.block_receipt_seed = next_ctx.last_step_receipt
    next_ctx.block_entry_path_digest = next_ctx.path_digest
    next_ctx.block_entry_capability_chain = next_ctx.capability_chain
    next_ctx.block_entry_anchor_digest = next_ctx.anchor_digest
    next_ctx.block_entry_distributed_route_digest = next_ctx.distributed_route_digest_value
    next_ctx.block_entry_distributed_tls_mesh_digest = next_ctx.distributed_tls_mesh_digest_value
    next_ctx.pending_block_count = 0
    next_ctx.pending_broker_move_macs = (0, 0, 0)
    return next_ctx


def recover_block_moves(
    block_entry_ctx: SearchCtx,
    target: DecodedBlock,
) -> tuple[list[str], SearchCtx]:
    supported = offline_sim.supported_move_tokens()
    branches: list[tuple[list[str], SearchCtx]] = [([], block_entry_ctx)]

    for slot in range(target.move_count):
        next_branches: list[tuple[list[str], SearchCtx]] = []
        for branch_moves, branch_ctx in branches:
            for token in supported:
                candidate_ctx = advance_search_ctx(branch_ctx, token)
                slot_index = len(branch_moves)
                if candidate_ctx.pending_broker_move_macs[slot_index] != target.broker_move_macs[slot_index]:
                    continue
                if slot_index + 1 == target.move_count:
                    broker_auth_value = offline_sim.broker_auth(
                        target.block_index,
                        target.move_count,
                        candidate_ctx.pending_broker_move_macs,
                        candidate_ctx.last_step_receipt,
                        candidate_ctx.peer_proof,
                    )
                    if broker_auth_value != target.broker_auth:
                        continue
                    if candidate_ctx.last_step_receipt != target.expected_step_receipt:
                        continue
                next_branches.append((branch_moves + [token], candidate_ctx))
        if not next_branches:
            raise ValueError(f"failed to recover block {target.block_index} slot {slot}")
        branches = next_branches

    if len(branches) != 1:
        raise ValueError(f"block {target.block_index} recovery remained ambiguous: {len(branches)} branches")
    moves, end_ctx = branches[0]
    return moves, promote_completed_block(end_ctx)


def recover_answer(binary_path: Path) -> str:
    binary_data = binary_path.read_bytes()
    start_state = decode_initial_state(binary_data)
    block_capsule_offset = find_unique(binary_data, BLOCK_CAPSULES_PREFIX, "block-capsules")

    ctx = initial_block_context(start_state)
    search_ctx = make_initial_search_ctx(start_state)
    recovered_moves: list[str] = []

    for block_index in range(BLOCK_CAPSULE_COUNT):
        target = decode_block_capsule(
            binary_data=binary_data,
            block_data_offset=block_capsule_offset,
            block_index=block_index,
            ctx=ctx,
        )
        block_moves, search_ctx = recover_block_moves(search_ctx, target)
        recovered_moves.extend(block_moves)
        print(
            f"[+] block {block_index:02d}: "
            f"{' '.join(block_moves)} "
            f"(receipt=0x{target.expected_step_receipt:016x})"
        )
        if block_index + 1 < BLOCK_CAPSULE_COUNT:
            ctx = BlockKeyContext(
                receipt_seed=search_ctx.block_receipt_seed,
                path_digest=search_ctx.block_entry_path_digest,
                capability_chain=search_ctx.block_entry_capability_chain,
                anchor_digest=search_ctx.block_entry_anchor_digest,
                distributed_route_digest=search_ctx.block_entry_distributed_route_digest,
                distributed_tls_mesh_digest=search_ctx.block_entry_distributed_tls_mesh_digest,
                peer_proof=ctx.peer_proof,
            )

    return " ".join(recovered_moves)


def to_wsl_path(path: Path) -> str:
    drive = path.drive.rstrip(":").lower()
    relative = path.as_posix().split(":", 1)[1]
    return f"/mnt/{drive}{relative}"


def run_binary_with_answer(binary_path: Path, answer: str) -> None:
    if sys.platform.startswith("win"):
        quoted_answer = shlex.quote(answer)
        quoted_binary = shlex.quote(to_wsl_path(binary_path.resolve()))
        result = subprocess.run(
            ["wsl", "bash", "-lc", f"printf '%s\\n' {quoted_answer} | {quoted_binary}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    else:
        result = subprocess.run(
            [str(binary_path.resolve())],
            input=answer + "\n",
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    print("[+] binary output:")
    print(result.stdout.rstrip())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover the re1_11 canonical move sequence block by block from the stripped ELF."
    )
    parser.add_argument("binary", type=Path, help="Path to cubeipc6.stripped")
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the binary with the recovered sequence after decryption.",
    )
    args = parser.parse_args()

    digest = sha256_hex(args.binary)
    print(f"[+] target sha256 = {digest}")
    if digest != OFFICIAL_SHA256:
        print("[!] sha256 does not match the official release; continuing anyway")

    answer = recover_answer(args.binary)
    print("[+] recovered canonical answer:")
    print(answer)

    if args.run:
        run_binary_with_answer(args.binary, answer)


if __name__ == "__main__":
    main()
