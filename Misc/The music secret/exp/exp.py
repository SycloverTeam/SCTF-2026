#!/usr/bin/env python3
import binascii
import base64
import hashlib
import json
import re
import statistics
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path


SCALE = 10_000_000
SYNC_LEN = 8


def iter_pcapng_packets(path):
    data = Path(path).read_bytes()
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("expected a little-endian pcapng file")
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            raise ValueError("invalid pcapng block")
        if block_type == 6:
            _iface, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack_from("<IIIII", data, offset + 8)
            packet = data[offset + 28 : offset + 28 + cap_len]
            timestamp = ((ts_hi << 32) | ts_lo) / 1_000_000
            yield timestamp, packet
        offset += block_len


def iter_tcp_segments(path):
    for timestamp, packet in iter_pcapng_packets(path):
        if len(packet) < 54 or packet[12:14] != b"\x08\x00" or packet[23] != 6:
            continue
        ip_start = 14
        ihl = (packet[ip_start] & 0x0f) * 4
        tcp_start = ip_start + ihl
        if len(packet) < tcp_start + 20:
            continue
        src_port, dst_port, seq = struct.unpack_from(">HHI", packet, tcp_start)
        tcp_len = ((packet[tcp_start + 12] >> 4) & 0x0f) * 4
        payload = packet[tcp_start + tcp_len :]
        if payload:
            yield timestamp, src_port, dst_port, seq, payload


def parse_headers(blob):
    head, body = blob.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            headers[name.decode().lower()] = value.strip().decode()
    return lines[0].decode(), headers, body


def extract_http_objects(path):
    flows = defaultdict(lambda: {"request": [], "response": [], "time": None})
    for timestamp, src_port, dst_port, seq, payload in iter_tcp_segments(path):
        if dst_port == 80:
            flow = flows[src_port]
            flow["request"].append((seq, payload))
            flow["time"] = timestamp if flow["time"] is None else min(flow["time"], timestamp)
        elif src_port == 80:
            flows[dst_port]["response"].append((seq, payload))

    objects = []
    for client_port, flow in flows.items():
        request_blob = b"".join(part for _seq, part in sorted(flow["request"]))
        response_blob = b"".join(part for _seq, part in sorted(flow["response"]))
        if not request_blob.startswith(b"GET ") or not response_blob.startswith(b"HTTP/"):
            continue
        if b"\r\n\r\n" not in request_blob or b"\r\n\r\n" not in response_blob:
            continue
        request_line, request_headers, _ = parse_headers(request_blob)
        status_line, response_headers, body = parse_headers(response_blob)
        path_value = request_line.split(" ", 2)[1]
        expected = int(response_headers.get("content-length", len(body)))
        objects.append(
            {
                "time": flow["time"],
                "port": client_port,
                "path": path_value,
                "status": status_line,
                "request_headers": request_headers,
                "response_headers": response_headers,
                "body": body[:expected],
                "complete": len(body) >= expected,
            }
        )
    return sorted(objects, key=lambda item: item["time"])


def parse_content_range(value):
    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", value or "")
    if not match:
        raise ValueError(f"invalid Content-Range: {value!r}")
    return tuple(map(int, match.groups()))


def rebuild_streams(objects):
    playlist = None
    playlist_id = None
    user_agent = None
    ranges = {"studio": [], "edge": []}
    ordered_edge_starts = []
    seen_edge_starts = set()

    for obj in objects:
        match = re.fullmatch(r"/api/v1/playback/session\?track=(\d+)", obj["path"])
        if match:
            if not obj["complete"]:
                continue
            candidate = json.loads(obj["body"])
            if candidate.get("title") == "Stream of Sound":
                playlist = candidate
                playlist_id = int(match.group(1))
                user_agent = obj["request_headers"].get("user-agent")
            continue

        match = re.fullmatch(r"/edge/v1/assets/\d+/(studio|cache)", obj["path"])
        if not match:
            continue
        track = "studio" if match.group(1) == "studio" else "edge"
        request_range = re.fullmatch(r"bytes=(\d+)-(\d+)", obj["request_headers"].get("range", ""))
        if not request_range:
            continue
        request_start = int(request_range.group(1))
        if track == "edge" and request_start not in seen_edge_starts:
            ordered_edge_starts.append(request_start)
            seen_edge_starts.add(request_start)
        if not obj["complete"]:
            continue
        start, end, total = parse_content_range(obj["response_headers"].get("content-range"))
        if end - start + 1 != len(obj["body"]):
            raise ValueError("range body length mismatch")
        ranges[track].append((start, end, total, obj["body"]))

    if playlist is None or playlist_id is None or user_agent is None:
        raise ValueError("target playlist not found")

    rebuilt = {}
    for track in ("studio", "edge"):
        if not ranges[track]:
            raise ValueError(f"no ranges for {track}")
        total = ranges[track][0][2]
        output = bytearray(total)
        covered = bytearray(total)
        for start, end, item_total, body in ranges[track]:
            if item_total != total:
                raise ValueError(f"inconsistent total size for {track}")
            for i, value in enumerate(body, start):
                if covered[i] and output[i] != value:
                    raise ValueError(f"conflicting overlap in {track} at {i}")
                output[i] = value
                covered[i] = 1
        if not all(covered):
            raise ValueError(f"incomplete HTTP Range coverage for {track}")
        rebuilt[track] = bytes(output)

    material = f"{user_agent}|{playlist_id}|" + ",".join(map(str, ordered_edge_starts))
    key = hashlib.sha256(material.encode()).digest()
    return playlist, rebuilt["studio"], rebuilt["edge"], key


def parse_float_wav(blob):
    if blob[:4] != b"RIFF" or blob[8:12] != b"WAVE":
        raise ValueError("not a WAV file")
    position = 12
    sample_rate = None
    audio_data = None
    while position + 8 <= len(blob):
        name = blob[position : position + 4]
        size = struct.unpack_from("<I", blob, position + 4)[0]
        chunk = blob[position + 8 : position + 8 + size]
        position += 8 + size + (size % 2)
        if name == b"fmt ":
            audio_format, channels, sample_rate, _byte_rate, _align, bits = struct.unpack_from("<HHIIHH", chunk)
            if (audio_format, channels, bits) != (3, 1, 32):
                raise ValueError("expected mono IEEE float32 WAV")
        elif name == b"data":
            audio_data = chunk
    if sample_rate is None or audio_data is None:
        raise ValueError("incomplete WAV")
    return [value[0] for value in struct.iter_unpack("<f", audio_data)], sample_rate


def recover_beat_period(original, remix):
    events = [
        index
        for index, (a, b) in enumerate(zip(original, remix))
        if abs((b - a) * SCALE) > 6
    ]
    if len(events) < 64:
        raise ValueError("not enough structured difference events")

    # Each encoded subdivision contains one true point and one decoy point.
    two_event_gaps = [events[i + 2] - events[i] for i in range(len(events) - 2)]
    median = statistics.median(two_event_gaps)
    near = [gap for gap in two_event_gaps if abs(gap - median) <= 32]
    if len(near) < len(two_event_gaps) * 0.8:
        raise ValueError("difference events do not expose a stable period")
    return round(statistics.median(near))


def infer_offset_window(delta, beat_period):
    beat_count = len(delta) // beat_period
    scores = []
    for start in range(4, 61):
        score = 0
        for beat in range(beat_count):
            base = beat * beat_period
            for rel in range(start, start + 5):
                value = abs(delta[base + rel] * SCALE)
                if 6 <= value <= 45:
                    score += 1
        scores.append((score, start))
    score, start = max(scores)
    if score < 32:
        raise ValueError("no stable beat-relative difference window")
    return range(start, start + 5)


def recover_symbol_stream(original, remix, beat_period):
    delta = [b - a for a, b in zip(original, remix)]
    window = infer_offset_window(delta, beat_period)
    raw_values = []
    for beat in range(len(delta) // beat_period):
        base = beat * beat_period
        candidates = []
        for rel in window:
            value = delta[base + rel] * SCALE
            if 6 <= value <= 45:
                candidates.append(value)
        if candidates:
            raw_values.append(max(candidates, key=abs))

    histogram = Counter(round(value) for value in raw_values)
    # The four carrier clusters are separated by ten units; choose the best such progression.
    candidates = []
    for first in range(6, 16):
        centers = tuple(first + 10 * i for i in range(4))
        support = sum(histogram[center] for center in centers)
        candidates.append((support, centers))
    _support, centers = max(candidates)

    stream = []
    for value in raw_values:
        distances = [abs(value - center) for center in centers]
        symbol = min(range(4), key=lambda i: distances[i])
        if distances[symbol] > 1.5:
            raise ValueError(f"unclassified symbol level: {value}")
        stream.append(symbol)
    return stream, centers, window


def quads_to_bytes(quads):
    if len(quads) % 4:
        raise ValueError("unaligned quaternary data")
    output = bytearray()
    for i in range(0, len(quads), 4):
        output.append((quads[i] << 6) | (quads[i + 1] << 4) | (quads[i + 2] << 2) | quads[i + 3])
    return bytes(output)


def hamming74_decode(quads, expected_len):
    bits = []
    for value in quads:
        bits.extend((value >> 1, value & 1))
    nibbles = []
    corrected = 0
    for offset in range(0, len(bits), 7):
        codeword = bits[offset : offset + 7]
        if len(codeword) != 7:
            raise ValueError("truncated Hamming codeword")
        s1 = codeword[0] ^ codeword[2] ^ codeword[4] ^ codeword[6]
        s2 = codeword[1] ^ codeword[2] ^ codeword[5] ^ codeword[6]
        s4 = codeword[3] ^ codeword[4] ^ codeword[5] ^ codeword[6]
        syndrome = s1 | (s2 << 1) | (s4 << 2)
        if syndrome:
            codeword[syndrome - 1] ^= 1
            corrected += 1
        nibble = (codeword[2] << 3) | (codeword[4] << 2) | (codeword[5] << 1) | codeword[6]
        nibbles.append(nibble)
    output = bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))
    return output[:expected_len], corrected


def recover_frames(stream):
    windows = Counter(tuple(stream[i : i + SYNC_LEN]) for i in range(len(stream) - SYNC_LEN + 1))
    sync, count = windows.most_common(1)[0]
    if count < 3:
        raise ValueError("repeated sync word not found")

    blocks = {}
    corrections = 0
    for position in range(len(stream) - SYNC_LEN + 1):
        if tuple(stream[position : position + SYNC_LEN]) != sync:
            continue
        cursor = position + SYNC_LEN
        if cursor + 8 > len(stream):
            continue
        block_index, block_len = quads_to_bytes(stream[cursor : cursor + 8])
        cursor += 8
        if not 1 <= block_len <= 12:
            continue
        encoded_len = block_len * 7
        if cursor + encoded_len + 8 > len(stream):
            continue
        block, fixed = hamming74_decode(stream[cursor : cursor + encoded_len], block_len)
        cursor += encoded_len
        saved_crc = int.from_bytes(quads_to_bytes(stream[cursor : cursor + 8]), "big")
        actual_crc = binascii.crc_hqx(bytes([block_index, block_len]) + block, 0xffff)
        if actual_crc != saved_crc:
            continue
        blocks[block_index] = block
        corrections += fixed

    if not blocks or sorted(blocks) != list(range(max(blocks) + 1)):
        raise ValueError("incomplete frame sequence")
    return b"".join(blocks[i] for i in range(len(blocks))), sync, corrections


def decode_container(ciphertext, key):
    plain = bytes(value ^ key[i % len(key)] for i, value in enumerate(ciphertext))
    try:
        return base64.b64decode(plain, validate=True)
    except binascii.Error as error:
        raise ValueError("bad decrypted base64") from error


def solve(path):
    objects = extract_http_objects(path)
    _playlist, original_blob, remix_blob, key = rebuild_streams(objects)
    original, sample_rate = parse_float_wav(original_blob)
    remix, remix_rate = parse_float_wav(remix_blob)
    if sample_rate != remix_rate or len(original) != len(remix):
        raise ValueError("WAV streams are not aligned")

    beat_period = recover_beat_period(original, remix)
    symbols, centers, window = recover_symbol_stream(original, remix, beat_period)
    ciphertext, sync, corrections = recover_frames(symbols)
    flag = decode_container(ciphertext, key)

    print(f"[+] sample_rate={sample_rate}, beat_period={beat_period}")
    print(f"[+] offset_window={window.start}-{window.stop - 1}, symbol_centers={centers}")
    print(f"[+] sync={sync}, Hamming corrections={corrections}")
    return flag


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} dist/stream.pcapng", file=sys.stderr)
        raise SystemExit(2)
    print(solve(sys.argv[1]).decode())


if __name__ == "__main__":
    main()
