#!/usr/bin/env bash
set -euo pipefail
gcc -nostdlib -ffreestanding -fno-builtin -no-pie -fno-stack-protector -z execstack -Og \
  -fno-strict-aliasing -fno-optimize-sibling-calls \
  -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -Wl,--build-id=none \
  -o ghost_step40_route_projection_unstripped \
  ghost_abyss_hardened_step40_route_projection.c
cp ghost_step40_route_projection_unstripped ghost_abyss_hardened
strip -s ghost_abyss_hardened
objcopy --remove-section=.comment \
        --remove-section=.note.gnu.build-id \
        --remove-section=.eh_frame \
        --remove-section=.eh_frame_hdr \
        ghost_abyss_hardened || true
python3 - <<'PY'
from pathlib import Path
p = Path('ghost_abyss_hardened')
b = bytearray(p.read_bytes())
b[0x28:0x30] = (0).to_bytes(8, 'little')
b[0x3c:0x3e] = (0).to_bytes(2, 'little')
b[0x3e:0x40] = (0).to_bytes(2, 'little')
p.write_bytes(b)
PY
chmod +x ghost_abyss_hardened
