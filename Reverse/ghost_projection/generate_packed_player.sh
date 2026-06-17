#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

python3 "$ROOT/scripts/pack_ghost_abyss_author.py" \
  --source "$ROOT/source/ghost_abyss_hardened_step40_route_projection.c" \
  --header "$ROOT/source/ghost_step30_generated.h" \
  --outdir "$ROOT/build_packed" \
  --output-name ghost_abyss_hardened \
  --package-name ghost_step40_route_projection_packed_player \
  --zip \
  --force

echo
printf '[+] packed player dir: %s\n' "$ROOT/build_packed/ghost_step40_route_projection_packed_player"
