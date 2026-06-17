#!/bin/bash
set -euo pipefail

flag_file="/flag"

printf '%s\n' "$1" > "$flag_file"
chown root:root "$flag_file"
chmod 400 "$flag_file"
