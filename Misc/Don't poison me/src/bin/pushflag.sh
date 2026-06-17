#!/bin/sh
set -eu

if [ $# -ge 1 ]; then
    printf '%s\n' "$1" > /flag
fi

chown root:root /flag
chmod 400 /flag
