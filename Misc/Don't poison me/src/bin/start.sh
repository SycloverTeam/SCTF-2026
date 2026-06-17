#!/bin/sh
set -eu

cd /app
python3 -u /app/server.py --host 0.0.0.0 --port 80 &

tail -f /dev/null
