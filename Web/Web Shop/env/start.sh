#!/bin/sh
set -eu

uvicorn backend.app.main:app \
  --host 0.0.0.0 \
  --port 8080 \
  --workers "${WEB_CONCURRENCY:-2}" \
  --proxy-headers \
  --forwarded-allow-ips '*' &

tail -f /dev/null
