#!/bin/sh
set -eu

/usr/local/bin/vault &
exec /usr/local/bin/gateway --config /etc/gateway.toml
