#!/bin/bash
# GateCrash — Server Startup (Static Flag / Per-Player Instances)
#
# Pre-compiles challenge contracts, then starts the TCP server.
# Anvil instances are spawned per-player by instance_manager.py.

set -e

echo "=========================================="
echo " GateCrash — Server Startup"
echo " Static Flag / Per-Player Instances"
echo "=========================================="

# Pre-compile challenge contracts (speeds up per-instance deployment)
echo "[INFO] Pre-compiling challenge contracts..."
cd /app/challenges/gatecrash
forge build
echo "[INFO] Build complete."

# Start TCP Server (background, with keep-alive)
echo "[INFO] Starting TCP server on port ${PORT:-1337}..."
echo "[INFO] Anvil port range: ${ANVIL_PORT_MIN:-40000}-${ANVIL_PORT_MAX:-40100}"
cd /app/server
python3 app.py &
PID=$!
echo "[INFO] Server PID: $PID"

# Keep the container alive even if python crashes
# Allows docker exec for troubleshooting without container exit
tail -f /dev/null &
TAIL_PID=$!
set +e
wait $PID
EXIT_CODE=$?
set -e
echo "[WARN] Server process exited (exit code: $EXIT_CODE). Container stays alive for debugging."
echo "[WARN] Use 'docker exec' to investigate or restart."
wait $TAIL_PID
