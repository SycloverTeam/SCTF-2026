#!/bin/bash
set -eu

# ============================================================================
# Chronostasis CTF — 容器启动脚本
# ============================================================================

if [ -f /flag ] && [ -s /flag ]; then
    export FLAG_SECRET
    FLAG_SECRET=$(cat /flag)
    echo "[start] using /flag as FLAG_SECRET"
fi

export FLAG_SECRET="${FLAG_SECRET:-SCTF{w0r!d.3xecut3(3th3r_!p_str1k3);}}"

# 其他可被 docker run -e 覆盖的默认值
export PUBLIC_HOST="${PUBLIC_HOST:-127.0.0.1}"
export PORT="${PORT:-7000}"
export INSTANCE_TIMEOUT="${INSTANCE_TIMEOUT:-1800}"
export MAX_INSTANCES_PER_TEAM="${MAX_INSTANCES_PER_TEAM:-0}"  # 0 = unlimited, set via docker run -e
export ANVIL_PORT_MIN="${ANVIL_PORT_MIN:-7001}"
export ANVIL_PORT_MAX="${ANVIL_PORT_MAX:-7050}"
export FOUNDRY_BIN="${FOUNDRY_BIN:-/root/.foundry/bin}"
export PYTHONPATH="${PYTHONPATH:-/app/server}"

echo "[start] Chronostasis CTF starting on port ${PORT}"

# 启动 CTF 服务进程
cd /app
python /app/server/app.py &

# 保持容器存活
tail -f /dev/null
