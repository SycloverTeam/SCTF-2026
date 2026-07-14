# GateCrash — Static Flag / Per-Player Instance Container
#
# Each player gets an isolated Anvil instance + Setup deployment.
# All players share the same static flag from /flag.
#
# Build:
#   docker build -t gatecrash .
#
# Run (port range covers per-player Anvil instances):
#   docker run -itd \
#     -p 1337:1337 \
#     -p 40000-40100:40000-40100 \
#     -e PUBLIC_HOST=<vps_ip> \
#     --name gatecrash \
#     gatecrash

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y \
    curl git wget jq build-essential python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Foundry
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

ENV PATH="/root/.foundry/bin:${PATH}"
ENV FOUNDRY_BIN="/root/.foundry/bin"

WORKDIR /app

# Challenge contracts
COPY challenges/ /app/challenges/

# Server code
COPY server/app.py               /app/server/app.py
COPY server/instance_manager.py  /app/server/instance_manager.py
COPY server/requirements.txt     /app/server/requirements.txt
COPY server/start.sh             /app/server/start.sh

# Flag injection script
COPY script/pushflag.sh /app/script/pushflag.sh

RUN chmod +x /app/server/start.sh /app/script/pushflag.sh

# Pre-compile contracts
WORKDIR /app/challenges/gatecrash
RUN forge build

WORKDIR /app

# 1337 = TCP server, 40000-40100 = per-player Anvil RPC proxies
EXPOSE 1337 40000-40100

ENV PORT=1337
ENV ANVIL_PORT_MIN=40000
ENV ANVIL_PORT_MAX=40100
ENV PUBLIC_HOST=127.0.0.1
ENV INSTANCE_TIMEOUT=1800

CMD ["/bin/bash", "/app/server/start.sh"]
