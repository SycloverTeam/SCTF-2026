FROM python:3.12-slim

# Install system dependencies (curl for downloads, git for forge)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Foundry binaries (direct download) ──────────────────────────────────────────
RUN mkdir -p /root/.foundry/bin && \
    curl -fsSL "https://github.com/foundry-rs/foundry/releases/latest/download/forge_linux_amd64" \
        -o /root/.foundry/bin/forge && \
    curl -fsSL "https://github.com/foundry-rs/foundry/releases/latest/download/cast_linux_amd64" \
        -o /root/.foundry/bin/cast && \
    curl -fsSL "https://github.com/foundry-rs/foundry/releases/latest/download/anvil_linux_amd64" \
        -o /root/.foundry/bin/anvil && \
    chmod +x /root/.foundry/bin/*

ENV PATH="/root/.foundry/bin:${PATH}"
ENV FOUNDRY_BIN=/root/.foundry/bin

# ── Solidity compiler (direct download) ─────────────────────────────────────────
RUN mkdir -p /root/.svm/0.8.24 && \
    curl -fsSL "https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux" \
        -o /root/.svm/0.8.24/solc-0.8.24 && \
    chmod +x /root/.svm/0.8.24/solc-0.8.24

WORKDIR /app

# Copy project files (server code + challenge sources)
COPY . /app

# Set up challenge directory structure expected by app.py / instance_manager.py
# (source lives in src/, runtime expects challenges/<id>/)
RUN mkdir -p /app/challenges/chronostasis && \
    cp -r /app/src/* /app/challenges/chronostasis/

# Pre-compile all challenge contracts during Docker build
# This way forge create at runtime uses cached artifacts — much faster instance startup
RUN shopt -s nullglob && \
    for challenge_dir in /app/challenges/*/; do \
        if [ -f "${challenge_dir}foundry.toml" ]; then \
            echo "==> Pre-compiling $(basename "$challenge_dir") contracts..." && \
            /root/.foundry/bin/forge build --root "$challenge_dir" && \
            echo "==> Done: $(basename "$challenge_dir")"; \
        fi; \
    done

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/server/requirements.txt

ENV PYTHONPATH=/app/server

# nc server port + Anvil RPC port range
EXPOSE 7000
EXPOSE 7001-7050

# Copy start script (relative to build context = project root)
COPY server/start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
