FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, anvil, cast)
ARG FOUNDRY_VERSION=v1.7.1
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup -i "${FOUNDRY_VERSION}"

WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r /app/server/requirements.txt

# Precompile the shipped challenge during image build so runtime instance
# launches do not depend on downloading solc or compiling from a cold cache.
RUN forge build --root /app/challenges/06_last_honest_witness

ENV FOUNDRY_BIN=/root/.foundry/bin
ENV PYTHONPATH=/app/server

# Port 1337 for nc connections; Anvil ports 20000-20200
EXPOSE 1337
EXPOSE 20000-20200

RUN chmod +x /app/server/start.sh

CMD ["/app/server/start.sh"]
