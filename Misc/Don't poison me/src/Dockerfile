FROM --platform=linux/amd64 python:3.12.9-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        less \
        libc6-dev \
        nodejs \
        npm \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir mcp==1.27.0

RUN npm install -g @openai/codex@0.139.0 && \
    codex --version

RUN useradd -m -u 1000 -s /bin/sh ctf

COPY bin/app /app
COPY bin/start.sh /start.sh
COPY bin/pushflag.sh /pushflag.sh
COPY bin/readflag.c /tmp/readflag.c
COPY bin/flag /flag

RUN gcc /tmp/readflag.c -o /readflag && \
    rm -f /tmp/readflag.c && \
    chown -R root:root /app /start.sh /pushflag.sh /readflag /flag && \
    chmod -R 755 /app && \
    chmod 755 /start.sh /pushflag.sh && \
    chmod 4755 /readflag && \
    chmod 400 /flag

WORKDIR /app

EXPOSE 80

CMD ["/bin/sh", "/start.sh"]
