FROM node:22-alpine AS frontend-build
WORKDIR /src/frontend
COPY frontend/package.json frontend/tsconfig.json frontend/vite.config.ts frontend/index.html ./
COPY frontend/src ./src
COPY frontend/public ./public
RUN npm install && npm run build

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    STATIC_DIR=/app/frontend/dist \
    BOT_IMGS_DIR=/app/bot_imgs \
    FLAG_PATH=/app/private/flag.txt \
    WEB_CONCURRENCY=2 \
    SQLITE_TIMEOUT=10 \
    SQLITE_BUSY_TIMEOUT_MS=10000 \
    SQLITE_MAX_CONCURRENT_DB=48 \
    DB_ACQUIRE_TIMEOUT=5 \
    IMAGE_MAX_CONCURRENT=2 \
    IMAGE_ACQUIRE_TIMEOUT=2 \
    LOUVRE_MAX_PIXELS=4000000 \
    SESSION_TTL_HOURS=12 \
    CHAT_METADATA_MAX_BYTES=16384 \
    CHAT_METADATA_MAX_DEPTH=12 \
    CHAT_METADATA_MAX_NODES=256 \
    CHAT_METADATA_MAX_STRING=4096 \
    CHAT_MESSAGES_PER_USER=200 \
    RULE_MAX_CONCURRENT=4 \
    RULE_ACQUIRE_TIMEOUT=1
WORKDIR /app
COPY backend /app/backend
RUN pip install --no-cache-dir /app/backend
COPY bot_imgs /app/bot_imgs
COPY --from=frontend-build /src/frontend/dist /app/frontend/dist
RUN mkdir -p /app/data /app/private && useradd -r -u 10001 webshop && chown -R webshop:webshop /app/data /app/private
USER webshop
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn backend.app.main:app --host 0.0.0.0 --port 8080 --workers ${WEB_CONCURRENCY} --proxy-headers --forwarded-allow-ips '*'"]
