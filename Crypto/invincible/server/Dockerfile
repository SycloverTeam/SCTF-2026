FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    DEMO_ADMIN_USERNAME=admin \
    FLAG="SCTF{t1hinK_mark1_You’ll outlast every fragile, insignificant being on this planet!}" \
    FLAG_ENV_FILE=/app/server/data/flag.env \
    DEMO_DB_PATH=/app/server/data/app.db \
    DEMO_JWT_KEY_FILE=/app/server/data/jwt_signer_key.pem

WORKDIR /app/server

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app/server

RUN mkdir -p /app/server/data

VOLUME ["/app/server/data"]

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
