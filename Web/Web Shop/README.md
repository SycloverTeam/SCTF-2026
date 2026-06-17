# Web Shop

XCTF/SCTF Web challenge service.

## Stack

- Backend: Python 3.11 + FastAPI
- Frontend: Vite + React + TypeScript
- Database: SQLite
- Key dependency: `langchain-core==0.3.80`

## Challenge chain

```text
chat metadata context restore
  -> leak SHOP_SUPPORT_SEED
  -> derive staff-code with HMAC
  -> Bot /login privilege escalation
  -> Rule Lab pricing-rule sandbox
  -> generator frame based rule-context escape
  -> read /app/private/flag.txt
```

## Local backend

```powershell
cd backend
pip install -e .
$env:FLAG='SCTF{local_flag}'
$env:SHOP_SUPPORT_SEED='local-support-seed'
$env:FLAG_PATH="$PWD\..\temp\flag.txt"
$env:DATA_DIR="$PWD\..\data"
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Local frontend

```powershell
cd frontend
npm install
npm run dev
```

Visit:

```text
http://127.0.0.1:5173
```

## Docker

```powershell
docker build -t web-shop .
docker run --rm -p 8080:8080 `
  -e FLAG='SCTF{placeholder}' `
  -e SHOP_SUPPORT_SEED='local-support-seed' `
  web-shop
```

Visit:

```text
http://127.0.0.1:8080
```

## Notes

- `FLAG` is written to `FLAG_PATH` on startup and then removed from `os.environ`.
- Default Docker `FLAG_PATH` is `/app/private/flag.txt`.
- `SHOP_SUPPORT_SEED` remains in the runtime environment for staff-code derivation.
- The container runs as non-root user `webshop`.
