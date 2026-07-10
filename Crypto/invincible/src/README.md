---
noteId: "01ff78f0658d11f1a4f94f7fb724ff3d"
tags: []

---

# Invincible Archive Server

This is the deployment-side source tree for the `Invincible Archive` web challenge.

## Current Behavior

- FastAPI site with register / login / dashboard / admin flow
- custom JWT cookie auth
- vulnerable BrainpoolP512r1 ECDSA signer
- nonce derived from `FoxHash`
- homepage and dashboard themed around Mark, Omni-Man, and Conquest

## Important Current Security Design

- Registration auto-issues a JWT cookie
- Registration is capped at `40` users per run
- Login does **not** re-sign a JWT when the requester already holds a valid cookie for the same identity
- `/api/jwt/public-key` has been removed
- `/api/admin/flag` still only checks:
  - valid signature
  - non-expired token
  - `role == "admin"`

So the intended solve path remains: recover the signing key and forge admin claims.

## Run

```bash
cd /home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server
conda run -n sage-10.6 python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

## Docker

This directory is self-contained for Docker builds:

```bash
cd /home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server
docker build -t demo-fastapi-jwt .
docker run -itd -p 8000:8000 demo-fastapi-jwt
```

The image already contains:

- a default `CMD`
- default `FLAG`
- default runtime DB path
- default runtime signer-key path

## Flag

Current source-tree logic reads:

- `FLAG`
- optional `FLAG_ENV_FILE`

The template deployment copy uses `flag.env` + `pushflag.sh` to refresh `FLAG` dynamically.

## Validation

```bash
cd /home/f0x/work/SCTF/demo_fastapi_jwt_bundle
conda run -n sage-10.6 python validate.py
```

## Related Files

- [main.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/main.py)
- [vuln_jwt.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/vuln_jwt.py)
- [vuln_hash.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/vuln_hash.py)
- [foxhash.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/foxhash.py)
- [templates/](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/templates)
- [static/](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/static)
