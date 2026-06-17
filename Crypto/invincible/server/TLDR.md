---
noteId: "91a236b0658c11f1a4f94f7fb724ff3d"
tags: []

---

# Invincible Archive TL;DR

## What Changed

- Theme: the site is now an `Invincible Archive` page with Mark, Omni-Man, and Conquest content.
- `GET /api/jwt/public-key` was removed. It should return `404`.
- `POST /login` no longer re-signs a new JWT when the browser already holds a valid token for the same user.
- Registration is still the intended signature-sample source.
- JWT signing still uses vulnerable ECDSA nonce generation derived from `FoxHash`.

## Intended Solve Path

1. Register 36 distinct users.
2. Collect the 36 `demo_access_token` cookies.
3. Recompute each sample's leaked 16-bit nonce window locally from `foxhash.py`.
4. Run the one-file Sage exploit in [exp.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/exp.py).
5. Recover the signing private key.
6. Forge an admin JWT and request `GET /api/admin/flag`.

## Current Important Routes

- `GET /`
- `GET /login`
- `POST /login`
- `GET /register`
- `POST /register`
- `GET /dashboard`
- `GET /api/me`
- `GET /admin`
- `GET /api/admin/flag`

There is **no** public-key route anymore.

## Current Flag Behavior

- Source code copy in `server/` reads `FLAG` from environment, and optionally refreshes it from `FLAG_ENV_FILE`.
- Template deployment copy in `2025-解题赛赛题模版/Invincible/env/web_deploy/` also uses `FLAG`, with `pushflag.sh` writing `FLAG=...` into `flag.env`.

## Current Directory Map

- [server/main.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/main.py)
  Main web app.
- [server/vuln_jwt.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/vuln_jwt.py)
  JWT signing / verification.
- [server/vuln_hash.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/vuln_hash.py)
  ECDSA nonce wrapper over `FoxHash`.
- [server/foxhash.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/foxhash.py)
  The self-contained hash implementation used in `server/`.
- [player/](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/player)
  Player attachment source tree, kept behavior-aligned with `server/`.
- [exp.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/exp.py)
  One-file Sage exploit used for validation.
- [2025-解题赛赛题模版/Invincible](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/2025-解题赛赛题模版/Invincible)
  Final challenge-delivery template directory.

## Validation

Run:

```bash
cd /home/f0x/work/SCTF/demo_fastapi_jwt_bundle
conda run -n sage-10.6 python validate.py
```

This validates:

- 36 registrations still yield enough samples
- the one-file Sage exploit still recovers the key
- the forged admin JWT still returns the expected flag

## If A New Session Starts Here

Read these first:

1. [server/TLDR.md](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/TLDR.md)
2. [server/CONTEXT.md](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/CONTEXT.md)
3. [writeup.md](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/writeup.md)
