---
noteId: "d28b7e20658c11f1a4f94f7fb724ff3d"
tags: []

---

# Invincible Archive Context

## Purpose

This project is a web CTF challenge themed around `Invincible`.

The exploit target is still a vulnerable custom JWT signer:

- curve: `brainpoolP512r1`
- hash: `SHA-512(signing_input)`
- nonce source: `FoxHash.hash(uid || username || signing_input)`, then wrapped into a valid ECDSA scalar

The intended break is:

1. collect enough signed JWTs through registration
2. reconstruct one 16-bit leaked nonce window per message from the public message plus local `foxhash.py`
3. solve an interval EHNP instance
4. recover the signer private key
5. forge an admin JWT

## Current User-Facing Design

The site is no longer a generic auth demo page.

It now presents itself as an `Invincible Archive` and shows:

- Mark Grayson / Invincible content
- Omni-Man content
- Conquest content

Current theme files:

- [server/templates/index.html](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/templates/index.html)
- [server/templates/dashboard.html](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/templates/dashboard.html)
- [server/templates/admin.html](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/templates/admin.html)
- [server/static/style.css](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/static/style.css)
- [server/static/characters/](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/static/characters)

Admin uses [thinkmarkthumbnail.PNG](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/thinkmarkthumbnail.PNG) as background through the copied static asset.

## Current Runtime Behavior

### Registration

- `POST /register` still creates a user and auto-issues a JWT cookie.
- This is the intended sample source.
- The run-wide registration cap is `40`.

### Login

- `POST /login` authenticates by `username + password`.
- If the browser already has a valid JWT for the same identity, login **does not** mint a fresh token.
- This was changed intentionally so players cannot register once and then farm infinite signatures by repeated login.

### Session

- Protected routes trust any valid signed JWT claims directly.
- There is still no database rebind after signature verification.

### Public Key

- `GET /api/jwt/public-key` was removed on purpose.
- If it exists again, that is a regression.

## Current Flag Handling

### Source tree in `server/`

`server/main.py` currently uses:

- `FLAG` as the primary flag value
- optional `FLAG_ENV_FILE` refresh logic

`current_flag()` will:

1. read `FLAG_ENV_FILE` if configured
2. if it contains a `FLAG=...` line, update `os.environ["FLAG"]`
3. otherwise fall back to the in-code default

### Template deployment tree

The delivery template under:

- [2025-解题赛赛题模版/Invincible](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/2025-解题赛赛题模版/Invincible)

uses the same behavior model.

In the template deployment copy:

- `pushflag.sh` writes `FLAG=...` into `/app/server/data/flag.env`
- `start.sh` seeds that file from the bundled `flag.env` if missing
- the web app reads `FLAG_ENV_FILE=/app/server/data/flag.env`

This matches the platform requirement better than exposing flag through the environment alone.

## Current Self-Contained Layout

One important cleanup already done:

- `server/` is self-contained
- `player/` is self-contained

Both now have their own:

- `foxhash.py`
- `vuln_hash.py`
- `vuln_jwt.py`
- `main.py`

so `server/` can be built locally with:

```bash
cd /home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server
docker build -t demo-fastapi-jwt .
```

without depending on the repository root as Docker build context.

## Exploit State

The current exploit is:

- [exp.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/exp.py)

Key properties:

- one-file Sage exploit
- depends only on local `foxhash.py`
- does **not** depend on a public-key API
- validates recovered candidates by trying forged admin JWTs against `/api/admin/flag`
- still supports `--local-key` for local validation

## Validation State

[validate.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/validate.py) delegates to:

- [server/validate.py](/home/f0x/work/SCTF/demo_fastapi_jwt_bundle/server/validate.py)

and currently verifies:

- the server starts
- 36 registrations are sufficient
- the one-file Sage exploit recovers the key
- forged admin JWT retrieves the expected flag

## Current Behavior That Is Still Intentionally Vulnerable

- Registration auto-issues JWTs.
- Claims are trusted directly after signature verification.
- A valid forged JWT for a nonexistent user still works.
- The crypto weakness is still the intended path.

## Things To Watch In Future Sessions

1. Do not accidentally restore `/api/jwt/public-key`.
2. Do not accidentally make `POST /login` mint a new JWT while the same valid cookie is already present.
3. Keep `player/` and `server/` behavior-aligned.
4. Keep template copies in `Invincible/` synchronized after code changes.
5. Re-export:
   - template `attachments/player.zip`
   - template `sourcecode/sourcecode.zip`
   - template `env/demo-fastapi-jwt.tar`
   after meaningful updates.

## Fast Checklist Before Shipping

- `curl /api/jwt/public-key` returns `404`
- homepage shows the Invincible archive theme
- repeated login with same valid cookie reuses the same JWT
- 36-register validation still passes
- template image tar was rebuilt from the latest template deployment tree
