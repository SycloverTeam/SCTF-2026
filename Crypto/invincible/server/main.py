#!/usr/bin/env python3
import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from fastapi import Cookie, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from vuln_jwt import JWT_ALG, VulnerableJWTSigner


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("DEMO_DB_PATH", str(DATA_DIR / "app.db")))
JWT_KEY_PATH = Path(os.environ.get("DEMO_JWT_KEY_FILE", str(DATA_DIR / "jwt_signer_key.pem")))
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DEFAULT_FLAG = "SCTF{t1hinK_mark1_You’ll outlast every fragile, insignificant being on this planet!}"
FLAG_ENV_FILE = Path(os.environ.get("FLAG_ENV_FILE", ""))
TOKEN_COOKIE = "demo_access_token"
TOKEN_TTL = 60 * 60
MAX_REGISTERED_USERS = 40
PBKDF2_ROUNDS = 200_000
ADMIN_PASSWORD_BYTES = 32
DEFAULT_ADMIN_USERNAME = "admin"
JWT_SIGNER: VulnerableJWTSigner | None = None
ARTICLES = [
    {
        "slug": "earth-safeguard",
        "title": "马克·格雷森观察日志",
        "subtitle": "无敌少侠在地球与维特鲁姆身份之间的成长轨迹。",
        "tag": "GDA",
        "image": "/static/characters/mark.png",
        "body": (
            "马克的力量继承自全能侠，但他的判断、同情和迟疑都更接近一个真正成长中的地球少年。"
            "这使他既可能成为维特鲁姆最危险的变量，也可能成为地球最可靠的盾牌。"
        ),
    },
    {
        "slug": "viltrum-report",
        "title": "全能侠入侵评估",
        "subtitle": "诺兰对地球的情感与维特鲁姆使命之间的撕裂。",
        "tag": "Viltrum",
        "image": "/static/characters/omni-man.png",
        "body": (
            "诺兰从一开始就不是普通意义上的超级英雄。他的爱、谎言和屠戮同时存在，"
            "让所有关于‘英雄父亲’的叙事在一瞬间崩塌。真正危险的不是他的拳头，而是他对秩序的信仰。"
        ),
    },
    {
        "slug": "conquest-encounter",
        "title": "征服者接触档案",
        "subtitle": "维特鲁姆帝国执行者中最接近纯粹灾难的一位。",
        "tag": "Conquest",
        "image": "/static/characters/conquest.jpg",
        "body": (
            "征服者不是为了征服而征服，他享受的是压碎抵抗的过程。"
            "在与马克的交锋里，他代表的不是某个政治命令，而是维特鲁姆世界观里最赤裸的暴力本身。"
        ),
    },
]


app = FastAPI(title="Demo FastAPI Auth")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def current_flag() -> str:
    try:
        if str(FLAG_ENV_FILE):
            if FLAG_ENV_FILE.exists():
                for line in FLAG_ENV_FILE.read_text(encoding="utf-8").splitlines():
                    if line.startswith("FLAG="):
                        os.environ["FLAG"] = line.split("=", 1)[1]
                        break
    except Exception:
        pass
    return os.environ.get("FLAG", DEFAULT_FLAG)


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user','admin')),
                created_at INTEGER NOT NULL,
                current_token TEXT,
                current_token_exp INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "current_token" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN current_token TEXT")
        if "current_token_exp" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN current_token_exp INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def configured_admin_username() -> str:
    return os.environ.get("DEMO_ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME).strip() or DEFAULT_ADMIN_USERNAME


def generate_admin_password() -> str:
    return secrets.token_hex(ADMIN_PASSWORD_BYTES)


def sync_admin_account() -> None:
    admin_username = configured_admin_username()
    admin_password = generate_admin_password()
    admin_password_hash = hash_password(admin_password)
    conn = db()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ? AND role = 'admin' ORDER BY id ASC LIMIT 1",
            (admin_username,),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users(username, password_hash, role, created_at, current_token, current_token_exp) VALUES (?, ?, 'admin', ?, NULL, 0)",
                (admin_username, admin_password_hash, int(time.time())),
            )
        else:
            conn.execute(
                "UPDATE users SET password_hash = ?, current_token = NULL, current_token_exp = 0 WHERE id = ?",
                (admin_password_hash, int(row["id"])),
            )
        conn.commit()
    finally:
        conn.close()
    print(f"[CTF] admin username: {admin_username}", flush=True)
    print(f"[CTF] admin password for this run: {admin_password}", flush=True)


def cleanup_ctf_users() -> None:
    admin_username = configured_admin_username()
    conn = db()
    try:
        conn.execute(
            "DELETE FROM users WHERE username != ? OR role != 'admin'",
            (admin_username,),
        )
        admin_row = conn.execute(
            "SELECT id FROM users WHERE username = ? AND role = 'admin' ORDER BY id ASC LIMIT 1",
            (admin_username,),
        ).fetchone()
        if admin_row is not None:
            conn.execute(
                "UPDATE sqlite_sequence SET seq = ? WHERE name = 'users'",
                (int(admin_row["id"]),),
            )
        conn.commit()
    finally:
        conn.close()


def regenerate_jwt_signer() -> VulnerableJWTSigner:
    global JWT_SIGNER

    JWT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if JWT_KEY_PATH.exists():
        JWT_KEY_PATH.unlink()
    JWT_SIGNER = VulnerableJWTSigner(JWT_KEY_PATH)
    return JWT_SIGNER


def jwt_signer() -> VulnerableJWTSigner:
    if JWT_SIGNER is None:
        raise RuntimeError("JWT signer is not initialized")
    return JWT_SIGNER


def authenticate_user(username: str, password: str) -> sqlite3.Row | None:
    conn = db()
    try:
        row = conn.execute(
            "SELECT id, username, password_hash, role, created_at, current_token, current_token_exp FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()
    finally:
        conn.close()

    if row is None or not verify_password(password, row["password_hash"]):
        return None
    return row


def subject_from_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "uid": int(row["id"]),
        "id": int(row["id"]),
        "sub": str(row["username"]),
        "username": str(row["username"]),
        "role": str(row["role"]),
        "created_at": int(row["created_at"]),
    }


def normalize_user_claims(payload: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None

    user = dict(payload)
    if "uid" not in user and "id" in user:
        user["uid"] = user["id"]
    if "id" not in user and "uid" in user:
        user["id"] = user["uid"]
    if "username" not in user and "sub" in user:
        user["username"] = user["sub"]
    if "sub" not in user and "username" in user:
        user["sub"] = user["username"]

    required = ("uid", "id", "sub", "username", "role", "created_at")
    if any(key not in user for key in required):
        return None

    try:
        user["uid"] = int(user["uid"])
        user["id"] = int(user["id"])
        user["created_at"] = int(user["created_at"])
        user["sub"] = str(user["sub"])
        user["username"] = str(user["username"])
        user["role"] = str(user["role"])
    except Exception:
        return None

    return user


def build_session_claims(subject: dict[str, Any]) -> dict[str, Any]:
    now = int(time.time())
    return {
        "uid": int(subject["uid"]),
        "id": int(subject["id"]),
        "sub": str(subject["sub"]),
        "username": str(subject["username"]),
        "role": str(subject["role"]),
        "created_at": int(subject["created_at"]),
        "iat": now,
        "exp": now + TOKEN_TTL,
        "jti": secrets.token_hex(8),
    }


def issue_token(subject: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    claims = build_session_claims(subject)
    return jwt_signer().make_token(claims), claims


def store_session_token(user_id: int, token: str, claims: dict[str, Any]) -> None:
    conn = db()
    try:
        conn.execute(
            "UPDATE users SET current_token = ?, current_token_exp = ? WHERE id = ?",
            (token, int(claims["exp"]), int(user_id)),
        )
        conn.commit()
    finally:
        conn.close()


def cached_token_for_row(row: sqlite3.Row | dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    token = row["current_token"]
    token_exp = int(row["current_token_exp"] or 0)
    if not token or token_exp < int(time.time()):
        return None
    payload = jwt_signer().verify_token(str(token))
    if payload is None:
        return None
    user = normalize_user_claims(payload)
    if user is None or not same_identity(user, row):
        return None
    return str(token), payload


def current_user_from_cookie(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None

    payload = jwt_signer().verify_token(token)
    if payload is None:
        return None
    return normalize_user_claims(payload)


def same_identity(user: dict[str, Any], row: sqlite3.Row | dict[str, Any]) -> bool:
    try:
        return (
            int(user["id"]) == int(row["id"])
            and str(user["username"]) == str(row["username"])
            and str(user["role"]) == str(row["role"])
        )
    except Exception:
        return False


def html(request: Request, template: str, **context: Any) -> Response:
    return templates.TemplateResponse(request, template, context)


def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(TOKEN_COOKIE, token, httponly=True, samesite="lax", max_age=TOKEN_TTL)


@app.on_event("startup")
def startup() -> None:
    regenerate_jwt_signer()
    init_db()
    sync_admin_account()


@app.on_event("shutdown")
def shutdown() -> None:
    cleanup_ctf_users()


@app.get("/ping")
def ping() -> dict[str, Any]:
    return {"ok": True, "msg": "pong", "alg": JWT_ALG}


@app.get("/", response_class=HTMLResponse)
def index(request: Request, access_token: str | None = Cookie(default=None, alias=TOKEN_COOKIE)):
    user = current_user_from_cookie(access_token)
    return html(request, "index.html", user=user, featured=ARTICLES, title="Invincible Archive")


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return html(request, "register.html", error=None, title="Join The Archive")


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if len(username) < 3 or len(password) < 6:
        return html(request, "register.html", error="Username >= 3 chars, password >= 6 chars")

    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        user_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'user'").fetchone()[0]
        if int(user_count) >= MAX_REGISTERED_USERS:
            conn.rollback()
            return html(
                request,
                "register.html",
                error=f"Registration limit reached ({MAX_REGISTERED_USERS} users per run)",
            )
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at, current_token, current_token_exp) VALUES (?, ?, 'user', ?, NULL, 0)",
            (username, hash_password(password), int(time.time())),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, username, role, created_at, current_token, current_token_exp FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except sqlite3.IntegrityError:
        conn.rollback()
        return html(request, "register.html", error="Username already exists")
    finally:
        conn.close()

    token, _claims = issue_token(subject_from_row(row))
    store_session_token(int(row["id"]), token, _claims)
    resp = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    set_auth_cookie(resp, token)
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return html(request, "login.html", error=None, title="Archive Login")


@app.post("/login")
def login(
    request: Request,
    access_token: str | None = Cookie(default=None, alias=TOKEN_COOKIE),
    username: str = Form(...),
    password: str = Form(...),
):
    row = authenticate_user(username, password)
    if row is None:
        return html(request, "login.html", error="Invalid username or password")

    current_user = current_user_from_cookie(access_token)
    if current_user is not None and same_identity(current_user, row):
        return RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)

    cached = cached_token_for_row(row)
    if cached is not None:
        token, _payload = cached
        resp = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        set_auth_cookie(resp, token)
        return resp

    token, _claims = issue_token(subject_from_row(row))
    store_session_token(int(row["id"]), token, _claims)
    resp = RedirectResponse("/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    set_auth_cookie(resp, token)
    return resp


@app.post("/logout")
def logout() -> RedirectResponse:
    resp = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(TOKEN_COOKIE)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, access_token: str | None = Cookie(default=None, alias=TOKEN_COOKIE)):
    user = current_user_from_cookie(access_token)
    if user is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    return html(request, "dashboard.html", user=user, articles=ARTICLES, title="Invincible Archive")


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, access_token: str | None = Cookie(default=None, alias=TOKEN_COOKIE)):
    user = current_user_from_cookie(access_token)
    if user is None:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="forbidden")

    conn = db()
    try:
        users = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    return html(request, "admin.html", user=user, users=users, flag=current_flag(), title="GDA Admin Console")


@app.get("/api/me")
def api_me(access_token: str | None = Cookie(default=None, alias=TOKEN_COOKIE)):
    user = current_user_from_cookie(access_token)
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


@app.get("/api/admin/flag")
def api_admin_flag(access_token: str | None = Cookie(default=None, alias=TOKEN_COOKIE)):
    user = current_user_from_cookie(access_token)
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="forbidden")
    return {"flag": current_flag()}
