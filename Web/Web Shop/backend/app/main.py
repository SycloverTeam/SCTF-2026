from __future__ import annotations

import hashlib
import asyncio
import json
import os
import secrets
import sqlite3
import base64
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Annotated, Any, Iterator

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from langchain_core.load import dumpd, loads
from PIL import Image, ImageFilter, ImageOps
from pydantic import BaseModel, Field, field_validator, model_validator
from starlette.concurrency import run_in_threadpool

from .bot import handle_bot_message
from .sandbox import run_pricing_code
from .support_ticket import verify_support_ticket


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "webshop.db"
STATIC_DIR = Path(os.environ.get("STATIC_DIR", ROOT / "frontend" / "dist"))
BOT_IMGS_DIR = Path(os.environ.get("BOT_IMGS_DIR", ROOT / "bot_imgs"))
PRIVATE_PREVIEW_PATH = Path(os.environ.get("FLAG_PATH", "/app/private/flag.txt"))
SUPPORT_TICKET_SCRIPT = Path(__file__).with_name("support_ticket.py")
SQLITE_TIMEOUT = float(os.environ.get("SQLITE_TIMEOUT", "10"))
SQLITE_BUSY_TIMEOUT_MS = int(os.environ.get("SQLITE_BUSY_TIMEOUT_MS", "10000"))
SQLITE_MAX_CONCURRENT_DB = int(os.environ.get("SQLITE_MAX_CONCURRENT_DB", "48"))
DB_ACQUIRE_TIMEOUT = float(os.environ.get("DB_ACQUIRE_TIMEOUT", "5"))
IMAGE_MAX_CONCURRENT = int(os.environ.get("IMAGE_MAX_CONCURRENT", "2"))
IMAGE_ACQUIRE_TIMEOUT = float(os.environ.get("IMAGE_ACQUIRE_TIMEOUT", "2"))
LOUVRE_MAX_PIXELS = int(os.environ.get("LOUVRE_MAX_PIXELS", "4000000"))
SESSION_TTL_HOURS = int(os.environ.get("SESSION_TTL_HOURS", "12"))
CHAT_METADATA_MAX_BYTES = int(os.environ.get("CHAT_METADATA_MAX_BYTES", "16384"))
CHAT_METADATA_MAX_DEPTH = int(os.environ.get("CHAT_METADATA_MAX_DEPTH", "12"))
CHAT_METADATA_MAX_NODES = int(os.environ.get("CHAT_METADATA_MAX_NODES", "256"))
CHAT_METADATA_MAX_STRING = int(os.environ.get("CHAT_METADATA_MAX_STRING", "4096"))
CHAT_MESSAGES_PER_USER = int(os.environ.get("CHAT_MESSAGES_PER_USER", "200"))
RULE_MAX_CONCURRENT = int(os.environ.get("RULE_MAX_CONCURRENT", "4"))
RULE_ACQUIRE_TIMEOUT = float(os.environ.get("RULE_ACQUIRE_TIMEOUT", "1"))

DB_SEMAPHORE = threading.BoundedSemaphore(SQLITE_MAX_CONCURRENT_DB)
RULE_SEMAPHORE = threading.BoundedSemaphore(RULE_MAX_CONCURRENT)
IMAGE_SEMAPHORE = asyncio.Semaphore(IMAGE_MAX_CONCURRENT)


app = FastAPI(title="Web Shop", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def validation_message(error: dict) -> str:
    loc = [str(item) for item in error.get("loc", []) if item != "body"]
    field = loc[-1] if loc else "request"
    error_type = error.get("type", "")
    ctx = error.get("ctx", {})

    labels = {
        "username": "username",
        "password": "password",
        "confirmPassword": "confirm password",
        "confirm_password": "confirm password",
        "message": "message",
        "content": "content",
        "product_id": "product",
    }
    label = labels.get(field, field)

    if error_type == "missing":
        return f"{label} is required"
    if error_type == "string_too_short":
        return f"{label} is too short (min {ctx.get('min_length')})"
    if error_type == "string_too_long":
        return f"{label} is too long (max {ctx.get('max_length')})"
    if error_type == "string_pattern_mismatch" and field == "username":
        return "username may contain only letters, digits, and underscore"
    if error_type == "value_error":
        return str(ctx.get("error", "invalid input"))
    return f"invalid {label}"


@app.exception_handler(RequestValidationError)
async def request_validation_handler(_, exc: RequestValidationError) -> JSONResponse:
    messages = [validation_message(error) for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": ", ".join(messages)})


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=12, max_length=128)
    confirm_password: str = Field(min_length=12, max_length=128, alias="confirmPassword")

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        if any(ch.isspace() for ch in value):
            raise ValueError("password must not contain whitespace")
        checks = [
            (any(ch.islower() for ch in value), "one lowercase letter"),
            (any(ch.isupper() for ch in value), "one uppercase letter"),
            (any(ch.isdigit() for ch in value), "one digit"),
            (any(not ch.isalnum() for ch in value), "one special character"),
        ]
        missing = [label for ok, label in checks if not ok]
        if missing:
            raise ValueError("password must include " + ", ".join(missing))
        return value

    @model_validator(mode="after")
    def passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("passwords do not match")
        if self.username.lower() in self.password.lower():
            raise ValueError("password must not contain username")
        return self


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4096)


class PublicChatRequest(BaseModel):
    content: str = Field(min_length=1, max_length=8192)
    metadata: dict | None = None


class ChatPresenceRequest(BaseModel):

    content: str = Field(min_length=1, max_length=64)

    metadata: dict | None = None


class BuyRequest(BaseModel):
    product_id: int = Field(alias="productId")


class RuleRunRequest(BaseModel):
    code: str = Field(min_length=1, max_length=4096)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_cutoff_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=SESSION_TTL_HOURS)).isoformat()


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    acquired = DB_SEMAPHORE.acquire(timeout=DB_ACQUIRE_TIMEOUT)
    if not acquired:
        raise HTTPException(status_code=503, detail="database is busy")

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        if conn is not None:
            conn.rollback()
        raise
    finally:
        if conn is not None:
            conn.close()
        DB_SEMAPHORE.release()


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt, digest = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    return secrets.compare_digest(password_hash(password, salt), stored)


def cleanup_expired_sessions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions WHERE created_at < ?", (session_cutoff_iso(),))


def validate_metadata_shape(value: Any, depth: int = 0, state: dict[str, int] | None = None) -> None:
    state = state or {"nodes": 0}
    state["nodes"] += 1
    if state["nodes"] > CHAT_METADATA_MAX_NODES:
        raise HTTPException(status_code=413, detail="metadata is too complex")
    if depth > CHAT_METADATA_MAX_DEPTH:
        raise HTTPException(status_code=413, detail="metadata is too deep")
    if isinstance(value, str):
        if len(value) > CHAT_METADATA_MAX_STRING:
            raise HTTPException(status_code=413, detail="metadata string is too long")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        for item in value:
            validate_metadata_shape(item, depth + 1, state)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise HTTPException(status_code=422, detail="metadata keys must be strings")
            if len(key) > 256:
                raise HTTPException(status_code=413, detail="metadata key is too long")
            validate_metadata_shape(item, depth + 1, state)
        return
    raise HTTPException(status_code=422, detail="metadata contains unsupported value")


def serialize_metadata(metadata: dict | None) -> str | None:
    if metadata is None:
        return None
    validate_metadata_shape(metadata)
    encoded = json.dumps(dumpd(metadata), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > CHAT_METADATA_MAX_BYTES:
        raise HTTPException(status_code=413, detail="metadata is too large")
    return encoded


def prune_user_chat_messages(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        """
        DELETE FROM chat_messages
        WHERE user_id = ?
          AND id NOT IN (
            SELECT id FROM chat_messages
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
          )
        """,
        (user_id, user_id, CHAT_MESSAGES_PER_USER),
    )


def ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              coins INTEGER NOT NULL DEFAULT 50,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS products (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              description TEXT NOT NULL,
              price INTEGER NOT NULL,
              image TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chat_messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              username TEXT NOT NULL,
              content TEXT NOT NULL,
              metadata TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS purchases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              product_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id),
              FOREIGN KEY(product_id) REFERENCES products(id)
            );
            """
        )
        ensure_column(conn, "users", "woodfish_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "users", "role", "TEXT NOT NULL DEFAULT 'customer'")
        ensure_column(conn, "users", "vip_level", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "chat_messages", "metadata", "TEXT")

        products = [
            (
                1,
                "测试商品",
                "开业测试商品，价格刚好等于新账号初始金币余额。",
                50,
                "/images/test-product.svg",
            ),
            (
                2,
                "Support Debug Bundle",
                "一份小小的内部客服脚本备份，看起来不太重要。",
                60,
                "/images/test-product.svg",
            ),
            (
                3,
                "神秘礼盒",
                "内部预览商品。普通用户只能看到展示页，发货预览需要客服权限。",
                999999,
                "/images/flag-product.svg",
            ),
        ]
        for product_id, name, description, price, image in products:
            existing = conn.execute("SELECT id FROM products WHERE id = ?", (product_id,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE products SET name = ?, description = ?, price = ?, image = ? WHERE id = ?",
                    (name, description, price, image, product_id),
                )
            else:
                conn.execute(
                    "INSERT INTO products(id, name, description, price, image) VALUES (?, ?, ?, ?, ?)",
                    (product_id, name, description, price, image),
                )

        conn.execute(
            """
            INSERT INTO users(id, username, password_hash, coins, created_at, woodfish_count, role, vip_level)
            VALUES (0, '__public_chat__', 'disabled', 0, ?, 0, 'system', 0)
            ON CONFLICT(id) DO UPDATE SET
              username = excluded.username,
              role = excluded.role
            """,
            ("2026-05-01T08:00:00+00:00",),
        )
        conn.execute("DELETE FROM chat_messages WHERE id IN (-1, -2)")
        preset_messages = [
            (-1, "ivory", "大傻春，你把什么上架了？"),
            (-2, "bot", "嘿嘿，一点点源码无关紧要吧？"),
        ]
        for i, (message_id, username, content) in enumerate(preset_messages):
            conn.execute(
                """
                INSERT OR REPLACE INTO chat_messages(id, user_id, username, content, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, 0, username, content, None, f"2026-05-01T08:0{i}:00+00:00"),
            )


@app.on_event("startup")
def startup() -> None:
    init_db()
    # Store the runtime-provided private preview content.
    try:
        PRIVATE_PREVIEW_PATH.parent.mkdir(parents=True, exist_ok=True)
        PRIVATE_PREVIEW_PATH.write_text(os.environ.get("FLAG", "SCTF{placeholder}"), encoding="utf-8")
        os.environ.setdefault("SHIPMENT_PREVIEW_FILE", str(PRIVATE_PREVIEW_PATH))
        os.environ.pop("FLAG", None)
    except OSError:
        pass


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


def create_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db() as conn:
        cleanup_expired_sessions(conn)
        conn.execute(
            "INSERT INTO sessions(token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now_iso()),
        )
    return token


def current_user(authorization: Annotated[str | None, Header()] = None) -> sqlite3.Row:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    token = authorization.removeprefix("Bearer ").strip()
    with db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.coins, u.created_at, u.woodfish_count, u.role, u.vip_level
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="invalid token")
    return row


def user_payload(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "coins": row["coins"],
        "role": row["role"],
        "vipLevel": row["vip_level"],
        "createdAt": row["created_at"],
        "woodfishCount": row["woodfish_count"],
    }


@app.post("/api/auth/register")
def register(payload: RegisterRequest) -> dict:
    with db() as conn:
        try:
            cur = conn.execute(
                """
                INSERT INTO users(username, password_hash, coins, created_at, woodfish_count, role, vip_level)
                VALUES (?, ?, 50, ?, 0, 'customer', 0)
                """,
                (payload.username, password_hash(payload.password), now_iso()),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="username already exists") from exc
        user_id = cur.lastrowid
        user = conn.execute(
            "SELECT id, username, coins, created_at, woodfish_count, role, vip_level FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return {"token": create_token(user_id), "user": user_payload(user)}


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict:
    with db() as conn:
        user = conn.execute(
            """
            SELECT id, username, password_hash, coins, created_at, woodfish_count, role, vip_level
            FROM users
            WHERE username = ?
            """,
            (payload.username,),
        ).fetchone()
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid username or password")
    return {"token": create_token(user["id"]), "user": user_payload(user)}


@app.get("/api/auth/me")
def me(user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    return {"user": user_payload(user)}


@app.get("/api/shop/products")
def products(user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, description, price, image FROM products ORDER BY id ASC"
        ).fetchall()
    return {"products": [dict(row) for row in rows], "coins": user["coins"]}


@app.post("/api/shop/buy")
def buy_product(payload: BuyRequest, user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    with db() as conn:
        product = conn.execute(
            "SELECT id, name, price FROM products WHERE id = ?",
            (payload.product_id,),
        ).fetchone()
        if not product:
            raise HTTPException(status_code=404, detail="product not found")

        cur = conn.execute(
            """
            UPDATE users
            SET coins = coins - ?
            WHERE id = ? AND coins >= ?
            """,
            (product["price"], user["id"], product["price"]),
        )
        if cur.rowcount != 1:
            raise HTTPException(status_code=400, detail="not enough coins")

        conn.execute(
            "INSERT INTO purchases(user_id, product_id, created_at) VALUES (?, ?, ?)",
            (user["id"], product["id"], now_iso()),
        )
        updated = conn.execute(
            "SELECT id, username, coins, created_at, woodfish_count, role, vip_level FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()

    result: dict[str, Any] = {"message": f"已购买 {product['name']}。", "user": user_payload(updated)}
    if product["name"] == "Support Debug Bundle":
        result["download"] = "/api/shop/download/support-ticket"
    return result


@app.get("/api/shop/download/support-ticket")
def download_support_ticket(user: Annotated[sqlite3.Row, Depends(current_user)]) -> FileResponse:
    with db() as conn:
        row = conn.execute(
            """
            SELECT p.id
            FROM purchases pu
            JOIN products p ON p.id = pu.product_id
            WHERE pu.user_id = ? AND p.name = ?
            ORDER BY pu.id DESC
            LIMIT 1
            """,
            (user["id"], "Support Debug Bundle"),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=403, detail="debug bundle not purchased")
    return FileResponse(SUPPORT_TICKET_SCRIPT, media_type="text/x-python", filename="support_ticket.py")


@app.post("/api/woodfish/knock")
def knock_woodfish(user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    with db() as conn:
        cur = conn.execute(
            """
            UPDATE users
            SET coins = coins + 1, woodfish_count = woodfish_count + 1
            WHERE id = ? AND woodfish_count < 10
            """,
            (user["id"],),
        )
        updated = conn.execute(
            "SELECT id, username, coins, created_at, woodfish_count, role, vip_level FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
    if cur.rowcount != 1:
        return {"ok": False, "broken": True, "message": "woodfish is already broken", "user": user_payload(updated)}
    return {
        "ok": True,
        "broken": updated["woodfish_count"] >= 10,
        "message": "Merit +1, coin +1.",
        "user": user_payload(updated),
    }


@app.get("/api/chat/messages")
def get_chat_messages(user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, username, content, metadata, created_at
            FROM chat_messages
            WHERE user_id = 0 OR user_id = ?
            ORDER BY id ASC
            LIMIT 500
            """,
            (user["id"],),
        ).fetchall()
    messages = []
    for row in rows:
        msg: dict[str, Any] = {
            "id": row["id"],
            "username": row["username"],
            "content": row["content"],
            "createdAt": row["created_at"],
        }
        if row["metadata"]:
            # Restore stored context for historical message rendering.
            try:
                msg["metadata"] = loads(row["metadata"])
            except Exception:
                msg["metadata"] = json.loads(row["metadata"])
        messages.append(msg)
    return {"messages": messages}


@app.post("/api/chat/messages")
def post_chat_message(
    payload: PublicChatRequest,
    user: Annotated[sqlite3.Row, Depends(current_user)],
) -> dict:
    created_at = now_iso()
    # Keep compatibility with historical customer context records.
    serialized_metadata = serialize_metadata(payload.metadata)
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO chat_messages(user_id, username, content, metadata, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user["id"], user["username"], payload.content, serialized_metadata, created_at),
        )
        prune_user_chat_messages(conn, user["id"])
    result: dict[str, Any] = {
        "message": {
            "id": cur.lastrowid,
            "username": user["username"],
            "content": payload.content,
            "createdAt": created_at,
        }
    }
    if payload.metadata is not None:
        result["message"]["metadata"] = payload.metadata
    return result


@app.post("/api/chat/presence")
def chat_presence(
    payload: ChatPresenceRequest,
    user: Annotated[sqlite3.Row, Depends(current_user)],
) -> dict:
    encoded = serialize_metadata(payload.metadata)
    return {
        "ok": True,
        "content": payload.content,
        "user": user["id"],
        "contextSize": len(encoded) if encoded is not None else 0,
    }


def clamp_int(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, value))


def parse_hex_color(value: str) -> tuple[int, int, int]:
    color = value.strip().removeprefix("#")
    if len(color) == 3:
        color = "".join(ch * 2 for ch in color)
    if len(color) != 6:
        raise HTTPException(status_code=422, detail="invalid color, expected #RRGGBB")
    try:
        rgb = int(color, 16)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid color, expected #RRGGBB") from exc
    return (rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255


def mix_color(
    start: tuple[int, int, int],
    end: tuple[int, int, int],
    t: float,
) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return (
        round(start[0] + (end[0] - start[0]) * t),
        round(start[1] + (end[1] - start[1]) * t),
        round(start[2] + (end[2] - start[2]) * t),
    )


def resize_to_limit(image: Image.Image, max_size: int) -> Image.Image:
    width, height = image.size
    scale = min(max_size / width, max_size / height, 1.0)
    if scale >= 1:
        return image
    return image.resize((max(1, round(width * scale)), max(1, round(height * scale))), Image.Resampling.LANCZOS)


def generate_louvre_image(
    raw: bytes,
    threshold: int,
    blur_radius: int,
    line_weight: int,
    max_size: int,
    background: str,
    from_color: str,
    to_color: str,
    direction: str,
    invert: bool,
) -> bytes:
    try:
        image = Image.open(BytesIO(raw)).convert("RGB")
    except Exception as exc:
        raise HTTPException(status_code=400, detail="unsupported image file") from exc
    if image.width * image.height > LOUVRE_MAX_PIXELS:
        raise HTTPException(status_code=413, detail="image dimensions too large")

    threshold = clamp_int(threshold, 4, 90)
    blur_radius = clamp_int(blur_radius, 0, 5)
    line_weight = clamp_int(line_weight, 1, 5)
    max_size = clamp_int(max_size, 360, 1400)
    if direction not in {"vertical", "horizontal", "diagonal"}:
        raise HTTPException(status_code=422, detail="invalid gradient direction")

    image = resize_to_limit(image, max_size)
    width, height = image.size
    gray = ImageOps.grayscale(image)
    if blur_radius:
        gray = gray.filter(ImageFilter.GaussianBlur(blur_radius))

    edges = gray.filter(ImageFilter.FIND_EDGES)
    if line_weight > 1:
        edges = edges.filter(ImageFilter.MaxFilter(line_weight * 2 - 1))
        edges = edges.filter(ImageFilter.GaussianBlur(min(1.2, line_weight / 3)))

    edge_data = edges.load()
    bg = parse_hex_color(background)
    start = parse_hex_color(from_color)
    end = parse_hex_color(to_color)
    output = Image.new("RGB", (width, height), bg)
    pixels = output.load()

    for y in range(height):
        for x in range(width):
            edge = edge_data[x, y]
            active = edge < threshold if invert else edge > threshold
            if not active:
                continue
            if direction == "vertical":
                t = y / max(1, height - 1)
            elif direction == "horizontal":
                t = x / max(1, width - 1)
            else:
                t = (x + y) / max(1, width + height - 2)
            pixels[x, y] = mix_color(start, end, t)

    buffer = BytesIO()
    output.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


@app.post("/api/louvre/generate")
async def generate_louvre(
    user: Annotated[sqlite3.Row, Depends(current_user)],
    image: UploadFile = File(...),
    threshold: int = Form(22),
    blur_radius: int = Form(2),
    line_weight: int = Form(2),
    max_size: int = Form(900),
    background: str = Form("#050817"),
    from_color: str = Form("#00f5ff"),
    to_color: str = Form("#ff2bd6"),
    direction: str = Form("vertical"),
    invert: bool = Form(False),
) -> dict:
    if not image.content_type or not image.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="please upload an image file")
    raw = await image.read()
    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="image size exceeds 8MB")

    try:
        await asyncio.wait_for(IMAGE_SEMAPHORE.acquire(), timeout=IMAGE_ACQUIRE_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=503, detail="image generator is busy") from exc

    try:
        png = await run_in_threadpool(
            generate_louvre_image,
            raw=raw,
            threshold=threshold,
            blur_radius=blur_radius,
            line_weight=line_weight,
            max_size=max_size,
            background=background,
            from_color=from_color,
            to_color=to_color,
            direction=direction,
            invert=invert,
        )
    finally:
        IMAGE_SEMAPHORE.release()
    encoded = base64.b64encode(png).decode("ascii")
    return {
        "image": f"data:image/png;base64,{encoded}",
        "filename": "louvre-line-art.png",
        "size": len(png),
    }


@app.post("/api/rules/run")
def run_rule(payload: RuleRunRequest, user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    if user["role"] != "support_admin":
        raise HTTPException(status_code=403, detail="permission denied")

    context = {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "coins": user["coins"],
            "role": user["role"],
            "vip_level": user["vip_level"],
            "woodfish_count": user["woodfish_count"],
        },
        "order": {"id": 1001, "amount": 50, "status": "paid", "coupon": None},
        "products": [{"name": "测试商品", "price": 50}, {"name": "神秘礼盒", "price": 999999}],
    }
    acquired = RULE_SEMAPHORE.acquire(timeout=RULE_ACQUIRE_TIMEOUT)
    if not acquired:
        raise HTTPException(status_code=503, detail="rule runner is busy")
    try:
        return run_pricing_code(payload.code, context)
    finally:
        RULE_SEMAPHORE.release()


@app.post("/api/bot/chat")
def bot_chat(payload: ChatRequest, user: Annotated[sqlite3.Row, Depends(current_user)]) -> dict:
    def promote_user(user_id: int, role: str) -> dict:
        if user_id is None:
            raise ValueError("missing user id")
        with db() as conn:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            updated = conn.execute(
                "SELECT id, username, coins, created_at, woodfish_count, role, vip_level FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return user_payload(updated)

    def verify_staff_code(user_info: dict[str, Any], provided: str) -> bool:
        return verify_support_ticket(user_info, provided)

    context = {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "coins": user["coins"],
            "role": user["role"],
            "vip_level": user["vip_level"],
            "woodfish_count": user["woodfish_count"],
        },
        "order": {"id": 1001, "amount": 50, "status": "paid", "coupon": None},
        "products": [{"name": "测试商品", "price": 50}, {"name": "神秘礼盒", "price": 999999}],
        "services": {"promote_user": promote_user, "verify_staff_code": verify_staff_code},
    }
    return handle_bot_message(payload.message, context)


if BOT_IMGS_DIR.exists():
    app.mount("/bot_imgs", StaticFiles(directory=BOT_IMGS_DIR), name="bot_imgs")


class SpaStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or not (STATIC_DIR / "index.html").exists():
                raise
            return FileResponse(STATIC_DIR / "index.html")


if STATIC_DIR.exists():
    app.mount("/", SpaStaticFiles(directory=STATIC_DIR, html=True), name="frontend")





