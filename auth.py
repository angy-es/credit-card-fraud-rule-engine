"""
auth.py - Authentication for the Fraud Rule Engine API (stdlib + FastAPI only).

- Users stored in SQLite (users.db), passwords hashed with salted PBKDF2.
- Login returns an HMAC-signed token (8h expiry); send it as
  "Authorization: Bearer <token>".
- Roles: "admin" (edit rules, manage users) and "analyst" (evaluate, view).

Environment variables (set before first run):
    AUTH_SECRET     long random string used to sign tokens (REQUIRED in real use)
    ADMIN_PASSWORD  password of the default 'admin' user created on first run
    ALLOW_SIGNUP    "true" (default) / "false" to disable self-registration
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

DB_PATH = os.environ.get("AUTH_DB_PATH", "users.db")
PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_SECONDS = 8 * 3600
MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 300
ROLES = ("admin", "analyst")
ALLOW_SIGNUP = os.environ.get("ALLOW_SIGNUP", "true").lower() == "true"

SECRET = os.environ.get("AUTH_SECRET")
if not SECRET:
    SECRET = secrets.token_hex(32)
    print("[auth] WARNING: AUTH_SECRET not set - using a random key. "
          "All logins will be invalidated on every API restart.")


# ------------------------------------------------------------------ database
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS).hex()


def _insert_user(conn, username, email, password, role):
    salt = os.urandom(16)
    conn.execute(
        "INSERT INTO users (username, email, password_hash, salt, role, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (username, email, _hash_password(password, salt), salt.hex(), role, time.time()),
    )


def init_db():
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                created_at REAL NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0
            )"""
        )
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            pwd = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
            _insert_user(c, "admin", "admin@example.com", pwd, "admin")
            print("[auth] Created default user 'admin'. Change its password!")


def _public(row):
    return {"id": row["id"], "username": row["username"],
            "email": row["email"], "role": row["role"]}


def get_user_by_id(user_id: int):
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public(row) if row else None


# -------------------------------------------------------------------- tokens
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def create_token(user_id: int) -> str:
    payload = _b64e(json.dumps({"uid": user_id, "exp": time.time() + TOKEN_TTL_SECONDS}).encode())
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def verify_token(token: str):
    try:
        payload, sig = token.split(".")
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_b64d(payload))
        return data if data["exp"] > time.time() else None
    except Exception:
        return None


# ---------------------------------------------------------------- validation
def validate_password(pw: str):
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", pw) or not re.search(r"[a-z]", pw):
        return "Password needs upper and lower case letters."
    if not re.search(r"\d", pw):
        return "Password needs at least one digit."
    return None


def validate_signup(username, email, pw):
    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return "Username: 3-30 chars, letters/numbers/underscore only."
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return "Enter a valid email address."
    return validate_password(pw)


# ---------------------------------------------------------------- dependencies
_bearer = HTTPBearer(auto_error=False)


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)):
    """Use as Depends(get_current_user) on any endpoint that needs a login."""
    if creds is None:
        raise HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    data = verify_token(creds.credentials)
    if not data:
        raise HTTPException(401, "Session expired - please log in again",
                            headers={"WWW-Authenticate": "Bearer"})
    user = get_user_by_id(data["uid"])  # fresh from DB so role changes apply instantly
    if not user:
        raise HTTPException(401, "User no longer exists")
    return user


def require_admin(user: dict = Depends(get_current_user)):
    """Use as Depends(require_admin) on admin-only endpoints."""
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return user


# -------------------------------------------------------------------- routes
router = APIRouter()


class LoginIn(BaseModel):
    username: str
    password: str


class SignupIn(BaseModel):
    username: str
    email: str
    password: str


class RoleIn(BaseModel):
    role: str


class PasswordIn(BaseModel):
    new_password: str


@router.post("/auth/login")
def login(body: LoginIn):
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username = ?",
                        (body.username.strip(),)).fetchone()
        if row is None:
            raise HTTPException(401, "Invalid username or password")

        if row["locked_until"] > time.time():
            mins = int((row["locked_until"] - time.time()) // 60) + 1
            raise HTTPException(429, f"Account locked. Try again in ~{mins} min.")

        candidate = _hash_password(body.password, bytes.fromhex(row["salt"]))
        if hmac.compare_digest(candidate, row["password_hash"]):
            c.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?",
                      (row["id"],))
            return {"token": create_token(row["id"]), "user": _public(row)}

        attempts = row["failed_attempts"] + 1
        locked = time.time() + LOCK_SECONDS if attempts >= MAX_FAILED_ATTEMPTS else 0
        c.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                  (0 if locked else attempts, locked, row["id"]))
    raise HTTPException(401, "Invalid username or password")


@router.post("/auth/signup")
def signup(body: SignupIn):
    if not ALLOW_SIGNUP:
        raise HTTPException(403, "Self-registration is disabled. Ask an admin for an account.")
    err = validate_signup(body.username.strip(), body.email.strip(), body.password)
    if err:
        raise HTTPException(400, err)
    try:
        with _conn() as c:
            _insert_user(c, body.username.strip(), body.email.strip().lower(),
                         body.password, "analyst")
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username or email already exists")
    return {"message": "Account created. You can log in now."}


@router.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


@router.get("/users")
def list_users(_: dict = Depends(require_admin)):
    with _conn() as c:
        rows = c.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id")
        return [dict(r) for r in rows]


@router.put("/users/{user_id}/role")
def set_role(user_id: int, body: RoleIn, admin: dict = Depends(require_admin)):
    if body.role not in ROLES:
        raise HTTPException(400, "Invalid role")
    if user_id == admin["id"]:
        raise HTTPException(400, "You can't change your own role")
    with _conn() as c:
        c.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, user_id))
    return {"message": "Role updated"}


@router.put("/users/{user_id}/password")
def admin_reset_password(user_id: int, body: PasswordIn, _: dict = Depends(require_admin)):
    err = validate_password(body.new_password)
    if err:
        raise HTTPException(400, err)
    salt = os.urandom(16)
    with _conn() as c:
        c.execute("UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, "
                  "locked_until = 0 WHERE id = ?",
                  (_hash_password(body.new_password, salt), salt.hex(), user_id))
    return {"message": "Password reset"}


@router.delete("/users/{user_id}")
def remove_user(user_id: int, admin: dict = Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(400, "You can't delete yourself")
    with _conn() as c:
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return {"message": "User deleted"}