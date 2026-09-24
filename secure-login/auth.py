"""Secure login module (Lab #4). Standard library only."""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3

MAX_FAILED_ATTEMPTS = 3
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{3,32}$")
GENERIC_ERROR = "Invalid username or password."
LOCKED_ERROR = "Account locked. Please contact support."


class ValidationError(Exception):
    """Raised when user input fails validation."""


def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password, stored):
    salt_hex, digest_hex = stored.split(":")
    candidate = hash_password(password, bytes.fromhex(salt_hex)).split(":")[1]
    return hmac.compare_digest(candidate, digest_hex)


def validate_input(username, password):
    """Validate at the system boundary, before any DB access."""
    username = (username or "").strip()
    password = password or ""
    if not username and not password:
        raise ValidationError("Username and password are required.")
    if not username:
        raise ValidationError("Username is required.")
    if not password:
        raise ValidationError("Password is required.")
    if not USERNAME_PATTERN.match(username):
        raise ValidationError("Username contains invalid characters.")
    return username, password


class AuthService:
    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, "
            "failed_attempts INTEGER NOT NULL DEFAULT 0, "
            "is_locked INTEGER NOT NULL DEFAULT 0)"
        )

    def register(self, username, password):
        username, password = validate_input(username, password)
        self.conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        self.conn.commit()

    def _find_user(self, username):
        # Parameterized query: input is treated as data, never as SQL.
        return self.conn.execute(
            "SELECT password_hash, failed_attempts, is_locked "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    def _record_failure(self, username, failed_attempts):
        failed_attempts += 1
        locked = 1 if failed_attempts >= MAX_FAILED_ATTEMPTS else 0
        self.conn.execute(
            "UPDATE users SET failed_attempts = ?, is_locked = ? WHERE username = ?",
            (failed_attempts, locked, username),
        )
        self.conn.commit()

    def _reset_failures(self, username):
        self.conn.execute(
            "UPDATE users SET failed_attempts = 0 WHERE username = ?", (username,)
        )
        self.conn.commit()

    def get_failed_attempts(self, username):
        row = self._find_user(username)
        return row[1] if row else None

    def is_locked(self, username):
        row = self._find_user(username)
        return bool(row[2]) if row else False

    def login(self, username, password):
        """Returns {'success': bool, 'token': str|None, 'error': str|None}.
        Raises ValidationError for bad input. Never leaks internals."""
        username, password = validate_input(username, password)
        try:
            user = self._find_user(username)
            if user is None:
                return {"success": False, "token": None, "error": GENERIC_ERROR}
            password_hash, failed_attempts, is_locked = user
            if is_locked:
                return {"success": False, "token": None, "error": LOCKED_ERROR}
            if not verify_password(password, password_hash):
                self._record_failure(username, failed_attempts)
                return {"success": False, "token": None, "error": GENERIC_ERROR}
            self._reset_failures(username)
            return {"success": True, "token": secrets.token_hex(16), "error": None}
        except sqlite3.Error:
            return {"success": False, "token": None, "error": "Service unavailable."}
