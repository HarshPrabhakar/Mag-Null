# app/core/auth.py
# Mag-Null — JWT Authentication
# Handles login, token generation, validation, and session management
#
# Usage:
#   from app.core.auth import AuthManager
#   auth = AuthManager()
#   token = auth.login("operator", "magnull2025")
#   if auth.verify(token): ...

import os, json, time, hmac, base64, hashlib, secrets
from pathlib import Path

ROOT       = Path(__file__).resolve().parent.parent.parent
USERS_FILE = ROOT / "config" / "users.json"
SECRET_KEY = os.environ.get("MAGNULL_SECRET", secrets.token_hex(32))


def _hash(username: str, password: str) -> str:
    """Salted SHA-256 hash: HMAC(secret, username+password)"""
    msg = (username + ":" + password).encode()
    return hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()


# ── Default users (stored as bcrypt-style SHA256 salted hashes) ───
DEFAULT_USERS = {
    "operator": {
        "password_hash": _hash("operator", "magnull2025"),
        "role": "operator",
        "display": "Operator"
    },
    "analyst": {
        "password_hash": _hash("analyst", "analyst123"),
        "role": "analyst",
        "display": "Analyst"
    },
    "admin": {
        "password_hash": _hash("admin", "admin@magnull"),
        "role": "admin",
        "display": "Administrator"
    },
}


def _hash(username: str, password: str) -> str:
    """Salted SHA-256 hash: HMAC(secret, username+password)"""
    msg = (username + ":" + password).encode()
    return hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


class AuthManager:
    """
    Minimal JWT implementation using HS256.
    No external libraries — pure Python stdlib.
    """

    ALGORITHM  = "HS256"
    TOKEN_TTL  = 3600 * 8   # 8 hour session

    def __init__(self):
        self._load_users()
        self._active_tokens: dict[str, dict] = {}  # jti → payload
        self._revoked: set[str]               = set()

    # ── User store ────────────────────────────────────────────────
    def _load_users(self):
        if USERS_FILE.exists():
            with open(USERS_FILE) as f:
                self._users = json.load(f)
        else:
            self._users = DEFAULT_USERS
            USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(USERS_FILE, "w") as f:
                json.dump(self._users, f, indent=2)

    # ── JWT helpers ───────────────────────────────────────────────
    def _sign(self, header_b64: str, payload_b64: str) -> str:
        msg = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).digest()
        return _b64url(sig)

    def _make_token(self, username: str, role: str) -> str:
        header  = {"alg": self.ALGORITHM, "typ": "JWT"}
        jti     = secrets.token_hex(8)
        now     = int(time.time())
        payload = {
            "sub": username,
            "role": role,
            "iat": now,
            "exp": now + self.TOKEN_TTL,
            "jti": jti,
        }
        h = _b64url(json.dumps(header, separators=(",",":")).encode())
        p = _b64url(json.dumps(payload, separators=(",",":")).encode())
        s = self._sign(h, p)
        token = f"{h}.{p}.{s}"
        self._active_tokens[jti] = payload
        return token

    # ── Public API ────────────────────────────────────────────────
    def login(self, username: str, password: str) -> dict:
        """
        Returns: {"ok": True, "token": "...", "role": "...", "display": "..."}
                 {"ok": False, "error": "Invalid credentials"}
        """
        user = self._users.get(username)
        if not user:
            return {"ok": False, "error": "User not found"}

        expected = _hash(username, password)
        if not hmac.compare_digest(expected, user["password_hash"]):
            return {"ok": False, "error": "Invalid password"}

        token = self._make_token(username, user["role"])
        return {
            "ok":      True,
            "token":   token,
            "role":    user["role"],
            "display": user["display"],
            "username": username,
        }

    def verify(self, token: str) -> dict | None:
        """
        Verify token signature + expiry.
        Returns payload dict if valid, None if invalid/expired.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            h, p, s = parts
            if not hmac.compare_digest(self._sign(h, p), s):
                return None
            payload = json.loads(_b64url_decode(p))
            if time.time() > payload.get("exp", 0):
                return None
            if payload.get("jti") in self._revoked:
                return None
            return payload
        except Exception:
            return None

    def logout(self, token: str):
        """Revoke a token immediately."""
        try:
            parts   = token.split(".")
            payload = json.loads(_b64url_decode(parts[1]))
            jti     = payload.get("jti")
            if jti:
                self._revoked.add(jti)
                self._active_tokens.pop(jti, None)
        except Exception:
            pass

    def active_sessions(self) -> list[dict]:
        now = time.time()
        return [
            {"jti": jti, "sub": p["sub"], "role": p["role"],
             "expires_in": int(p["exp"] - now)}
            for jti, p in self._active_tokens.items()
            if p["exp"] > now and jti not in self._revoked
        ]


# ── Singleton ─────────────────────────────────────────────────────
_auth_instance = None

def get_auth() -> AuthManager:
    global _auth_instance
    if _auth_instance is None:
        _auth_instance = AuthManager()
    return _auth_instance