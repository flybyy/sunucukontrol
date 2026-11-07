import os
import secrets
import time
from collections import defaultdict, deque
from fastapi import HTTPException, Request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()
LOGIN_WINDOW = 300
LOGIN_LIMIT = 5
_attempts = defaultdict(deque)


def _bool_env(name: str, default=False):
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def verify_password(password: str) -> bool:
    hashed = os.environ.get("PANEL_PASSWORD_HASH", "")
    if not hashed:
        return False
    try:
        return ph.verify(hashed, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def client_ip(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip") if _bool_env("PANEL_TRUST_CF_HEADERS", False) else None
    return cf or (request.client.host if request.client else "unknown")


def cf_identity(request: Request) -> str:
    return (request.headers.get("cf-access-authenticated-user-email") or "").strip().lower()


def enforce_cf_access(request: Request):
    if not _bool_env("PANEL_REQUIRE_CF_ACCESS", False):
        return
    email = cf_identity(request)
    if not email:
        raise HTTPException(403, "Cloudflare Access kimliği gerekli")
    allowed = {
        x.strip().lower()
        for x in os.environ.get("PANEL_ALLOWED_CF_EMAILS", "").split(",")
        if x.strip()
    }
    if allowed and email not in allowed:
        raise HTTPException(403, "Bu Cloudflare Access hesabının panel yetkisi yok")


def check_login_rate(request: Request):
    ip = client_ip(request)
    now = time.time()
    q = _attempts[ip]
    while q and now - q[0] > LOGIN_WINDOW:
        q.popleft()
    if len(q) >= LOGIN_LIMIT:
        raise HTTPException(429, "Çok fazla giriş denemesi. Birkaç dakika sonra tekrar deneyin.")


def record_failed_login(request: Request):
    _attempts[client_ip(request)].append(time.time())


def clear_login_rate(request: Request):
    _attempts.pop(client_ip(request), None)


def require_auth(request: Request):
    enforce_cf_access(request)
    if not request.session.get("authenticated"):
        raise HTTPException(401, "Oturum gerekli")


def ensure_csrf(request: Request):
    require_auth(request)
    token = request.headers.get("x-csrf-token", "")
    expected = request.session.get("csrf", "")
    if not token or not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(403, "CSRF doğrulaması başarısız")


def check_origin(request: Request):
    expected = os.environ.get("PANEL_ORIGIN", "").rstrip("/")
    origin = request.headers.get("origin", "").rstrip("/")
    if expected and origin and origin != expected:
        raise HTTPException(403, "Geçersiz origin")
