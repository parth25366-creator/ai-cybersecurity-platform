"""JWT auth, role-based access control, rate limiting."""
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from limits import parse, storage, strategies
from pwdlib import PasswordHash
from sqlmodel import Session

from .core import User, get_session, settings

ph = PasswordHash.recommended()  # argon2
oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login")
_limiter = strategies.MovingWindowRateLimiter(storage.MemoryStorage())  # per-process; use Redis to scale out


def rate_limit(rule: str, *key: str):
    """Raise 429 when `key` exceeds `rule` (e.g. "5/minute"). Keyed by account, not IP, because the
    UI proxy hides client IPs."""
    if not _limiter.hit(parse(rule), *key):
        raise HTTPException(429, "Too many requests, slow down")


def make_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode({"sub": str(user.id), "exp": exp}, settings.jwt_secret, "HS256")


def current_user(token: str = Depends(oauth2), s: Session = Depends(get_session)) -> User:
    try:  # role is read from the DB, so role changes apply immediately
        user = s.get(User, int(jwt.decode(token, settings.jwt_secret, ["HS256"])["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        user = None
    if not user:
        raise HTTPException(401, "Invalid token", headers={"WWW-Authenticate": "Bearer"})
    return user


def require(*roles: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Insufficient role")
        return user

    return dep
