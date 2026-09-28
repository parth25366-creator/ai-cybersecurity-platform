"""JWT auth + role-based access control."""
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from sqlmodel import Session

from .core import User, get_session, settings

ph = PasswordHash.recommended()  # argon2
oauth2 = OAuth2PasswordBearer(tokenUrl="auth/login")


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
