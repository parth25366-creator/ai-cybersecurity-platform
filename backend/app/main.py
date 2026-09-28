import time
from contextlib import asynccontextmanager
from typing import Literal

import structlog
from fastapi import Depends, FastAPI, HTTPException, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func
from sqlmodel import Session, select

from . import ai
from .auth import current_user, make_token, ph, rate_limit, require
from .core import AuditLog, User, get_session, init_db, settings

structlog.configure(processors=[
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.JSONRenderer(),  # JSON to stdout -> CloudWatch
])
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(_):
    init_db()
    yield


app = FastAPI(title="AI Cybersecurity Platform", lifespan=lifespan)
Instrumentator().instrument(app).expose(app)  # Prometheus /metrics


@app.middleware("http")
async def access_log(req, call_next):
    t = time.perf_counter()
    res = await call_next(req)
    log.info("request", method=req.method, path=req.url.path, status=res.status_code,
             ms=round((time.perf_counter() - t) * 1000))
    return res


def audit(s: Session, u: User, action: str, detail: str = ""):
    s.add(AuditLog(user_id=u.id, action=action, detail=detail[:500]))
    s.commit()


class Creds(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class Doc(BaseModel):
    source: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1)


class Ask(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/register", status_code=201)
def register(c: Creds, s: Session = Depends(get_session)):
    email = c.email.lower()
    first = s.exec(select(User)).first() is None  # first user bootstraps as admin
    if not first and not settings.open_registration:
        raise HTTPException(403, "Registration is closed")
    if s.exec(select(User).where(func.lower(User.email) == email)).first():
        raise HTTPException(409, "Email already registered")
    u = User(email=email, password_hash=ph.hash(c.password), role="admin" if first else "viewer")
    s.add(u)
    s.commit()
    return {"id": u.id, "role": u.role}


@app.post("/auth/login")
def login(f: OAuth2PasswordRequestForm = Depends(), s: Session = Depends(get_session)):
    rate_limit("5/minute", "login", f.username.lower())  # blunts password guessing per account
    u = s.exec(select(User).where(func.lower(User.email) == f.username.lower())).first()
    if not u or not ph.verify(f.password, u.password_hash):
        log.warning("login_failed", email=f.username.lower())
        raise HTTPException(401, "Bad credentials")
    return {"access_token": make_token(u), "token_type": "bearer", "role": u.role}


@app.get("/users")
def list_users(_: User = Depends(require("admin")), s: Session = Depends(get_session)):
    return [{"id": u.id, "email": u.email, "role": u.role} for u in s.exec(select(User)).all()]


@app.patch("/users/{uid}/role")
def set_role(uid: int, role: Literal["admin", "analyst", "viewer"],
             admin: User = Depends(require("admin")), s: Session = Depends(get_session)):
    u = s.get(User, uid)
    if not u:
        raise HTTPException(404)
    u.role = role
    s.commit()
    audit(s, admin, "set_role", f"user={uid} role={role}")
    return {"id": uid, "role": role}


def _ingest(s: Session, u: User, source: str, text: str) -> dict:
    try:
        n = ai.ingest(s, source, text)
    except ValueError as e:
        raise HTTPException(413, str(e))
    audit(s, u, "kb_ingest", f"{source}: {n} chunks")
    return {"chunks": n}


@app.post("/kb")
def add_doc(d: Doc, u: User = Depends(require("admin", "analyst")), s: Session = Depends(get_session)):
    return _ingest(s, u, d.source, d.text)


@app.post("/kb/upload")
def upload_doc(file: UploadFile, u: User = Depends(require("admin", "analyst")), s: Session = Depends(get_session)):
    limit = settings.max_upload_mb * 1024 * 1024
    name = file.filename or ""
    if not name.lower().endswith((".pdf", ".txt", ".md")):
        raise HTTPException(415, "Only .pdf, .txt and .md files are supported")
    data = file.file.read(limit + 1)  # never buffer more than the limit
    if len(data) > limit:
        raise HTTPException(413, f"File larger than {settings.max_upload_mb} MB")
    text = ai.extract_text(name, data)
    if not text.strip():
        raise HTTPException(422, "No extractable text in file")
    return _ingest(s, u, name[:200], text)


@app.post("/chat")
def chat(a: Ask, u: User = Depends(current_user), s: Session = Depends(get_session)):
    rate_limit("10/minute", "chat", str(u.id))  # each call spends LLM quota
    answer, tools = ai.run_agent(s, a.question)
    audit(s, u, "chat", f"q={a.question[:200]!r} tools={tools}")
    return {"answer": answer, "tools_used": tools}


@app.get("/audit")
def audit_log(_: User = Depends(require("admin")), s: Session = Depends(get_session)):
    return s.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(100)).all()
