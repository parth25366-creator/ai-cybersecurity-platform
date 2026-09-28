import time
from contextlib import asynccontextmanager
from typing import Literal

import structlog
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from prometheus_fastapi_instrumentator import Instrumentator
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from . import ai
from .auth import current_user, make_token, ph, require
from .core import AuditLog, User, get_session, init_db

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
    email: str
    password: str = Field(min_length=10)


class Doc(BaseModel):
    source: str
    text: str


class Ask(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/register", status_code=201)
def register(c: Creds, s: Session = Depends(get_session)):
    if s.exec(select(User).where(User.email == c.email)).first():
        raise HTTPException(409, "Email already registered")
    first = s.exec(select(User)).first() is None  # first user bootstraps as admin
    u = User(email=c.email, password_hash=ph.hash(c.password), role="admin" if first else "viewer")
    s.add(u)
    s.commit()
    return {"id": u.id, "role": u.role}


@app.post("/auth/login")
def login(f: OAuth2PasswordRequestForm = Depends(), s: Session = Depends(get_session)):
    u = s.exec(select(User).where(User.email == f.username)).first()
    if not u or not ph.verify(f.password, u.password_hash):
        raise HTTPException(401, "Bad credentials")
    return {"access_token": make_token(u), "token_type": "bearer", "role": u.role}


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


@app.post("/kb")
def add_doc(d: Doc, u: User = Depends(require("admin", "analyst")), s: Session = Depends(get_session)):
    n = ai.ingest(s, d.source, d.text)
    audit(s, u, "kb_ingest", f"{d.source}: {n} chunks")
    return {"chunks": n}


@app.post("/chat")
def chat(a: Ask, u: User = Depends(current_user), s: Session = Depends(get_session)):
    answer, tools = ai.run_agent(s, a.question)
    audit(s, u, "chat", f"q={a.question[:200]!r} tools={tools}")
    return {"answer": answer, "tools_used": tools}


@app.get("/audit")
def audit_log(_: User = Depends(require("admin")), s: Session = Depends(get_session)):
    return s.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(100)).all()
