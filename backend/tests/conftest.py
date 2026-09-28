import os

os.environ.update(OPENAI_API_KEY="test-key", JWT_SECRET="t" * 32, DATABASE_URL="sqlite://")  # before app imports

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from helpers import headers, register  # noqa: E402
from limits import storage, strategies  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from app import ai, auth  # noqa: E402
from app.core import AuditLog, User, get_session  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    """App wired to in-memory SQLite (users + audit only) with the LLM and embeddings stubbed out."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(engine, tables=[User.__table__, AuditLog.__table__])

    def override():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = override
    monkeypatch.setattr(ai, "ingest", lambda s, source, text: 2)
    monkeypatch.setattr(ai, "run_agent", lambda s, q: (f"echo: {q}", ["SearchKB"]))
    monkeypatch.setattr(auth, "_limiter", strategies.MovingWindowRateLimiter(storage.MemoryStorage()))
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture()
def users(client):
    """admin, analyst and viewer accounts (ids 1, 2, 3) with ready-made auth headers."""
    for email in ("admin@corp.io", "analyst@corp.io", "viewer@corp.io"):
        register(client, email)
    admin = headers(client, "admin@corp.io")
    client.patch("/users/2/role", params={"role": "analyst"}, headers=admin)
    return {"admin": admin, "analyst": headers(client, "analyst@corp.io"), "viewer": headers(client, "viewer@corp.io")}
