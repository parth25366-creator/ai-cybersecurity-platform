from datetime import datetime, timedelta, timezone

import jwt
from helpers import PW, login, register
from sqlmodel import select

from app.core import User, get_session, settings


# ---------- authentication ----------
def test_first_user_is_admin_and_later_users_are_viewers(client):
    assert register(client, "a@corp.io").json()["role"] == "admin"
    assert register(client, "b@corp.io").json()["role"] == "viewer"


def test_duplicate_email_is_rejected_case_insensitively(client):
    register(client, "a@corp.io")
    assert register(client, "A@Corp.io").status_code == 409


def test_weak_password_and_bad_email_are_rejected(client):
    assert register(client, "a@corp.io", "short").status_code == 422
    assert register(client, "not-an-email").status_code == 422


def test_registration_can_be_closed_after_bootstrap(client, monkeypatch):
    register(client, "a@corp.io")
    monkeypatch.setattr(settings, "open_registration", False)
    assert register(client, "b@corp.io").status_code == 403


def test_wrong_password_is_401(client):
    register(client, "a@corp.io")
    assert login(client, "a@corp.io", "wrong-password").status_code == 401


def test_login_is_rate_limited_per_account(client):
    register(client, "a@corp.io")
    codes = [login(client, "a@corp.io", "wrong-password").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]


def test_password_is_stored_as_argon2_hash(client):
    register(client, "a@corp.io")
    s = next(client.app.dependency_overrides[get_session]())
    stored = s.exec(select(User)).first().password_hash
    assert stored.startswith("$argon2") and PW not in stored


# ---------- token attacks ----------
def test_endpoints_require_a_token(client):
    assert client.post("/chat", json={"question": "hi"}).status_code == 401


def test_token_signed_with_wrong_key_is_rejected(client):
    register(client, "a@corp.io")
    forged = jwt.encode({"sub": "1", "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, "x" * 32, "HS256")
    r = client.post("/chat", json={"question": "hi"}, headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_alg_none_token_is_rejected(client):
    register(client, "a@corp.io")
    none_token = jwt.encode({"sub": "1"}, key="", algorithm="none")
    r = client.post("/chat", json={"question": "hi"}, headers={"Authorization": f"Bearer {none_token}"})
    assert r.status_code == 401


def test_expired_token_is_rejected(client):
    register(client, "a@corp.io")
    old = jwt.encode({"sub": "1", "exp": datetime.now(timezone.utc) - timedelta(seconds=5)}, settings.jwt_secret, "HS256")
    assert client.post("/chat", json={"question": "hi"}, headers={"Authorization": f"Bearer {old}"}).status_code == 401


# ---------- RBAC ----------
def test_viewer_cannot_ingest_but_analyst_can(client, users):
    body = {"source": "playbook", "text": "isolate hosts"}
    assert client.post("/kb", json=body, headers=users["viewer"]).status_code == 403
    assert client.post("/kb", json=body, headers=users["analyst"]).json() == {"chunks": 2}


def test_only_admin_can_read_audit_log_or_list_users(client, users):
    for path in ("/audit", "/users"):
        assert client.get(path, headers=users["analyst"]).status_code == 403
        assert client.get(path, headers=users["admin"]).status_code == 200


def test_role_changes_apply_to_existing_tokens(client, users):
    body = {"source": "s", "text": "t"}
    assert client.post("/kb", json=body, headers=users["viewer"]).status_code == 403
    client.patch("/users/3/role", params={"role": "analyst"}, headers=users["admin"])
    assert client.post("/kb", json=body, headers=users["viewer"]).status_code == 200


def test_invalid_role_is_rejected(client, users):
    r = client.patch("/users/3/role", params={"role": "root"}, headers=users["admin"])
    assert r.status_code == 422


# ---------- features ----------
def test_chat_returns_answer_and_writes_audit_entry(client, users):
    r = client.post("/chat", json={"question": "what is log4shell?"}, headers=users["viewer"])
    assert r.json() == {"answer": "echo: what is log4shell?", "tools_used": ["SearchKB"]}
    actions = [e["action"] for e in client.get("/audit", headers=users["admin"]).json()]
    assert "chat" in actions


def test_chat_is_rate_limited_per_user(client, users):
    codes = [client.post("/chat", json={"question": "hi"}, headers=users["viewer"]).status_code for _ in range(12)]
    assert codes[:10] == [200] * 10 and codes[10:] == [429, 429]


def test_upload_accepts_text_and_rejects_other_types(client, users):
    ok = client.post("/kb/upload", files={"file": ("notes.txt", b"isolate the host", "text/plain")}, headers=users["analyst"])
    assert ok.json() == {"chunks": 2}
    bad = client.post("/kb/upload", files={"file": ("evil.exe", b"MZ", "application/octet-stream")}, headers=users["analyst"])
    assert bad.status_code == 415


def test_upload_enforces_size_limit_and_role(client, users, monkeypatch):
    f = {"file": ("notes.txt", b"x" * 10, "text/plain")}
    assert client.post("/kb/upload", files=f, headers=users["viewer"]).status_code == 403
    monkeypatch.setattr(settings, "max_upload_mb", 0)
    assert client.post("/kb/upload", files=f, headers=users["analyst"]).status_code == 413


def test_upload_rejects_empty_documents(client, users):
    f = {"file": ("empty.md", b"   \n", "text/markdown")}
    assert client.post("/kb/upload", files=f, headers=users["analyst"]).status_code == 422


def test_health_and_metrics_endpoints(client):
    assert client.get("/health").json() == {"ok": True}
    assert "http_requests_total" in client.get("/metrics").text
