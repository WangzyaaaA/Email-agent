from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from app import main
from app.store import set_setting


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    main.login_throttle.reset("testclient")
    yield
    main.login_throttle.reset("testclient")


@pytest.fixture
def client(db):
    previous = main.app.dependency_overrides.copy()
    main.app.dependency_overrides[main.get_db] = lambda: db
    client = TestClient(main.app, follow_redirects=False)
    session = base64.b64encode(json.dumps({"admin": True, "csrf_token": "review-csrf"}).encode())
    client.cookies.set("session", TimestampSigner(main.session_secret).sign(session).decode())
    try:
        yield client
    finally:
        client.close()
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(previous)


def test_admin_pages_send_strict_security_headers(client) -> None:
    response = client.get("/dashboard")
    assert response.status_code == 200
    policy = response.headers["content-security-policy"]
    assert policy.startswith("default-src 'self'")
    assert "script-src 'self'" in policy and "'unsafe-inline'" not in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in response.headers["permissions-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_templates_use_delegated_script_instead_of_inline_handlers(client) -> None:
    page = client.get("/dashboard")
    assert "onclick=" not in page.text
    assert "/static/app.js" in page.text

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert "toggle-sidebar" in script.text


def test_login_locks_out_repeated_failures_without_verifying_again(client, db, monkeypatch) -> None:
    set_setting(db, "admin_password_hash", "stored-hash")
    db.commit()
    attempts: list[str] = []

    def reject(_encoded: str, password: str) -> bool:
        attempts.append(password)
        return False

    monkeypatch.setattr(main, "verify_password", reject)
    for _ in range(4):
        response = client.post("/login", data={"password": "guess", "csrf_token": "review-csrf"})
        assert response.status_code == 400 and "密码错误" in response.text

    locked = client.post("/login", data={"password": "guess", "csrf_token": "review-csrf"})
    assert locked.status_code == 429
    refused = client.post("/login", data={"password": "correct horse", "csrf_token": "review-csrf"})
    assert refused.status_code == 429
    # A locked source must not keep spending Argon2 time on password guesses.
    assert len(attempts) == 5


def test_successful_login_clears_the_failure_history(client, db, monkeypatch) -> None:
    set_setting(db, "admin_password_hash", "stored-hash")
    db.commit()
    monkeypatch.setattr(main, "verify_password", lambda _encoded, password: password == "right-password")

    for _ in range(4):
        assert client.post("/login", data={"password": "wrong", "csrf_token": "review-csrf"}).status_code == 400

    assert client.post("/login", data={"password": "right-password", "csrf_token": "review-csrf"}).status_code == 303
    assert main.login_throttle.blocked_for("testclient") == 0
    assert main.login_throttle.tracked_sources == 0
