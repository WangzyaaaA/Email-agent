import base64
import json

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from app import main
from app.models import MailboxAccount
from app.store import get_setting, has_admin, set_setting


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


@pytest.mark.parametrize("url", ["http://llm.example/v1", "https://user:PrivateReviewSecret@llm.example/v1"])
def test_settings_reject_unsafe_model_url_atomically(client, db, url) -> None:
    response = client.post("/settings", data={
        "csrf_token": "review-csrf", "model_base_url": url,
        "model_api_key": "PrivateReviewSecret", "wxpusher_app_token": "other-test-value",
    })
    assert response.status_code == 400 and "HTTPS" in response.text
    assert "PrivateReviewSecret" not in response.text
    assert get_setting(db, "llm_base_url") is None
    assert get_setting(db, "wxpusher_app_token") is None


def test_setup_rejects_http_before_creating_administrator(client, db) -> None:
    response = client.post("/setup", data={
        "csrf_token": "review-csrf", "admin_password": "a-strong-test-password",
        "admin_password_confirm": "a-strong-test-password", "llm_base_url": "http://llm.example/v1",
    })
    assert response.status_code == 400
    assert not has_admin(db)


def test_settings_save_https_and_keep_csrf_and_login_boundaries(client, db) -> None:
    data = {"csrf_token": "wrong", "model_base_url": "https://llm.example/v1/"}
    assert client.post("/settings", data=data).status_code == 403
    assert get_setting(db, "llm_base_url") is None
    data["csrf_token"] = "review-csrf"
    assert client.post("/settings", data=data).status_code == 303
    assert get_setting(db, "llm_base_url") == "https://llm.example/v1"
    client.cookies.clear()
    response = client.post("/settings", data=data)
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_legacy_unsafe_model_url_has_a_safe_warning(client, db) -> None:
    set_setting(db, "llm_base_url", "https://user:PrivateReviewSecret@llm.example/v1")
    db.commit()
    response = client.get("/settings")
    assert response.status_code == 200
    assert "云分类已暂停" in response.text and "PrivateReviewSecret" not in response.text


def test_manual_sync_uses_existing_monitor_signal(client, db, monkeypatch) -> None:
    account = MailboxAccount(name="Test", email_address="user@example.com", provider="gmail", imap_host="imap.example.com", username="user", password_encrypted="unused", host_confirmed=True)
    db.add(account)
    db.commit()
    calls = []
    monkeypatch.setattr(main.monitor_manager, "request_sync", calls.append)
    assert client.post(f"/mailboxes/{account.id}/sync", data={"csrf_token": "wrong"}).status_code == 403
    assert calls == []
    assert client.post(f"/mailboxes/{account.id}/sync", data={"csrf_token": "review-csrf"}).status_code == 303
    assert calls == [account.id]
