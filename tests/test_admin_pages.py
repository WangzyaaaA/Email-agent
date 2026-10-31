from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from app import main
from app.models import (
    ActionItem,
    DigestRun,
    MailboxAccount,
    MessageMetadata,
    Notification,
    OtpCandidate,
    Rule,
)
from app.security import Cipher, hash_password
from app.store import set_setting

FORWARDED_ADDRESS = "203.0.113.9"
SPOOFED_ADDRESS = "198.51.100.7"
LOCAL_TIME_PATTERN = re.compile(r"\d{2}-\d{2} \d{2}:\d{2}")


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    for source in ("testclient", FORWARDED_ADDRESS, SPOOFED_ADDRESS):
        main.login_throttle.reset(source)
    yield
    for source in ("testclient", FORWARDED_ADDRESS, SPOOFED_ADDRESS):
        main.login_throttle.reset(source)


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


def _mailbox(db, *, status: str = "healthy", last_sync_at: datetime | None = None) -> MailboxAccount:
    account = MailboxAccount(
        name="主邮箱",
        email_address="owner@example.com",
        provider="gmail",
        imap_host="imap.example.com",
        username="owner@example.com",
        password_encrypted="unused",
        host_confirmed=True,
        enabled=True,
        status=status,
        last_sync_at=last_sync_at,
    )
    db.add(account)
    db.commit()
    return account


def _message(db, account: MailboxAccount, *, uid: int, received_at: datetime, subject: str = "登录验证码") -> MessageMetadata:
    row = MessageMetadata(
        account_id=account.id,
        folder="INBOX",
        uidvalidity="1",
        uid=uid,
        message_id=f"<message-{uid}@example.com>",
        subject=subject,
        received_at=received_at,
        from_address="security@example.com",
        from_name="账户安全",
    )
    db.add(row)
    db.commit()
    return row


def test_dashboard_reports_today_totals_and_overdue_without_truncation(client, db) -> None:
    now = datetime.now(timezone.utc)
    account = _mailbox(db, last_sync_at=now)
    _message(db, account, uid=1, received_at=now)
    _message(db, account, uid=2, received_at=now - timedelta(days=2))
    _message(db, account, uid=3, received_at=now - timedelta(days=2))
    for index in range(8):
        db.add(ActionItem(kind="deadline", title=f"逾期事项{index}", status="new", due_at=now - timedelta(hours=3)))
    db.add(ActionItem(kind="deadline", title="未来事项", status="new", due_at=now + timedelta(days=2)))
    db.add(ActionItem(kind="deadline", title="已办事项", status="done", due_at=now - timedelta(days=1)))
    db.commit()

    page = client.get("/dashboard")

    assert page.status_code == 200
    assert "较昨日 +1" in page.text
    assert "9" in page.text  # pending actions include the eight overdue rows and the future one
    assert "8 项已逾期" in page.text
    assert "尚未同步" not in page.text
    assert "最近同步" in page.text
    assert "已逾期 ·" in page.text
    assert LOCAL_TIME_PATTERN.search(page.text)


def test_actions_page_filters_status_and_renders_due_dates(client, db) -> None:
    now = datetime.now(timezone.utc)
    db.add(ActionItem(kind="deadline", title="逾期待办", status="new", due_at=now - timedelta(hours=1)))
    db.add(ActionItem(kind="deadline", title="已完成待办", status="done", due_at=now + timedelta(days=1)))
    db.commit()

    page = client.get("/actions")
    filtered = client.get("/actions?status=done")

    assert page.status_code == 200
    assert "逾期待办" in page.text and "已逾期 ·" in page.text
    assert "无截止时间" not in page.text
    assert filtered.status_code == 200
    assert "已完成待办" in filtered.text and "逾期待办" not in filtered.text
    assert 'value="done" selected' in filtered.text


def test_mailbox_page_shows_local_sync_time_and_status_label(client, db) -> None:
    now = datetime.now(timezone.utc)
    _mailbox(db, status="connected", last_sync_at=now)

    page = client.get("/mailboxes")

    assert page.status_code == 200
    assert "已连接" in page.text
    assert "尚未同步" not in page.text
    assert LOCAL_TIME_PATTERN.search(page.text)


def test_otp_page_joins_mail_subject_and_labels_risk(client, db) -> None:
    now = datetime.now(timezone.utc)
    account = _mailbox(db)
    message = _message(db, account, uid=9, received_at=now, subject="登录验证码提醒")
    db.add(
        OtpCandidate(
            message_id=message.id,
            sender_address="security@example.com",
            sender_domain="example.com",
            code_fingerprint="fingerprint-value",
            status="pending",
            risk="unknown_auth",
        )
    )
    db.commit()

    page = client.get("/otp-candidates")

    assert page.status_code == 200
    assert "登录验证码提醒" in page.text
    assert "认证未知" in page.text
    assert LOCAL_TIME_PATTERN.search(page.text)


def test_notification_page_uses_chinese_status_and_send_time(client, db) -> None:
    now = datetime.now(timezone.utc)
    db.add(
        Notification(
            kind="otp",
            priority="critical",
            title="验证码已发送",
            status="sent",
            channel="wxpusher",
            sent_at=now,
        )
    )
    db.commit()

    page = client.get("/notifications")

    assert page.status_code == 200
    assert "验证码" in page.text and "紧急" in page.text and "已发送" in page.text
    assert LOCAL_TIME_PATTERN.search(page.text)


def test_digest_page_shows_type_and_linked_notification_status(client, db) -> None:
    notification = Notification(kind="digest", priority="normal", title="今日邮箱总结", status="failed")
    db.add(notification)
    db.flush()
    db.add(
        DigestRun(
            period_key="2026-10-31:daily",
            digest_types="daily",
            title="今日邮箱总结",
            item_count=3,
            notification_id=notification.id,
        )
    )
    db.commit()

    page = client.get("/digests")

    assert page.status_code == 200
    assert "每日总结" in page.text
    assert "发送失败" in page.text


def test_mailbox_update_reports_master_key_mismatch_instead_of_crashing(client, db) -> None:
    account = _mailbox(db)
    account.password_encrypted = Cipher(master_key="another-master-key-" + "y" * 32).encrypt("secret")
    db.commit()

    response = client.post(
        f"/mailboxes/{account.id}/edit",
        data={
            "name": "主邮箱",
            "email_address": "owner@example.com",
            "provider": "gmail",
            "imap_host": "imap.example.com",
            "imap_port": "993",
            "username": "owner@example.com",
            "password": "",
            "host_confirmed": "yes",
            "csrf_token": "review-csrf",
        },
    )

    assert response.status_code == 400
    assert "主密钥" in response.text


def test_rules_page_labels_kinds_without_exposing_raw_enum(client, db) -> None:
    db.add(Rule(kind="otp_domain", value="example.com"))
    db.commit()

    page = client.get("/rules")

    assert page.status_code == 200
    assert "验证码域名" in page.text
    assert "example.com" in page.text


def test_detect_api_returns_400_for_invalid_address(client) -> None:
    response = client.post(
        "/api/mailboxes/detect",
        json={"email_address": "not-an-email"},
        headers={"X-CSRF-Token": "review-csrf"},
    )

    assert response.status_code == 400
    assert "detail" in response.json()


def test_detected_mailbox_form_posts_to_create_not_update(client) -> None:
    response = client.post(
        "/mailboxes/new/detect",
        data={"email_address": "someone@gmail.com", "csrf_token": "review-csrf"},
    )

    assert response.status_code == 200
    assert 'action="http://testserver/mailboxes"' in response.text
    assert "/mailboxes//edit" not in response.text


def test_retry_failed_only_schedules_and_never_sends_inside_request(client, db, monkeypatch) -> None:
    db.add(
        Notification(
            kind="otp",
            priority="critical",
            title="待重试验证码",
            status="failed",
            payload_encrypted=Cipher().encrypt_json({"content": "<p>stub</p>"}),
        )
    )
    db.commit()
    calls: list[tuple] = []
    monkeypatch.setattr(main, "flush_notifications", lambda *args, **kwargs: calls.append(args) or 0)

    response = client.post("/notifications/retry-failed", data={"csrf_token": "review-csrf"})

    assert response.status_code == 303
    assert calls == []
    row = db.query(Notification).one()
    assert row.status == "pending"


def test_login_throttle_uses_forwarded_address_only_when_opted_in(client, db, monkeypatch) -> None:
    set_setting(db, "admin_password_hash", hash_password("correct-horse-battery"))
    db.commit()
    monkeypatch.setattr(main.settings, "trusted_proxy_headers", True)

    last = None
    for _ in range(5):
        last = client.post(
            "/login",
            data={"password": "wrong-password", "csrf_token": "review-csrf"},
            headers={"X-Forwarded-For": FORWARDED_ADDRESS},
        )

    assert last is not None and last.status_code == 429
    assert main.login_throttle.blocked_for(FORWARDED_ADDRESS) > 0
    assert main.login_throttle.blocked_for("testclient") == 0

    monkeypatch.setattr(main.settings, "trusted_proxy_headers", False)
    client.post(
        "/login",
        data={"password": "wrong-password", "csrf_token": "review-csrf"},
        headers={"X-Forwarded-For": SPOOFED_ADDRESS},
    )
    assert main.login_throttle.blocked_for(SPOOFED_ADDRESS) == 0
