from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage

from sqlalchemy import select

from app.mail.types import RemoteMessage
from app.models import MailboxAccount, Notification, OtpCandidate, Rule
from app.security import Cipher
from app.services.pipeline import process_remote_message


def _account(db) -> MailboxAccount:
    account = MailboxAccount(
        name="Gmail",
        email_address="me@gmail.com",
        provider="gmail",
        imap_host="imap.gmail.com",
        imap_port=993,
        username="me@gmail.com",
        password_encrypted=Cipher("test-key").encrypt("password"),
        host_confirmed=True,
    )
    db.add(account)
    db.flush()
    return account


def _remote(uid: int, auth: str, body: str, historical: bool = False) -> RemoteMessage:
    message = EmailMessage()
    message["From"] = "Example <security@example.com>"
    message["To"] = "me@gmail.com"
    message["Subject"] = "登录验证码"
    message["Message-ID"] = f"<{uid}@example.com>"
    message["Authentication-Results"] = auth
    message.set_content(body)
    return RemoteMessage(
        folder="INBOX",
        folder_role="inbox",
        uidvalidity="1",
        uid=uid,
        raw=message.as_bytes(),
        internal_date=datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc),
        historical=historical,
    )


def test_trusted_otp_queues_only_an_encrypted_short_lived_notification(db) -> None:
    account = _account(db)
    db.add(Rule(kind="otp_address", value="security@example.com"))
    db.flush()
    message = process_remote_message(
        db,
        account,
        _remote(1, "mx.google.com; spf=pass; dkim=pass", "您的验证码为 123456，有效期 5 分钟。"),
    )
    assert message is not None and message.category == "otp"
    candidate = db.scalar(select(OtpCandidate))
    notification = db.scalar(select(Notification))
    assert candidate is not None and candidate.status == "approved" and len(candidate.code_fingerprint) == 64
    assert notification is not None and notification.payload_encrypted
    assert "123456" not in notification.content_preview
    assert "123456" not in notification.payload_encrypted
    assert Cipher().decrypt_json(notification.payload_encrypted)["content"].count("123456") >= 1


def test_unknown_or_failed_otp_never_queues_the_code(db) -> None:
    account = _account(db)
    process_remote_message(
        db,
        account,
        _remote(2, "attacker.invalid; spf=pass", "验证码：654321"),
    )
    candidate = db.scalar(select(OtpCandidate).where(OtpCandidate.message_id.is_not(None)))
    assert candidate is not None and candidate.status == "pending"
    assert db.scalar(select(Notification)) is None


def test_historical_otp_does_not_backfill_notifications(db) -> None:
    account = _account(db)
    db.add(Rule(kind="otp_address", value="security@example.com"))
    db.flush()
    process_remote_message(
        db,
        account,
        _remote(3, "mx.google.com; dkim=pass", "验证码为 777777", historical=True),
    )
    assert db.scalar(select(Notification)) is None
