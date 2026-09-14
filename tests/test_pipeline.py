from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import pytest
from sqlalchemy import select

from app.mail.types import RemoteMessage
from app.models import ActionItem, MailboxAccount, MessageMetadata, Notification, OtpCandidate, ProcessingJob, Rule
from app.security import Cipher
from app.services import pipeline
from app.services.classifier import ClassificationResult
from app.services.notifier import _fallback_allowed
from app.services.pipeline import process_remote_message, retry_processing_jobs
from app.store import set_setting


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


def _remote(uid: int, auth: str, body: str, historical: bool = False, subject: str = "登录验证码", sender_name: str = "Example") -> RemoteMessage:
    message = EmailMessage()
    message["From"] = f"{sender_name} <security@example.com>"
    message["To"] = "me@gmail.com"
    message["Subject"] = subject
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


@pytest.mark.parametrize("approved, auth, historical", [
    (True, "mx.google.com; dkim=pass", False),
    (False, "mx.google.com; dkim=pass", False),
    (True, "mx.google.com; dkim=fail", False),
    (True, "mx.google.com; dkim=pass", True),
])
@pytest.mark.parametrize("subject", ["验证码：A7B8C9", "A7B8C9 is your verification code"])
def test_otp_in_subject_never_persists_in_metadata(db, approved, auth, historical, subject) -> None:
    account = _account(db)
    if approved:
        db.add(Rule(kind="otp_address", value="security@example.com"))
        db.flush()
    message = process_remote_message(db, account, _remote(10, auth, "请核对登录请求", historical, subject, "Example A7B8C9"))
    message_id = message.id
    db.expire_all()
    message = db.get(MessageMetadata, message_id)
    for value in (message.subject, message.from_name, message.summary, message.reason, message.thread_key):
        assert "A7B8C9" not in value
    for row in db.scalars(select(Notification)).all():
        assert "A7B8C9" not in row.title and "A7B8C9" not in row.content_preview
        content = Cipher().decrypt_json(row.payload_encrypted)["content"]
        if row.kind == "otp":
            assert approved and not historical and "fail" not in auth
            assert "A7B8C9" in content
        else:
            assert "A7B8C9" not in content


def test_model_is_deferred_and_security_outbox_stays_idempotent(db, monkeypatch) -> None:
    account = _account(db)
    calls = []

    class Model:
        def classify(self, sender, text):
            calls.append(text)
            assert db.scalar(select(Notification)).kind == "security"
            return ClassificationResult(category="work", importance="low", summary="云摘要")

    monkeypatch.setattr(pipeline, "configured_classifier", lambda _: Model())
    remote = _remote(11, "mx.google.com; dkim=pass", "请检查本次登录 password: PrivateReviewSecret", subject="异地登录安全告警")
    message = process_remote_message(db, account, remote)
    assert calls == []
    assert message.llm_status == "pending"
    notification = db.scalar(select(Notification))
    assert notification.kind == "security" and _fallback_allowed(notification)
    job = db.scalar(select(ProcessingJob))
    assert "PrivateReviewSecret" not in Cipher().decrypt_json(job.payload_encrypted)["sanitized_text"]
    assert process_remote_message(db, account, remote).id == message.id
    assert len(db.scalars(select(ProcessingJob)).all()) == 1
    assert retry_processing_jobs(db) == 1
    assert len(calls) == 1 and "PrivateReviewSecret" not in calls[0]
    assert message.category == "security" and message.importance == "critical"
    assert message.llm_status == "complete"
    assert db.scalar(select(ProcessingJob)) is None
    assert len(db.scalars(select(Notification)).all()) == 1
    assert retry_processing_jobs(db) == 0


def test_model_failure_does_not_hold_up_following_otp_and_payload_expires(db, monkeypatch) -> None:
    account = _account(db)
    db.add(Rule(kind="otp_address", value="security@example.com"))
    db.flush()
    clock = [datetime(2026, 9, 14, 12, tzinfo=timezone.utc)]
    calls = []

    class Model:
        def classify(self, *_):
            calls.append(True)
            raise ValueError("synthetic private response")

    monkeypatch.setattr(pipeline, "configured_classifier", lambda _: Model())
    monkeypatch.setattr(pipeline, "utcnow", lambda: clock[0])
    ordinary = process_remote_message(db, account, _remote(12, "mx.google.com; dkim=pass", "普通消息", subject="问候"))
    otp = process_remote_message(db, account, _remote(13, "mx.google.com; dkim=pass", "验证码：678901"))
    assert calls == [] and otp.category == "otp"
    assert db.scalar(select(Notification)).kind == "otp"
    assert retry_processing_jobs(db) == 0
    assert len(calls) == 1 and ordinary.llm_status == "retrying"
    job = db.scalar(select(ProcessingJob))
    assert "synthetic private response" not in job.last_error
    assert retry_processing_jobs(db) == 0
    assert len(calls) == 1
    clock[0] += timedelta(hours=25)
    assert retry_processing_jobs(db) == 0
    assert len(calls) == 1 and ordinary.llm_status == "expired"
    assert db.scalar(select(ProcessingJob)) is None


def test_historical_mail_never_enqueues_model_work_or_alerts(db, monkeypatch) -> None:
    account = _account(db)
    monkeypatch.setattr(pipeline, "configured_classifier", lambda _: object())
    message = process_remote_message(db, account, _remote(14, "mx.google.com; dkim=pass", "异地登录", True, "安全告警"))
    assert message.importance == "critical"
    assert db.scalar(select(Notification)) is None
    assert db.scalar(select(ProcessingJob)) is None


def test_legacy_http_model_configuration_keeps_local_rules_running(db, monkeypatch) -> None:
    account = _account(db)
    for key, value in {"llm_base_url": "http://llm.example/v1", "llm_api_key": "private", "llm_model": "model"}.items():
        set_setting(db, key, value)
    db.commit()
    monkeypatch.setattr(pipeline, "safe_cloud_classify", lambda *_: pytest.fail("unsafe model must stay disabled"))
    message = process_remote_message(db, account, _remote(15, "mx.google.com; dkim=pass", "异地登录", subject="安全告警"))
    assert message.category == "security"
    assert db.scalar(select(Notification)).kind == "security"
    assert db.scalar(select(ProcessingJob)) is None


def test_processing_worker_keeps_existing_single_process_lock(db, monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "_retry_processing_jobs_locked", lambda *_: pytest.fail("worker must not overlap"))
    with pipeline._processing_lock:
        assert retry_processing_jobs(db) == 0


def test_subject_fallback_is_private_and_supports_legacy_followups(db) -> None:
    account = _account(db)
    mail = EmailMessage()
    mail["From"] = "me@example.com"
    mail["To"] = "partner@example.com"
    mail["Subject"] = "请回复 password: PrivateReviewSecret"
    mail.set_content("请回复确认")
    remote = RemoteMessage("Sent", "sent", "1", 16, mail.as_bytes(), datetime(2026, 9, 14, 12, tzinfo=timezone.utc), False)
    message = process_remote_message(db, account, remote)
    item = db.scalar(select(ActionItem))
    assert message.message_id is None
    assert item.thread_key.startswith("subject-hmac:")
    assert "PrivateReviewSecret" not in item.thread_key + item.title + message.subject + message.summary
    pipeline._complete_replied_followups(db, [], None, "Re: 请回复 password: PrivateReviewSecret")
    assert item.status == "done"
    old = ActionItem(kind="followup", title="旧事项", thread_key="subject:project update")
    db.add(old)
    db.flush()
    pipeline._complete_replied_followups(db, [], None, "Re: Project update")
    assert old.status == "done"


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
