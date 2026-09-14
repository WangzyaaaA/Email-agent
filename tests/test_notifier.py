from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.models import NotificationStatus
from app.services import notifier
from app.services.notifier import (
    _as_utc,
    enqueue_notification,
    flush_notifications,
    important_html,
    otp_html,
    quiet_hours_end,
)


def _settings():
    return SimpleNamespace(timezone="Asia/Shanghai", master_key="test-master-key")


def test_quiet_hours_boundaries_in_shanghai(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "get_settings", _settings)
    # 22:29 is still sendable; 22:30 begins quiet hours.
    assert quiet_hours_end(datetime(2025, 1, 1, 14, 29, tzinfo=timezone.utc)) is None
    assert quiet_hours_end(datetime(2025, 1, 1, 14, 30, tzinfo=timezone.utc)) == datetime(2025, 1, 1, 23, 30, tzinfo=timezone.utc)
    # 07:29 is quiet; 07:30 is sendable.
    assert quiet_hours_end(datetime(2025, 1, 1, 23, 29, tzinfo=timezone.utc)) == datetime(2025, 1, 1, 23, 30, tzinfo=timezone.utc)
    assert quiet_hours_end(datetime(2025, 1, 1, 23, 30, tzinfo=timezone.utc)) is None


def test_as_utc_normalizes_naive_and_aware_datetimes() -> None:
    naive = _as_utc(datetime(2025, 1, 1, 1, 2, 3))
    aware = _as_utc(datetime(2025, 1, 1, 9, 2, 3, tzinfo=timezone(timedelta(hours=8))))
    assert naive.tzinfo == timezone.utc
    assert aware == datetime(2025, 1, 1, 1, 2, 3, tzinfo=timezone.utc)


def test_html_builders_escape_untrusted_fields() -> None:
    html = otp_html("<source>", "12'34", "<time>", "<expiry>", "unknown")
    assert "&lt;source&gt;" in html
    assert "12&#x27;34" in html
    assert "&lt;time&gt;" in html
    assert "认证结果缺失" in html
    assert "onclick" not in html
    important = important_html("<title>", "<summary>", "<reason>", "<deadline>")
    assert "&lt;title&gt;" in important
    assert "&lt;summary&gt;" in important
    assert "&lt;reason&gt;" in important
    assert "&lt;deadline&gt;" in important


def test_enqueue_is_idempotent_and_respects_quiet_hours(db, monkeypatch) -> None:
    monkeypatch.setattr(notifier, "get_settings", _settings)
    monkeypatch.setattr(notifier, "utcnow", lambda: datetime(2025, 1, 1, 14, 30, tzinfo=timezone.utc))
    first = enqueue_notification(
        db,
        kind="important",
        priority="normal",
        title="title",
        html_content="<p>secret body</p>",
        preview="redacted",
        dedupe_key="message:1",
    )
    second = enqueue_notification(
        db,
        kind="important",
        priority="normal",
        title="duplicate",
        html_content="different",
        preview="different",
        dedupe_key="message:1",
    )
    assert second.id == first.id
    assert first.next_attempt_at == datetime(2025, 1, 1, 23, 30, tzinfo=timezone.utc)
    assert first.content_preview == "redacted"


def test_flush_notifications_sends_and_erases_encrypted_payload(db, monkeypatch) -> None:
    monkeypatch.setattr(notifier, "get_settings", _settings)
    monkeypatch.setattr(notifier, "all_settings", lambda db, keys: {"wxpusher_app_token": "app", "wxpusher_uid": "uid"})
    monkeypatch.setattr(notifier, "utcnow", lambda: datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc))
    captured = {}

    def fake_send(token, uid, content, summary):
        captured.update(token=token, uid=uid, content=content, summary=summary)
        return "record-1"

    monkeypatch.setattr(notifier, "_send_wxpusher", fake_send)
    row = enqueue_notification(
        db,
        kind="test",
        priority="critical",
        title="Test",
        html_content="<p>private body</p>",
        preview="safe preview",
        dedupe_key="flush:1",
        bypass_quiet=True,
    )
    assert flush_notifications(db) == 1
    assert captured["content"] == "<p>private body</p>"
    assert row.status == NotificationStatus.SENT.value
    assert row.external_id == "record-1"
    assert row.payload_encrypted is None


def test_slow_send_cannot_make_the_next_notification_send_after_expiry(db, monkeypatch) -> None:
    clock = [datetime(2026, 9, 14, 12, tzinfo=timezone.utc)]
    monkeypatch.setattr(notifier, "utcnow", lambda: clock[0])
    monkeypatch.setattr(notifier, "all_settings", lambda *_: {"wxpusher_app_token": "test", "wxpusher_uid": "test"})
    calls = []

    def send(*args):
        calls.append(args)
        clock[0] += timedelta(minutes=2)
        return "test-record"

    monkeypatch.setattr(notifier, "_send_wxpusher", send)
    for _ in range(2):
        row = enqueue_notification(db, kind="otp", priority="critical", title="测试", html_content="synthetic", preview="masked", expires_at=clock[0] + timedelta(minutes=1))
    db.commit()
    assert flush_notifications(db) == 1
    assert len(calls) == 1
    assert row.status == "expired" and row.payload_encrypted is None


def test_flush_notifications_expires_without_network(db, monkeypatch) -> None:
    monkeypatch.setattr(notifier, "get_settings", _settings)
    now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(notifier, "utcnow", lambda: now)
    monkeypatch.setattr(notifier, "_send_wxpusher", lambda *args: (_ for _ in ()).throw(AssertionError("must not send expired notification")))
    row = enqueue_notification(
        db,
        kind="test",
        priority="critical",
        title="Expired",
        html_content="private",
        preview="expired",
        expires_at=datetime(2025, 1, 1, 11, 59, tzinfo=timezone.utc),
        bypass_quiet=True,
    )
    assert flush_notifications(db) == 0
    assert row.status == NotificationStatus.EXPIRED.value
    assert row.payload_encrypted is None
