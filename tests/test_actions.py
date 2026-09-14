from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import ActionItem, Notification
from app.services import actions, notifier


NOW = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)


@pytest.mark.parametrize("hours, priority", [(-1, None), (0, None), (1, "critical"), (2, "critical"), (3, "high"), (24, "high"), (25, None)])
def test_deadline_windows_are_exclusive_and_repeat_safe(db, monkeypatch, hours, priority) -> None:
    monkeypatch.setattr(actions, "utcnow", lambda: NOW)
    monkeypatch.setattr(notifier, "utcnow", lambda: NOW)
    item = ActionItem(kind="deadline", title="待办", due_at=NOW + timedelta(hours=hours))
    db.add(item)
    db.commit()
    assert actions.run_action_reminders(db) == (1 if priority else 0)
    assert actions.run_action_reminders(db) == 0
    rows = db.scalars(select(Notification)).all()
    assert [row.priority for row in rows] == ([priority] if priority else [])
    if hours <= 2:
        assert item.reminder_24_sent and item.reminder_2_sent
    if rows:
        expiry = notifier._as_utc(rows[0].expires_at)
        assert expiry == NOW + timedelta(hours=hours if priority == "critical" else hours - 2)


def test_entering_urgent_window_expires_old_reminder_and_queues_one_urgent_alert(db, monkeypatch) -> None:
    clock = [NOW]
    monkeypatch.setattr(actions, "utcnow", lambda: clock[0])
    monkeypatch.setattr(notifier, "utcnow", lambda: clock[0])
    item = ActionItem(kind="deadline", title="待办", due_at=NOW + timedelta(hours=3))
    db.add(item)
    db.commit()
    assert actions.run_action_reminders(db) == 1
    clock[0] += timedelta(hours=2)
    assert actions.run_action_reminders(db) == 1
    assert actions.run_action_reminders(db) == 0
    calls = []
    monkeypatch.setattr(notifier, "all_settings", lambda *_: {"wxpusher_app_token": "test", "wxpusher_uid": "test"})
    monkeypatch.setattr(notifier, "_send_wxpusher", lambda *args: calls.append(args) or "synthetic-record")
    assert notifier.flush_notifications(db) == 1
    assert len(calls) == 1
    rows = db.scalars(select(Notification).order_by(Notification.id)).all()
    assert [row.status for row in rows] == ["expired", "sent"]
    assert all(row.payload_encrypted is None for row in rows)


def test_historical_snoozed_and_completed_deadlines_do_not_notify(db, monkeypatch) -> None:
    monkeypatch.setattr(actions, "utcnow", lambda: NOW)
    db.add_all([
        ActionItem(kind="deadline", title="历史事项", due_at=NOW + timedelta(hours=1), reminder_24_sent=True, reminder_2_sent=True),
        ActionItem(kind="deadline", title="稍后提醒", due_at=NOW + timedelta(hours=1), status="snoozed", snoozed_until=NOW + timedelta(minutes=30)),
        ActionItem(kind="deadline", title="已完成", due_at=NOW + timedelta(hours=1), status="done"),
    ])
    db.commit()
    assert actions.run_action_reminders(db) == 0
    assert db.scalar(select(Notification)) is None


def test_overdue_followup_still_notifies_once(db, monkeypatch) -> None:
    monkeypatch.setattr(actions, "utcnow", lambda: NOW)
    db.add(ActionItem(kind="followup", title="等待回复", due_at=NOW - timedelta(minutes=1)))
    db.commit()
    assert actions.run_action_reminders(db) == 1
    assert actions.run_action_reminders(db) == 0
    assert db.scalar(select(Notification)).kind == "followup"
