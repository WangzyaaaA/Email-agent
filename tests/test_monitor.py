from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import MailboxAccount, utcnow
from app.services import monitor


class FakeMonitor(monitor.AccountMonitor):
    def __init__(self, *args):
        super().__init__(*args)
        self.alive = False
        self.linger = False

    def start(self):
        self.alive = True

    def is_alive(self):
        return self.alive

    def stop(self):
        super().stop()
        self.alive = self.linger

    def join(self, timeout=None):
        pass


def test_status_changes_keep_monitor_and_configuration_changes_replace_it(db, monkeypatch) -> None:
    account = MailboxAccount(name="Test", email_address="user@example.com", provider="gmail", imap_host="imap.example.com", username="user", password_encrypted="unused", host_confirmed=True)
    db.add(account)
    db.commit()
    monkeypatch.setattr(monitor, "SessionLocal", lambda: Session(db.get_bind(), expire_on_commit=False))
    monkeypatch.setattr(monitor, "AccountMonitor", FakeMonitor)
    manager = monitor.MonitorManager()
    manager.refresh()
    original = manager._handles[account.id].monitor
    account.status = "healthy"
    account.last_sync_at = utcnow()
    account.updated_at = utcnow() + timedelta(seconds=1)
    db.commit()
    manager.refresh()
    assert manager._handles[account.id].monitor is original
    assert not original.stop_event.is_set()
    manager.request_sync(account.id)
    assert manager._handles[account.id].monitor is original and original.sync_event.is_set()
    account.password_encrypted = "updated-credential"
    db.commit()
    manager.refresh()
    replacement = manager._handles[account.id].monitor
    assert replacement is not original and original.stop_event.is_set()
    assert replacement.is_alive()
    account.enabled = False
    db.commit()
    manager.refresh()
    assert account.id not in manager._handles and replacement.stop_event.is_set()


def test_changed_configuration_never_overlaps_a_stopping_monitor(db, monkeypatch) -> None:
    account = MailboxAccount(name="Test", email_address="user@example.com", provider="gmail", imap_host="imap.example.com", username="user", password_encrypted="unused", host_confirmed=True)
    db.add(account)
    db.commit()
    monkeypatch.setattr(monitor, "SessionLocal", lambda: Session(db.get_bind(), expire_on_commit=False))
    monkeypatch.setattr(monitor, "AccountMonitor", FakeMonitor)
    manager = monitor.MonitorManager()
    manager.refresh()
    original = manager._handles[account.id].monitor
    original.linger = True
    account.provider = "custom"
    db.commit()
    manager.refresh()
    assert manager._handles[account.id].monitor is original
    original.linger = False
    original.alive = False
    manager.refresh()
    assert manager._handles[account.id].monitor is not original


def test_manual_request_during_idle_runs_sync_without_reconnecting(db, monkeypatch) -> None:
    account = MailboxAccount(name="Test", email_address="user@example.com", provider="gmail", imap_host="imap.example.com", username="user", password_encrypted="unused", host_confirmed=True)
    db.add(account)
    db.commit()
    worker = monitor.AccountMonitor(account.id, monitor._fingerprint(account))
    calls = []

    class Source:
        def __init__(self, *_):
            pass

        def connect(self):
            calls.append("connect")

        def capabilities(self):
            return {"IDLE"}

        def wait_for_changes(self, *_):
            worker.request_sync()
            return False

        def close(self):
            calls.append("close")

    def sync(*_):
        calls.append("sync")
        if calls.count("sync") == 2:
            worker.stop()

    monkeypatch.setattr(worker, "_load", lambda: (account, "unused"))
    monkeypatch.setattr(monitor, "SessionLocal", lambda: Session(db.get_bind(), expire_on_commit=False))
    monkeypatch.setattr(monitor, "IMAPMailSource", Source)
    monkeypatch.setattr(monitor, "sync_account_with_source", sync)
    worker.run()
    assert calls == ["connect", "sync", "sync", "close"]
