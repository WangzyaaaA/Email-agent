from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.mail.imap_source import IMAPMailSource, classify_connection_error
from app.models import MailboxAccount, utcnow
from app.security import Cipher
from app.services.pipeline import sync_account_with_source
from app.store import audit


logger = logging.getLogger(__name__)


def _fingerprint(account: MailboxAccount) -> tuple:
    return (
        account.updated_at.isoformat() if account.updated_at else "",
        account.enabled,
        account.imap_host,
        account.imap_port,
        account.username,
        account.password_encrypted,
    )


class AccountMonitor(threading.Thread):
    def __init__(self, account_id: int, fingerprint: tuple) -> None:
        super().__init__(name=f"mail-monitor-{account_id}", daemon=True)
        self.account_id = account_id
        self.fingerprint = fingerprint
        self.stop_event = threading.Event()

    def stop(self) -> None:
        self.stop_event.set()

    def _load(self) -> tuple[MailboxAccount, str] | None:
        with SessionLocal() as db:
            account = db.get(MailboxAccount, self.account_id)
            if not account or not account.enabled or not account.host_confirmed:
                return None
            return account, Cipher().decrypt(account.password_encrypted)

    def _set_error(self, exc: Exception, provider: str) -> None:
        code, message = classify_connection_error(exc, provider)
        with SessionLocal() as db:
            account = db.get(MailboxAccount, self.account_id)
            if account:
                account.status = "error"
                account.last_error_code = code
                account.last_error = message
                audit(db, "mailbox_error", f"account={account.id} code={code}")
                db.commit()

    def run(self) -> None:
        settings = get_settings()
        backoff = 5
        while not self.stop_event.is_set():
            loaded = self._load()
            if not loaded:
                return
            account, password = loaded
            source = IMAPMailSource(account.imap_host, account.imap_port, account.username, password, account.provider)
            try:
                source.connect()
                with SessionLocal() as db:
                    current = db.get(MailboxAccount, self.account_id)
                    if current:
                        current.status = "connected"
                        current.capabilities = ",".join(sorted(source.capabilities()))
                        current.last_error = None
                        current.last_error_code = None
                        db.commit()
                sync_account_with_source(self.account_id, source)
                backoff = 5
                last_reconcile = datetime.now(timezone.utc)
                while not self.stop_event.is_set():
                    changed = source.wait_for_changes(self.stop_event, settings.poll_seconds)
                    now = datetime.now(timezone.utc)
                    reconcile = (now - last_reconcile).total_seconds() >= settings.reconciliation_seconds
                    if changed or reconcile:
                        sync_account_with_source(self.account_id, source)
                        last_reconcile = now
            except Exception as exc:
                logger.warning("Mailbox monitor %s failed: %s", self.account_id, type(exc).__name__)
                self._set_error(exc, account.provider)
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, 300)
            finally:
                source.close()


@dataclass
class MonitorHandle:
    fingerprint: tuple
    monitor: AccountMonitor


class MonitorManager:
    def __init__(self) -> None:
        self._handles: dict[int, MonitorHandle] = {}
        self._lock = threading.Lock()

    def refresh(self) -> None:
        with SessionLocal() as db:
            accounts = db.scalars(select(MailboxAccount)).all()
        desired = {account.id: account for account in accounts if account.enabled and account.host_confirmed}
        with self._lock:
            for account_id, handle in list(self._handles.items()):
                account = desired.get(account_id)
                if not account or _fingerprint(account) != handle.fingerprint or not handle.monitor.is_alive():
                    handle.monitor.stop()
                    handle.monitor.join(timeout=2)
                    if handle.monitor.is_alive():
                        # Do not overlap two live IMAP sessions for one account. The next refresh
                        # will replace this stopped monitor after its current IDLE wait returns.
                        desired.pop(account_id, None)
                        continue
                    self._handles.pop(account_id, None)
            for account_id, account in desired.items():
                if account_id in self._handles:
                    continue
                fingerprint = _fingerprint(account)
                monitor = AccountMonitor(account_id, fingerprint)
                self._handles[account_id] = MonitorHandle(fingerprint, monitor)
                monitor.start()

    def stop_all(self) -> None:
        with self._lock:
            handles = list(self._handles.values())
            self._handles.clear()
        for handle in handles:
            handle.monitor.stop()
        for handle in handles:
            handle.monitor.join(timeout=5)


monitor_manager = MonitorManager()
