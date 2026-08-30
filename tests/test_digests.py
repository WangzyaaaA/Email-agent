from __future__ import annotations

from datetime import datetime, timezone

from app.models import DigestRun, Notification
from app.security import Cipher
from app.services.digests import run_scheduled_digest


def test_scheduled_digest_is_idempotent_and_keeps_encrypted_snapshot(db) -> None:  # type: ignore[no-untyped-def]
    now = datetime(2026, 8, 31, 12, 30, tzinfo=timezone.utc)

    run = run_scheduled_digest(db, now=now)
    duplicate = run_scheduled_digest(db, now=now)

    assert run is not None
    assert duplicate is None
    assert run.digest_types == "daily,monthly"
    assert run.content_encrypted is not None
    snapshot = Cipher().decrypt_json(run.content_encrypted)
    assert "今日 / 本月邮箱总结" in snapshot["content"]
    assert db.query(DigestRun).count() == 1
    assert db.query(Notification).count() == 1
