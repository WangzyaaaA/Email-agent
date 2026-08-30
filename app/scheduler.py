from __future__ import annotations

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import get_settings
from app.database import SessionLocal
from app.services.actions import run_action_reminders
from app.services.digests import run_scheduled_digest
from app.services.maintenance import purge_expired_data
from app.services.monitor import monitor_manager
from app.services.notifier import flush_notifications
from app.services.pipeline import retry_processing_jobs
from app.services.push_management import retry_pending_revocations


logger = logging.getLogger(__name__)


def _db_job(function) -> None:  # type: ignore[no-untyped-def]
    try:
        with SessionLocal() as db:
            function(db)
    except Exception:
        logger.exception("Scheduled job %s failed", getattr(function, "__name__", "unknown"))


def build_scheduler() -> BackgroundScheduler:
    settings = get_settings()
    scheduler = BackgroundScheduler(timezone=settings.timezone, daemon=True)
    scheduler.add_job(lambda: _db_job(flush_notifications), "interval", seconds=10, id="notification-outbox", max_instances=1, coalesce=True)
    scheduler.add_job(lambda: _db_job(retry_processing_jobs), "interval", seconds=60, id="model-retries", max_instances=1, coalesce=True)
    scheduler.add_job(lambda: _db_job(run_action_reminders), "interval", seconds=60, id="action-reminders", max_instances=1, coalesce=True)
    scheduler.add_job(monitor_manager.refresh, "interval", seconds=30, id="monitor-refresh", max_instances=1, coalesce=True)
    scheduler.add_job(lambda: _db_job(run_scheduled_digest), "cron", hour=20, minute=30, id="scheduled-digests", max_instances=1)
    scheduler.add_job(lambda: _db_job(purge_expired_data), "cron", hour=3, minute=15, id="retention-cleanup", max_instances=1)
    scheduler.add_job(lambda: _db_job(retry_pending_revocations), "interval", seconds=60, id="push-revocations", max_instances=1, coalesce=True)
    return scheduler
