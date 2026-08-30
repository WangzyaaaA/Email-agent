from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import ActionItem, AuditEvent, DigestRun, MessageMetadata, Notification, ProcessingJob, PushDevice, utcnow


def purge_expired_data(db: Session) -> None:
    now = utcnow()
    cutoff = now - timedelta(days=get_settings().retention_days)
    audit_cutoff = now - timedelta(days=30)
    db.execute(delete(ProcessingJob).where(ProcessingJob.expires_at < now))
    db.execute(delete(ActionItem).where(ActionItem.created_at < cutoff))
    db.execute(delete(MessageMetadata).where(MessageMetadata.received_at < cutoff))
    db.execute(delete(Notification).where(Notification.created_at < cutoff))
    db.execute(delete(DigestRun).where(DigestRun.created_at < cutoff))
    db.execute(delete(AuditEvent).where(AuditEvent.created_at < audit_cutoff))
    pending_devices = db.scalars(
        select(PushDevice).where(PushDevice.status == "pending_activation", PushDevice.pairing_expires_at < now)
    ).all()
    for device in pending_devices:
        device.status = "pairing_expired"
        device.pending_device_token_encrypted = None
        device.content_root_key_encrypted = None
    db.commit()
