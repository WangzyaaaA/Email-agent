from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Notification, NotificationStatus, PushDevice, utcnow
from app.services.fcm_channel import GatewayClient, GatewayFailure
from app.store import all_settings


def finish_local_revocation(device: PushDevice) -> None:
    device.status = "revoked"
    device.revoke_pending = False
    device.content_root_key_encrypted = None
    device.pending_device_token_encrypted = None
    device.last_error_code = None


def invalidate_revoked_device_envelopes(db: Session) -> None:
    rows = db.scalars(
        select(Notification).where(
            Notification.channel == "fcm_gateway",
            Notification.status.in_([NotificationStatus.PENDING.value, NotificationStatus.FAILED.value, NotificationStatus.SENDING.value]),
        )
    ).all()
    for row in rows:
        row.wire_envelope_encrypted = None
        row.gateway_message_id = None
        if row.kind in {"otp", "security"} or (row.kind == "deadline" and row.priority == "critical"):
            row.route = "fallback_wxpusher"
            row.fallback_reason_code = "device_revoked"
            row.status = NotificationStatus.PENDING.value
            row.next_attempt_at = utcnow()
        else:
            row.status = NotificationStatus.FAILED.value
            row.last_error = "device_revoked_requires_admin_review"


def retry_pending_revocations(db: Session) -> int:
    config = all_settings(db, ["fcm_device_admin_token"])
    token = config.get("fcm_device_admin_token")
    if not token:
        return 0
    rows = db.scalars(select(PushDevice).where(PushDevice.revoke_pending.is_(True))).all()
    completed = 0
    for device in rows:
        try:
            GatewayClient(device.gateway_url, token).revoke(device.device_id)
            finish_local_revocation(device)
            completed += 1
        except GatewayFailure as exc:
            device.status = "revocation_pending"
            device.last_error_code = exc.code
    db.commit()
    return completed
