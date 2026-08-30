from __future__ import annotations

import random
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, delete, or_, select
from sqlalchemy.orm import Session, sessionmaker

from push_gateway.config import GatewaySettings
from push_gateway.fcm import FcmClient
from push_gateway.models import Device, GatewayMessage, OperationalEvent, RequestNonce, utcnow
from push_gateway.security import GatewayCipher


_delivery_lock = threading.Lock()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def flush_gateway_messages(
    factory: sessionmaker[Session], settings: GatewaySettings, fcm_client: FcmClient, limit: int = 20
) -> int:
    if not _delivery_lock.acquire(blocking=False):
        return 0
    try:
        return _flush_locked(factory, settings, fcm_client, limit)
    finally:
        _delivery_lock.release()


def _flush_locked(factory: sessionmaker[Session], settings: GatewaySettings, fcm_client: FcmClient, limit: int) -> int:
    now = utcnow()
    with factory() as db:
        rows = db.scalars(
            select(GatewayMessage)
            .where(
                GatewayMessage.status.in_(["accepted", "retry_wait", "waiting_registration"]),
                GatewayMessage.next_attempt_at <= now,
                or_(GatewayMessage.lease_until.is_(None), GatewayMessage.lease_until <= now),
            )
            .order_by(case((GatewayMessage.priority == "high", 2), else_=1).desc(), GatewayMessage.created_at)
            .limit(limit)
        ).all()
        if not rows:
            return 0
        for row in rows:
            row.lease_until = now + timedelta(minutes=2)
        db.commit()

    completed = 0
    cipher = GatewayCipher(settings.master_key)
    for claimed in rows:
        with factory() as db:
            row = db.get(GatewayMessage, claimed.id)
            if not row:
                continue
            expires = _aware(row.expires_at)
            if expires <= now:
                row.status = "expired"
                row.envelope_encrypted = None
                row.lease_until = None
                db.commit()
                continue
            device = db.get(Device, row.device_id)
            if not device or device.status != "active" or not device.fcm_token_encrypted:
                row.status = "waiting_registration"
                row.last_error_code = "device_unavailable"
                row.next_attempt_at = now + timedelta(minutes=5)
                row.lease_until = None
                db.commit()
                continue
            if not row.envelope_encrypted:
                row.status = "permanent_failed"
                row.last_error_code = "envelope_missing"
                row.lease_until = None
                db.commit()
                continue
            envelope = cipher.decrypt_json(row.envelope_encrypted)
            fcm_token = cipher.decrypt(device.fcm_token_encrypted)
            try:
                delivery_envelope = {key: str(value) for key, value in envelope.items()}
                delivery_envelope["gateway_message_id"] = row.gateway_message_id
                result = fcm_client.send(
                    fcm_token=fcm_token,
                    envelope=delivery_envelope,
                    ttl_seconds=max(0, int((expires - now).total_seconds())),
                )
            except Exception:
                result = None
            row.attempts += 1
            row.lease_until = None
            if result and result.accepted:
                row.status = "fcm_accepted"
                row.fcm_name_fingerprint = cipher.fingerprint(result.message_name or "")
                row.last_error_code = None
                completed += 1
            elif result and result.registration_invalid:
                device.fcm_token_encrypted = None
                device.status = "waiting_registration"
                row.status = "waiting_registration"
                row.last_error_code = result.error_code
                row.next_attempt_at = now + timedelta(minutes=5)
                db.add(OperationalEvent(event_type="device_registration", code="fcm_token_unregistered"))
            elif result and result.retryable:
                row.status = "retry_wait"
                row.last_error_code = result.error_code
                base = result.retry_after_seconds or max(10, min(600, 2 ** min(row.attempts + 3, 9)))
                row.next_attempt_at = min(expires, now + timedelta(seconds=base + random.randint(0, max(1, base // 4))))
                if row.attempts == 3:
                    db.add(OperationalEvent(event_type="fcm_delivery", code=row.last_error_code or "fcm_retrying"))
            else:
                row.status = "permanent_failed"
                row.last_error_code = result.error_code if result else "fcm_client_failure"
                row.envelope_encrypted = None
                db.add(OperationalEvent(event_type="fcm_delivery", code=row.last_error_code))
            db.commit()
    return completed


def purge_gateway_data(factory: sessionmaker[Session], settings: GatewaySettings) -> None:
    now = utcnow()
    metadata_cutoff = now - timedelta(days=settings.status_retention_days)
    audit_cutoff = now - timedelta(days=30)
    with factory() as db:
        expired = db.scalars(
            select(GatewayMessage).where(GatewayMessage.expires_at <= now, GatewayMessage.envelope_encrypted.is_not(None))
        ).all()
        for row in expired:
            row.status = "expired"
            row.envelope_encrypted = None
            row.lease_until = None
        pending_devices = db.scalars(
            select(Device).where(Device.status == "pending_activation", Device.activation_expires_at <= now)
        ).all()
        for device in pending_devices:
            device.status = "pairing_expired"
            device.device_token_fingerprint = None
            device.device_auth_key_encrypted = None
        db.execute(delete(RequestNonce).where(RequestNonce.expires_at <= now))
        db.execute(
            delete(GatewayMessage).where(
                GatewayMessage.created_at < metadata_cutoff,
                GatewayMessage.status.in_(["acknowledged", "expired", "revoked", "permanent_failed"]),
            )
        )
        db.execute(delete(OperationalEvent).where(OperationalEvent.created_at < audit_cutoff))
        db.commit()
