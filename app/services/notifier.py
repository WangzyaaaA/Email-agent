from __future__ import annotations

import html
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import case, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Notification, NotificationStatus, PushDevice, utcnow
from app.push_protocol import b64url_decode
from app.security import Cipher
from app.services.fcm_channel import GatewayClient, GatewayFailure, default_expiry, freeze_envelope
from app.store import all_settings, get_setting


WXPUSHER_ENDPOINT = "https://wxpusher.zjiecode.com/api/send/message"
_outbox_lock = threading.Lock()


@contextmanager
def pause_notification_delivery():  # type: ignore[no-untyped-def]
    """Serializes device revocation with the single-process notification sender."""
    with _outbox_lock:
        yield


def redact_sensitive(value: str) -> str:
    value = re.sub(
        r"(?i)(验证码|校验码|动态码|认证码|verification\s*code|security\s*code|otp|password|token|secret)"
        r"(\s*(?:是|为|[:：=])?\s*)([A-Za-z0-9._-]{4,})",
        lambda match: f"{match.group(1)}{match.group(2)}[已遮盖]",
        value,
    )
    value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]{12,}", "Bearer [已遮盖]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{5,})?\b", "[JWT已遮盖]", value)
    return value[:1000]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def quiet_hours_end(now: datetime | None = None) -> datetime | None:
    settings = get_settings()
    zone = ZoneInfo(settings.timezone)
    local = (now or utcnow()).astimezone(zone)
    minutes = local.hour * 60 + local.minute
    start = 22 * 60 + 30
    end = 7 * 60 + 30
    if minutes >= start:
        target = (local + timedelta(days=1)).replace(hour=7, minute=30, second=0, microsecond=0)
        return target.astimezone(timezone.utc)
    if minutes < end:
        target = local.replace(hour=7, minute=30, second=0, microsecond=0)
        return target.astimezone(timezone.utc)
    return None


def enqueue_notification(
    db: Session,
    *,
    kind: str,
    priority: str,
    title: str,
    html_content: str,
    preview: str,
    dedupe_key: str | None = None,
    expires_at: datetime | None = None,
    bypass_quiet: bool = False,
) -> Notification:
    if dedupe_key:
        existing = db.scalar(select(Notification).where(Notification.dedupe_key == dedupe_key))
        if existing:
            return existing
    next_attempt = utcnow()
    if not bypass_quiet and priority == "normal":
        next_attempt = quiet_hours_end(next_attempt) or next_attempt
    selected_channel = get_setting(db, "notification_channel", "wxpusher") or "wxpusher"
    if selected_channel not in {"wxpusher", "fcm_gateway"}:
        selected_channel = "wxpusher"
    row = Notification(
        kind=kind,
        priority=priority,
        title=redact_sensitive(title)[:500],
        content_preview=redact_sensitive(preview),
        payload_encrypted=Cipher().encrypt_json({"content": html_content}),
        next_attempt_at=next_attempt,
        expires_at=expires_at,
        dedupe_key=dedupe_key,
        channel=selected_channel,
        route="primary",
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        if dedupe_key:
            existing = db.scalar(select(Notification).where(Notification.dedupe_key == dedupe_key))
            if existing:
                return existing
        raise
    return row


def _send_wxpusher(app_token: str, uid: str, content: str, summary: str) -> str:
    response = httpx.post(
        WXPUSHER_ENDPOINT,
        json={
            "appToken": app_token,
            "content": content,
            "summary": summary[:100],
            "contentType": 2,
            "uids": [uid],
        },
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("code") != 1000 or not data.get("success", True):
        safe_code = str(data.get("code", "unknown"))[:20]
        raise RuntimeError(f"wxpusher_rejected:{safe_code}")
    records = data.get("data") or []
    return str(records[0].get("sendRecordId", "")) if records else ""


def _fallback_allowed(row: Notification) -> bool:
    return row.kind in {"otp", "security"} or (row.kind == "deadline" and row.priority == "critical")


def _finish_sent(row: Notification, now: datetime, external_id: str | None = None) -> None:
    row.external_id = external_id or row.external_id
    row.status = NotificationStatus.SENT.value
    row.sent_at = now
    row.last_error = None
    row.payload_encrypted = None
    row.wire_envelope_encrypted = None


def _active_push_device(db: Session) -> PushDevice | None:
    return db.scalar(
        select(PushDevice)
        .where(PushDevice.status == "active", PushDevice.revoke_pending.is_(False))
        .order_by(PushDevice.created_at.desc())
    )


def _send_fcm_gateway(db: Session, row: Notification, publisher_token: str | None) -> str:
    device = _active_push_device(db)
    if not publisher_token or not device or not device.content_root_key_encrypted:
        raise GatewayFailure("fcm_channel_not_active")
    if not row.payload_encrypted:
        raise GatewayFailure("notification_payload_missing")
    expires_at = _as_utc(row.expires_at) if row.expires_at else default_expiry(row.kind, row.priority, _as_utc(row.created_at))
    row.expires_at = expires_at
    if not row.wire_envelope_encrypted:
        payload = Cipher().decrypt_json(row.payload_encrypted)
        root_key = b64url_decode(Cipher().decrypt(device.content_root_key_encrypted), expected_length=32)
        frozen = freeze_envelope(
            content_root_key=root_key,
            device_id=device.device_id,
            key_id=device.key_id,
            kind=row.kind,
            priority=row.priority,
            title=row.title,
            html_content=str(payload.get("content", "")),
            created_at=_as_utc(row.created_at),
            expires_at=expires_at,
        )
        row.wire_envelope_encrypted = Cipher().encrypt_json(frozen)
        db.flush()
    frozen = Cipher().decrypt_json(row.wire_envelope_encrypted)
    client = GatewayClient(device.gateway_url, publisher_token)
    try:
        result = client.publish(str(frozen["idempotency_key"]), dict(frozen["envelope"]))
    except GatewayFailure as publish_error:
        if not publish_error.uncertain:
            raise
        try:
            status_result = client.status(str(frozen["idempotency_key"]))
            if not status_result.get("exists"):
                raise GatewayFailure(publish_error.code, retryable=True) from publish_error
            result = status_result
        except GatewayFailure as status_error:
            if status_error.code == "not_found":
                raise GatewayFailure(publish_error.code, retryable=True) from publish_error
            raise GatewayFailure("submission_uncertain", retryable=True, uncertain=True) from status_error
    gateway_id = result.get("gateway_message_id")
    if not isinstance(gateway_id, str) or not gateway_id:
        raise GatewayFailure("invalid_gateway_response")
    row.gateway_message_id = gateway_id[:128]
    return row.gateway_message_id


def flush_notifications(db: Session, limit: int = 20) -> int:
    if not _outbox_lock.acquire(blocking=False):
        return 0
    try:
        return _flush_notifications_locked(db, limit)
    finally:
        _outbox_lock.release()


def _flush_notifications_locked(db: Session, limit: int = 20) -> int:
    now = utcnow()
    priority_order = case(
        (Notification.priority == "critical", 4),
        (Notification.priority == "high", 3),
        (Notification.priority == "normal", 2),
        else_=1,
    )
    rows = db.scalars(
        select(Notification)
        .where(
            Notification.status.in_([
                NotificationStatus.PENDING.value,
                NotificationStatus.FAILED.value,
                NotificationStatus.SENDING.value,
            ])
        )
        .where(Notification.next_attempt_at <= now)
        .order_by(priority_order.desc(), Notification.created_at)
        .limit(limit)
    ).all()
    if not rows:
        return 0
    config = all_settings(db, ["wxpusher_app_token", "wxpusher_uid", "fcm_publisher_token"])
    token = config.get("wxpusher_app_token")
    uid = config.get("wxpusher_uid")
    sent = 0
    for row in rows:
        expires_at = _as_utc(row.expires_at) if row.expires_at else None
        if expires_at and expires_at <= now:
            row.status = NotificationStatus.EXPIRED.value
            row.payload_encrypted = None
            row.wire_envelope_encrypted = None
            row.last_error = "通知已超过有效期"
            continue
        if not row.payload_encrypted:
            row.status = NotificationStatus.EXPIRED.value
            row.wire_envelope_encrypted = None
            continue
        # A short database lease prevents concurrent workers from sending the same row.
        row.status = NotificationStatus.SENDING.value
        row.next_attempt_at = now + timedelta(minutes=5)
        db.commit()
        try:
            payload = Cipher().decrypt_json(row.payload_encrypted)
            if row.channel == "fcm_gateway" and row.route == "primary":
                if row.first_route_attempt_at is None:
                    row.first_route_attempt_at = now
                row.route_attempts += 1
                gateway_id = _send_fcm_gateway(db, row, config.get("fcm_publisher_token"))
                _finish_sent(row, now, gateway_id)
            else:
                if not token or not uid:
                    raise RuntimeError("wxpusher_not_configured")
                wx_id = _send_wxpusher(token, uid, payload["content"], row.title)
                _finish_sent(row, now, wx_id)
            sent += 1
        except GatewayFailure as exc:
            row.attempts += 1
            elapsed = now - _as_utc(row.first_route_attempt_at) if row.first_route_attempt_at else timedelta(0)
            can_fallback = (
                exc.retryable
                and _fallback_allowed(row)
                and bool(token and uid)
                and (row.route_attempts >= 3 or elapsed >= timedelta(seconds=60))
            )
            if can_fallback:
                row.route = "fallback_wxpusher"
                row.fallback_reason_code = exc.code
                try:
                    payload = Cipher().decrypt_json(row.payload_encrypted) if row.payload_encrypted else {}
                    wx_id = _send_wxpusher(token, uid, str(payload.get("content", "")), row.title)
                    _finish_sent(row, now, wx_id)
                    sent += 1
                except Exception:
                    row.status = NotificationStatus.FAILED.value
                    row.last_error = "fallback_wxpusher_failed"
                    row.next_attempt_at = now + timedelta(seconds=30)
            else:
                row.status = NotificationStatus.FAILED.value
                row.last_error = exc.code
                if exc.retryable:
                    delay = 20 if row.route_attempts < 3 else min(600, 2 ** min(row.attempts + 3, 9))
                    row.next_attempt_at = now + timedelta(seconds=delay)
                else:
                    row.next_attempt_at = _as_utc(row.expires_at) if row.expires_at else now + timedelta(hours=24)
        except Exception as exc:
            row.attempts += 1
            row.status = NotificationStatus.FAILED.value
            row.last_error = "wxpusher_not_configured" if str(exc) == "wxpusher_not_configured" else f"{type(exc).__name__}: {str(exc)[:300]}"
            backoff = min(600, 2 ** min(row.attempts, 9))
            row.next_attempt_at = now + timedelta(seconds=backoff)
    db.commit()
    return sent


def otp_html(source: str, code: str, received_text: str, expiry_text: str, auth_status: str) -> str:
    warning = "" if auth_status == "pass" else "<p style='color:#b45309'>⚠ 邮件认证结果缺失，请核对来源。</p>"
    return (
        f"<h2>{html.escape(source)} 验证码</h2>"
        f"<p style='font-size:28px;font-weight:700;letter-spacing:3px'>{html.escape(code)}</p>"
        f"<copy data-clipboard-text='{html.escape(code, quote=True)}'>复制验证码</copy>"
        f"<p>收到时间：{html.escape(received_text)}<br>预计有效至：{html.escape(expiry_text)}</p>{warning}"
    )


def important_html(title: str, summary: str, reason: str, deadline: str | None = None) -> str:
    deadline_html = f"<p><strong>期限：</strong>{html.escape(deadline)}</p>" if deadline else ""
    return (
        f"<h2>{html.escape(title)}</h2>"
        f"<p>{html.escape(summary)}</p>"
        f"<p><strong>提醒原因：</strong>{html.escape(reason)}</p>{deadline_html}"
    )


def enqueue_test_notification(db: Session) -> Notification:
    now = utcnow()
    return enqueue_notification(
        db,
        kind="test",
        priority="critical",
        title="邮箱 Agent 测试通知",
        html_content="<h2>连接成功</h2><p>如果你看到这条消息，当前主通知通道可用。</p>",
        preview="连接成功",
        dedupe_key=f"test:{now.timestamp()}",
        expires_at=now + timedelta(minutes=10),
        bypass_quiet=True,
    )
