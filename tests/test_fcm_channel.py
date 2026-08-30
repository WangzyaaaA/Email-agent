from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models import NotificationStatus, PushDevice
from app.push_protocol import b64url_encode
from app.security import Cipher
from app.services import notifier
from app.services.fcm_channel import GatewayFailure, normalize_gateway_url
from app.services.notifier import enqueue_notification, flush_notifications
from app.services.push_management import invalidate_revoked_device_envelopes
from app.store import set_setting


def test_gateway_url_rejects_credentials_paths_redirect_origins_and_private_hosts() -> None:
    assert normalize_gateway_url("https://Push.Example.com/") == "https://push.example.com"
    for value in (
        "http://push.example.com",
        "https://user:secret@push.example.com",
        "https://push.example.com/api",
        "https://push.example.com/#fragment",
        "https://127.0.0.1",
        "https://192.168.1.2",
        "https://push.example.com:8443",
    ):
        with pytest.raises(ValueError):
            normalize_gateway_url(value, allow_loopback=False)


def _configure_active_device(db) -> None:
    set_setting(db, "notification_channel", "fcm_gateway")
    set_setting(db, "fcm_publisher_token", b64url_encode(bytes([9]) * 32))
    db.add(
        PushDevice(
            device_id="device_0123456789",
            key_id="key_0123456789",
            gateway_url="https://push.example.com",
            content_root_key_encrypted=Cipher().encrypt(b64url_encode(bytes(range(32)))),
            status="active",
        )
    )
    db.commit()


def test_channel_is_frozen_at_enqueue_and_success_clears_both_ciphertexts(db, monkeypatch) -> None:
    _configure_active_device(db)
    row = enqueue_notification(
        db,
        kind="otp",
        priority="critical",
        title="OTP",
        html_content="<p>Code 123456</p>",
        preview="1••••6",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        bypass_quiet=True,
    )
    set_setting(db, "notification_channel", "wxpusher")
    db.commit()
    captured = {}

    def accept(_self, idempotency_key, envelope):
        captured.update(key=idempotency_key, envelope=envelope)
        return {"gateway_message_id": "gateway_0123456789", "status": "accepted"}

    monkeypatch.setattr(notifier.GatewayClient, "publish", accept)
    assert flush_notifications(db) == 1
    assert row.channel == "fcm_gateway"
    assert row.status == NotificationStatus.SENT.value
    assert row.payload_encrypted is None
    assert row.wire_envelope_encrypted is None
    assert captured["envelope"]["ciphertext"]
    assert "Code 123456" not in str(captured)


def test_fcm_retry_reuses_frozen_envelope_and_only_urgent_message_falls_back(db, monkeypatch) -> None:
    _configure_active_device(db)
    set_setting(db, "wxpusher_app_token", "wx-app")
    set_setting(db, "wxpusher_uid", "wx-uid")
    now = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(notifier, "utcnow", lambda: now)
    row = enqueue_notification(
        db,
        kind="otp",
        priority="critical",
        title="OTP",
        html_content="<p>Code 123456</p>",
        preview="masked",
        expires_at=now + timedelta(minutes=10),
        bypass_quiet=True,
    )
    wires = []

    def unavailable(self, idempotency_key, envelope):
        wires.append((idempotency_key, dict(envelope)))
        raise GatewayFailure("gateway_unreachable", retryable=True)

    monkeypatch.setattr(notifier.GatewayClient, "publish", unavailable)
    monkeypatch.setattr(notifier, "_send_wxpusher", lambda *args: "wx-record")
    for _ in range(3):
        row.next_attempt_at = now
        db.commit()
        flush_notifications(db)
    assert wires[0] == wires[1] == wires[2]
    assert row.status == NotificationStatus.SENT.value
    assert row.route == "fallback_wxpusher"
    assert row.fallback_reason_code == "gateway_unreachable"
    assert row.payload_encrypted is None and row.wire_envelope_encrypted is None


def test_nonurgent_message_never_falls_back(db, monkeypatch) -> None:
    _configure_active_device(db)
    set_setting(db, "wxpusher_app_token", "wx-app")
    set_setting(db, "wxpusher_uid", "wx-uid")
    row = enqueue_notification(
        db,
        kind="important",
        priority="high",
        title="Important",
        html_content="<p>Private summary</p>",
        preview="safe",
        bypass_quiet=True,
    )
    monkeypatch.setattr(
        notifier.GatewayClient,
        "publish",
        lambda *args, **kwargs: (_ for _ in ()).throw(GatewayFailure("gateway_unreachable", retryable=True)),
    )
    monkeypatch.setattr(notifier, "_send_wxpusher", lambda *args: (_ for _ in ()).throw(AssertionError("must not fall back")))
    for _ in range(4):
        row.next_attempt_at = notifier.utcnow()
        db.commit()
        flush_notifications(db)
    assert row.status == NotificationStatus.FAILED.value
    assert row.route == "primary"
    assert row.payload_encrypted is not None


def test_device_revocation_invalidates_old_key_envelopes_and_only_reroutes_urgent(db) -> None:
    _configure_active_device(db)
    urgent = enqueue_notification(
        db, kind="security", priority="critical", title="Security", html_content="private", preview="safe", bypass_quiet=True
    )
    normal = enqueue_notification(
        db, kind="important", priority="high", title="Important", html_content="private", preview="safe", bypass_quiet=True
    )
    urgent.wire_envelope_encrypted = Cipher().encrypt_json({"old": "envelope"})
    normal.wire_envelope_encrypted = Cipher().encrypt_json({"old": "envelope"})
    invalidate_revoked_device_envelopes(db)
    assert urgent.route == "fallback_wxpusher" and urgent.fallback_reason_code == "device_revoked"
    assert urgent.wire_envelope_encrypted is None
    assert normal.status == NotificationStatus.FAILED.value
    assert normal.wire_envelope_encrypted is None
    assert normal.last_error == "device_revoked_requires_admin_review"
