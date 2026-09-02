from __future__ import annotations

from datetime import timedelta

from push_gateway.cli import operational_status_lines
from push_gateway.config import GatewaySettings
from push_gateway.database import create_gateway_engine, create_session_factory, init_gateway_db
from push_gateway.models import Device, GatewayMessage, OperationalEvent, utcnow


def test_operational_status_is_aggregate_and_contains_no_sensitive_values() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
    )
    engine = create_gateway_engine(settings)
    init_gateway_db(engine)
    factory = create_session_factory(engine)
    now = utcnow()
    with factory() as db:
        device = Device(
            device_id="device-secret-id",
            key_id="key-secret-id",
            status="active",
            device_auth_key_encrypted="encrypted-auth-secret",
            fcm_token_encrypted="encrypted-fcm-secret",
        )
        db.add(device)
        db.flush()
        db.add(
            GatewayMessage(
                gateway_message_id="gateway-secret-id",
                device_id=device.id,
                message_id="message-secret-id",
                idempotency_fingerprint="a" * 64,
                envelope_digest="b" * 64,
                envelope_encrypted="encrypted-envelope-secret",
                priority="high",
                expires_at=now + timedelta(minutes=5),
                status="retry_wait",
                created_at=now - timedelta(seconds=90),
            )
        )
        db.add(OperationalEvent(event_type="fcm_delivery", code="fcm_service_unavailable", created_at=now))
        db.commit()
        output = "\n".join(operational_status_lines(db, now=now))

    assert "devices=active:1" in output
    assert "messages=retry_wait:1" in output
    assert "oldest_pending_age_seconds=90" in output
    assert "operational_events_24h=fcm_service_unavailable:1" in output
    assert all(secret not in output for secret in ["device-secret-id", "message-secret-id", "encrypted-envelope-secret"])


def test_operational_status_counts_fcm_accepted_as_pending_until_device_ack() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
    )
    engine = create_gateway_engine(settings)
    init_gateway_db(engine)
    factory = create_session_factory(engine)
    now = utcnow()
    with factory() as db:
        device = Device(device_id="device_waiting_ack", key_id="key_waiting_ack", status="active")
        db.add(device)
        db.flush()
        db.add(
            GatewayMessage(
                gateway_message_id="gateway_waiting_ack",
                device_id=device.id,
                message_id="message_waiting_ack",
                idempotency_fingerprint="c" * 64,
                envelope_digest="d" * 64,
                envelope_encrypted="encrypted-envelope",
                priority="normal",
                expires_at=now + timedelta(minutes=5),
                status="fcm_accepted",
                created_at=now - timedelta(seconds=120),
            )
        )
        db.commit()
        output = "\n".join(operational_status_lines(db, now=now))

    assert "messages=fcm_accepted:1" in output
    assert "oldest_pending_age_seconds=120" in output
