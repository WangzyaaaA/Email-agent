from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from push_gateway.config import GatewaySettings
from push_gateway.main import create_app
from push_gateway.models import Device, GatewayCredential, GatewayMessage, utcnow
from push_gateway.security import GatewayCipher, new_token

TERMINAL = {"acknowledged", "expired", "revoked", "permanent_failed"}


def test_revoke_keeps_terminal_history_and_clears_deliverable_envelopes(tmp_path) -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url=f"sqlite:///{(tmp_path / 'gateway.db').as_posix()}",
        firebase_project_id="test-project",
        allow_http_for_tests=True,
        request_rate_per_minute=1000,
    )
    app = create_app(settings)
    factory = app.state.session_factory
    cipher = GatewayCipher(settings.master_key)
    token = new_token()
    now = utcnow()

    with factory() as db:
        device = Device(device_id="device_revoke0001", key_id="key_revoke0000001", status="active")
        db.add(device)
        db.flush()
        db.add(GatewayCredential(kind="device_admin", token_fingerprint=cipher.fingerprint(token), active=True))
        statuses = ["acknowledged", "expired", "revoked", "permanent_failed", "fcm_accepted", "accepted", "retry_wait", "waiting_registration"]
        for index, status in enumerate(statuses, start=1):
            db.add(
                GatewayMessage(
                    gateway_message_id=f"message_{index:014d}",
                    device_id=device.id,
                    message_id=f"remote_message_{index:04d}",
                    idempotency_fingerprint=f"fingerprint_{index:04d}",
                    envelope_digest="d" * 64,
                    envelope_encrypted=None if status in TERMINAL else f"cipher-{index}",
                    priority="normal",
                    expires_at=now + timedelta(hours=1),
                    status=status,
                    next_attempt_at=now,
                )
            )
        db.commit()

    client = TestClient(app)
    response = client.post(
        "/v1/devices/device_revoke0001/revoke",
        json={},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "revoked"
    with factory() as db:
        rows = {row.message_id: row for row in db.scalars(select(GatewayMessage)).all()}
        assert rows["remote_message_0001"].status == "acknowledged"
        assert rows["remote_message_0002"].status == "expired"
        assert rows["remote_message_0003"].status == "revoked"
        assert rows["remote_message_0004"].status == "permanent_failed"
        for index in range(5, 9):
            assert rows[f"remote_message_{index:04d}"].status == "revoked"
        assert all(row.envelope_encrypted is None for row in rows.values())
        assert all(row.lease_until is None for row in rows.values())
        device = db.scalars(select(Device).where(Device.device_id == "device_revoke0001")).one()
        assert device.fcm_token_encrypted is None
        assert device.device_auth_key_encrypted is None
        assert device.device_token_fingerprint is None
