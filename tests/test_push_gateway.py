from __future__ import annotations

import json
import secrets
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.push_protocol import (
    b64url_encode,
    derive_device_keys,
    encrypt_envelope,
    new_opaque_id,
    notification_plaintext,
    sign_device_request,
)
from push_gateway.config import GatewaySettings
from push_gateway.database import create_gateway_engine, create_session_factory
from push_gateway.fcm import FcmResult
from push_gateway.main import RateLimiter, create_app
from push_gateway.models import Device, GatewayCredential, GatewayMessage, utcnow
from push_gateway.security import GatewayCipher, new_token
from push_gateway.service import flush_gateway_messages


class FakeFcm:
    def __init__(self) -> None:
        self.calls = []

    def send(self, **kwargs):
        self.calls.append(kwargs)
        return FcmResult(True, message_name="projects/example/messages/opaque")


def _signed_headers(token: str, auth_key: bytes, method: str, target: str, body: bytes, nonce: bytes | None = None) -> dict[str, str]:
    timestamp = str(int(utcnow().timestamp()))
    nonce_text = b64url_encode(nonce or secrets.token_bytes(16))
    signature = sign_device_request(
        auth_key,
        method=method,
        path_and_query=target,
        body=body,
        timestamp=timestamp,
        nonce=nonce_text,
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-MS-Timestamp": timestamp,
        "X-MS-Nonce": nonce_text,
        "X-MS-Signature": signature,
        "Content-Type": "application/json",
    }


def test_gateway_scope_pairing_replay_idempotency_delivery_pending_ack_and_revoke() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
        allow_http_for_tests=False,
        request_rate_per_minute=1000,
    )
    engine = create_gateway_engine(settings)
    factory = create_session_factory(engine)
    publisher = new_token()
    device_admin = new_token()
    cipher = GatewayCipher(settings.master_key)
    fake_fcm = FakeFcm()
    app = create_app(settings, engine=engine, fcm_client=fake_fcm)
    with factory() as db:
        db.add_all(
            [
                GatewayCredential(kind="publisher", token_fingerprint=cipher.fingerprint(publisher)),
                GatewayCredential(kind="device_admin", token_fingerprint=cipher.fingerprint(device_admin)),
            ]
        )
        db.commit()

    root = bytes(range(32))
    device_id = "device_0123456789"
    key_id = "key_0123456789"
    device_token = b64url_encode(bytes([7]) * 32)
    _, auth_key = derive_device_keys(root, device_id)
    provision = {
        "device_id": device_id,
        "key_id": key_id,
        "device_token": device_token,
        "device_auth_key": b64url_encode(auth_key),
        "activation_expires_at": (utcnow() + timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }

    with TestClient(app, base_url="https://gateway.test") as client:
        wrong_scope = client.post("/v1/devices/provision", json=provision, headers={"Authorization": f"Bearer {publisher}"})
        assert wrong_scope.status_code == 401
        response = client.post("/v1/devices/provision", json=provision, headers={"Authorization": f"Bearer {device_admin}"})
        assert response.status_code == 200 and response.json()["status"] == "pending_activation"

        token_only = client.post(
            "/v1/devices/register",
            json={"device_id": device_id, "fcm_token": "attacker-registration-token", "registration_version": 1, "app_protocol_version": 1},
            headers={"Authorization": f"Bearer {device_token}"},
        )
        assert token_only.status_code == 401

        early_target = "/v1/messages/pending?limit=50"
        early_headers = _signed_headers(device_token, auth_key, "GET", early_target, b"")
        early_headers.pop("Content-Type")
        early = client.get(early_target, headers=early_headers)
        # A provisioned device that has not registered yet must be told apart from a revoked
        # one; the app deletes local key material only for the latter.
        assert early.status_code == 409 and early.json()["error"]["code"] == "device_not_activated"

        register = json.dumps(
            {
                "device_id": device_id,
                "fcm_token": "fcm-registration-token-value",
                "registration_version": 1,
                "app_protocol_version": 1,
            },
            separators=(",", ":"),
        ).encode()
        fixed_nonce = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
        headers = _signed_headers(device_token, auth_key, "POST", "/v1/devices/register", register, fixed_nonce)
        response = client.post("/v1/devices/register", content=register, headers=headers)
        assert response.status_code == 200 and response.json()["status"] == "active"
        replay = client.post("/v1/devices/register", content=register, headers=headers)
        assert replay.status_code == 409 and replay.json()["error"]["code"] == "replay_detected"
        stale_headers = _signed_headers(device_token, auth_key, "POST", "/v1/devices/register", register)
        stale = client.post("/v1/devices/register", content=register, headers=stale_headers)
        assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale_registration_version"

        expires = utcnow() + timedelta(minutes=30)
        plaintext = notification_plaintext(
            kind="otp", title="OTP", body="Code 123456", created_at=utcnow()
        )
        envelope = encrypt_envelope(
            content_root_key=root,
            message_id="message_0123456789",
            device_id=device_id,
            key_id=key_id,
            priority="high",
            expires_at=expires,
            plaintext=plaintext,
        )
        publish = {"idempotency_key": "dedupe_0123456789", "envelope": envelope}
        headers_publisher = {"Authorization": f"Bearer {publisher}"}
        accepted = client.post("/v1/messages", json=publish, headers=headers_publisher)
        assert accepted.status_code == 200 and accepted.json()["status"] == "accepted"
        gateway_message_id = accepted.json()["gateway_message_id"]
        duplicate = client.post("/v1/messages", json=publish, headers=headers_publisher)
        assert duplicate.json()["gateway_message_id"] == gateway_message_id
        conflict_payload = json.loads(json.dumps(publish))
        conflict_payload["envelope"]["ciphertext"] = ("A" if envelope["ciphertext"][0] != "A" else "B") + envelope["ciphertext"][1:]
        conflict = client.post("/v1/messages", json=conflict_payload, headers=headers_publisher)
        assert conflict.status_code == 409 and conflict.json()["error"]["code"] == "idempotency_conflict"

        assert flush_gateway_messages(factory, settings, fake_fcm) == 1
        assert fake_fcm.calls[0]["envelope"]["gateway_message_id"] == gateway_message_id
        assert "Code 123456" not in json.dumps(fake_fcm.calls[0])
        with factory() as db:
            stored_device = db.scalar(select(Device).where(Device.device_id == device_id))
            stored_message = db.scalar(select(GatewayMessage).where(GatewayMessage.gateway_message_id == gateway_message_id))
            assert stored_device is not None and stored_device.fcm_token_encrypted != "fcm-registration-token-value"
            assert stored_message is not None and "Code 123456" not in (stored_message.envelope_encrypted or "")

        target = "/v1/messages/pending?limit=50"
        pending_headers = _signed_headers(device_token, auth_key, "GET", target, b"")
        pending_headers.pop("Content-Type")
        pending = client.get(target, headers=pending_headers)
        assert pending.status_code == 200 and len(pending.json()["items"]) == 1
        assert pending.json()["items"][0]["envelope"]["ciphertext"] == envelope["ciphertext"]

        ack_body = json.dumps({"device_id": device_id, "result": "shown"}, separators=(",", ":")).encode()
        ack_target = f"/v1/messages/{gateway_message_id}/ack"
        ack = client.post(
            ack_target,
            content=ack_body,
            headers=_signed_headers(device_token, auth_key, "POST", ack_target, ack_body),
        )
        assert ack.status_code == 200 and ack.json()["status"] == "acknowledged"
        with factory() as db:
            row = db.scalar(select(GatewayMessage).where(GatewayMessage.gateway_message_id == gateway_message_id))
            assert row is not None and row.envelope_encrypted is None

        device_cannot_publish = client.post("/v1/messages", json=publish, headers={"Authorization": f"Bearer {device_token}"})
        assert device_cannot_publish.status_code == 401
        admin_cannot_publish = client.post("/v1/messages", json=publish, headers={"Authorization": f"Bearer {device_admin}"})
        assert admin_cannot_publish.status_code == 401
        revoke = client.post(
            f"/v1/devices/{device_id}/revoke",
            json={},
            headers={"Authorization": f"Bearer {device_admin}"},
        )
        assert revoke.status_code == 200 and revoke.json()["status"] == "revoked"
        with factory() as db:
            device = db.scalar(select(Device).where(Device.device_id == device_id))
            assert device is not None
            assert device.fcm_token_encrypted is None
            assert device.device_auth_key_encrypted is None
            assert device.device_token_fingerprint is None


def test_gateway_allows_reregistration_when_its_own_registration_was_invalidated() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
        allow_http_for_tests=False,
        request_rate_per_minute=1000,
    )
    engine = create_gateway_engine(settings)
    factory = create_session_factory(engine)
    device_admin = new_token()
    cipher = GatewayCipher(settings.master_key)
    app = create_app(settings, engine=engine, fcm_client=FakeFcm())
    with factory() as db:
        db.add(GatewayCredential(kind="device_admin", token_fingerprint=cipher.fingerprint(device_admin)))
        db.commit()

    root = bytes(range(32))
    device_id = "device_reregistration"
    device_token = b64url_encode(bytes([9]) * 32)
    _, auth_key = derive_device_keys(root, device_id)
    provision = {
        "device_id": device_id,
        "key_id": "key_reregistration",
        "device_token": device_token,
        "device_auth_key": b64url_encode(auth_key),
        "activation_expires_at": (utcnow() + timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    with TestClient(app, base_url="https://gateway.test") as client:
        assert client.post("/v1/devices/provision", json=provision, headers={"Authorization": f"Bearer {device_admin}"}).status_code == 200
        body = json.dumps(
            {"device_id": device_id, "fcm_token": "first-registration", "registration_version": 2, "app_protocol_version": 1},
            separators=(",", ":"),
        ).encode()
        first = client.post(
            "/v1/devices/register",
            content=body,
            headers=_signed_headers(device_token, auth_key, "POST", "/v1/devices/register", body),
        )
        assert first.status_code == 200 and first.json()["status"] == "active"

        # The gateway invalidates the stored registration itself (FCM reported it as
        # unregistered); the device keeps its version because the installation id never changed.
        with factory() as db:
            device = db.scalar(select(Device).where(Device.device_id == device_id))
            assert device is not None
            device.status = "waiting_registration"
            device.fcm_token_encrypted = None
            db.commit()

        same_version = client.post(
            "/v1/devices/register",
            content=body,
            headers=_signed_headers(device_token, auth_key, "POST", "/v1/devices/register", body),
        )
        assert same_version.status_code == 200 and same_version.json()["status"] == "active"

        older = json.dumps(
            {"device_id": device_id, "fcm_token": "older-registration", "registration_version": 1, "app_protocol_version": 1},
            separators=(",", ":"),
        ).encode()
        stale = client.post(
            "/v1/devices/register",
            content=older,
            headers=_signed_headers(device_token, auth_key, "POST", "/v1/devices/register", older),
        )
        assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale_registration_version"


def test_gateway_rejects_plain_http_and_non_json_without_echoing_secrets() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
        request_rate_per_minute=1000,
    )
    app = create_app(settings, fcm_client=FakeFcm())
    with TestClient(app, base_url="http://gateway.test") as client:
        response = client.get("/healthz")
        assert response.status_code == 400 and response.json() == {"error": {"code": "https_required"}}
    with TestClient(app, base_url="https://gateway.test") as client:
        response = client.post("/v1/messages", content="secret=value", headers={"Content-Type": "text/plain"})
        assert response.status_code == 415
        assert "secret" not in response.text


def test_gateway_rejects_oversized_chunked_body_without_buffering_it() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
        max_request_bytes=1024,
        request_rate_per_minute=1000,
    )
    app = create_app(settings, fcm_client=FakeFcm())

    def oversized():
        for _ in range(20):
            yield b"x" * 512

    with TestClient(app, base_url="https://gateway.test") as client:
        response = client.post(
            "/v1/devices/register",
            content=oversized(),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json() == {"error": {"code": "request_too_large"}}


def test_gateway_rate_limiter_keeps_memory_bounded_under_address_rotation() -> None:
    limiter = RateLimiter(5, max_keys=8)
    for index in range(200):
        assert limiter.allow(f"2001:db8::{index:x}") is True
    assert limiter.tracked_sources <= 8


def test_gateway_rate_limiter_evicts_idle_peers_instead_of_refusing_new_ones() -> None:
    limiter = RateLimiter(1, max_keys=2)
    assert limiter.allow("a") is True
    assert limiter.allow("b") is True
    assert limiter.allow("c") is True
    assert limiter.tracked_sources == 2


def test_gateway_rate_limiter_still_limits_a_single_source() -> None:
    limiter = RateLimiter(3)
    assert all(limiter.allow("203.0.113.7") for _ in range(3))
    assert limiter.allow("203.0.113.7") is False
    assert limiter.allow("203.0.113.8") is True
