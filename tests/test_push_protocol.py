from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.push_protocol import (
    ProtocolError,
    b64url_decode,
    b64url_encode,
    decrypt_envelope,
    derive_device_keys,
    encrypt_envelope,
    notification_plaintext,
    sign_device_request,
)


def _vector() -> dict:
    return json.loads((Path(__file__).resolve().parents[1] / "protocol_vectors.json").read_text(encoding="utf-8"))


def test_shared_protocol_vector_matches() -> None:
    value = _vector()
    root = b64url_decode(value["content_root_key"], expected_length=32)
    message_key, auth_key = derive_device_keys(root, value["device_id"])
    assert b64url_encode(message_key) == value["message_key"]
    assert b64url_encode(auth_key) == value["device_auth_key"]
    assert decrypt_envelope(root, value["envelope"])["title"] == "OTP example"
    request = value["request"]
    assert sign_device_request(
        auth_key,
        method=request["method"],
        path_and_query=request["path_and_query"],
        body=request["body"].encode(),
        timestamp=request["timestamp"],
        nonce=request["nonce"],
    ) == request["signature"]


@pytest.mark.parametrize("field", ["message_id", "device_id", "key_id", "priority", "expires_at", "nonce", "ciphertext"])
def test_tampering_any_authenticated_envelope_field_fails(field: str) -> None:
    value = _vector()
    envelope = dict(value["envelope"])
    if field == "priority":
        envelope[field] = "normal"
    elif field == "expires_at":
        envelope[field] = "2030-01-01T00:09:59Z"
    elif field in {"nonce", "ciphertext"}:
        raw = bytearray(b64url_decode(envelope[field]))
        raw[0] ^= 1
        envelope[field] = b64url_encode(bytes(raw))
    else:
        envelope[field] = envelope[field][:-1] + ("A" if envelope[field][-1] != "A" else "B")
    with pytest.raises(ProtocolError):
        decrypt_envelope(b64url_decode(value["content_root_key"]), envelope)


def test_unicode_plaintext_is_bounded_by_bytes_and_fcm_envelope_limit() -> None:
    root = bytes(range(32))
    plain = notification_plaintext(
        kind="digest",
        title="中文标题" * 100,
        body="长摘要🙂" * 1000,
        created_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    assert len(plain) <= 2200
    envelope = encrypt_envelope(
        content_root_key=root,
        message_id="message_0123456789",
        device_id="device_0123456789",
        key_id="key_0123456789",
        priority="normal",
        expires_at=datetime(2030, 1, 2, tzinfo=timezone.utc),
        plaintext=plain,
        nonce=bytes.fromhex("101112131415161718191a1b"),
    )
    wire = json.dumps({"message": {"data": envelope}}, separators=(",", ":")).encode()
    assert len(wire) <= 3500
