from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


PROTOCOL_VERSION = 1
MESSAGE_INFO = b"mail-sentinel/android/message/v1"
DEVICE_AUTH_INFO = b"mail-sentinel/android/device-auth/v1"
MAX_PLAINTEXT_BYTES = 2200
MAX_FCM_DATA_BYTES = 3500
MAX_TITLE_CHARS = 160
MAX_BODY_CHARS = 1600
ALLOWED_KINDS = {"otp", "security", "deadline", "important", "followup", "digest", "test"}
ALLOWED_PRIORITIES = {"normal", "high"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class ProtocolError(ValueError):
    """A stable, content-free protocol validation error."""


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, expected_length: int | None = None) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ProtocolError("invalid_base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ProtocolError("invalid_base64url") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ProtocolError("invalid_binary_length")
    return decoded


def canonical_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def parse_canonical_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("invalid_timestamp") from exc
    if canonical_utc(parsed) != value:
        raise ProtocolError("noncanonical_timestamp")
    return parsed.astimezone(timezone.utc)


def validate_identifier(value: str, field: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ProtocolError(f"invalid_{field}")
    return value


def derive_device_keys(content_root_key: bytes, device_id: str) -> tuple[bytes, bytes]:
    if len(content_root_key) != 32:
        raise ProtocolError("invalid_content_root_key")
    validate_identifier(device_id, "device_id")
    salt = device_id.encode("utf-8")
    message_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=MESSAGE_INFO).derive(content_root_key)
    auth_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=DEVICE_AUTH_INFO).derive(content_root_key)
    return message_key, auth_key


def envelope_aad(
    *, message_id: str, device_id: str, key_id: str, priority: str, expires_at: str
) -> bytes:
    validate_identifier(message_id, "message_id")
    validate_identifier(device_id, "device_id")
    validate_identifier(key_id, "key_id")
    if priority not in ALLOWED_PRIORITIES:
        raise ProtocolError("invalid_priority")
    parse_canonical_utc(expires_at)
    return f"v1\n{message_id}\n{device_id}\n{key_id}\n{priority}\n{expires_at}".encode("utf-8")


def html_to_plain_text(value: str) -> str:
    soup = BeautifulSoup(value or "", "html.parser")
    for node in soup(["script", "style", "img", "svg", "video", "audio", "iframe"]):
        node.decompose()
    text = soup.get_text("\n", strip=True)
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def _truncate_utf8(value: str, max_bytes: int, suffix: str = "…（已安全截断）") -> str:
    if len(value.encode("utf-8")) <= max_bytes:
        return value
    suffix_bytes = suffix.encode("utf-8")
    budget = max(0, max_bytes - len(suffix_bytes))
    encoded = value.encode("utf-8")[:budget]
    while encoded:
        try:
            return encoded.decode("utf-8") + suffix
        except UnicodeDecodeError:
            encoded = encoded[:-1]
    return suffix[:1]


def notification_plaintext(
    *, kind: str, title: str, body: str, created_at: datetime, sensitive: bool | None = None
) -> bytes:
    if kind not in ALLOWED_KINDS:
        raise ProtocolError("invalid_kind")
    safe_title = _truncate_utf8(title.strip(), MAX_TITLE_CHARS * 4)[:MAX_TITLE_CHARS]
    safe_body = _truncate_utf8(body.strip(), MAX_BODY_CHARS * 4)[:MAX_BODY_CHARS]
    payload: dict[str, Any] = {
        "schema": 1,
        "kind": kind,
        "title": safe_title,
        "body": safe_body,
        "created_at": canonical_utc(created_at),
        "sensitive": kind in {"otp", "security"} if sensitive is None else bool(sensitive),
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_PLAINTEXT_BYTES:
        overhead = len(encoded) - len(safe_body.encode("utf-8"))
        payload["body"] = _truncate_utf8(safe_body, max(0, MAX_PLAINTEXT_BYTES - overhead))
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_PLAINTEXT_BYTES:
        raise ProtocolError("plaintext_too_large")
    return encoded


def encrypt_envelope(
    *,
    content_root_key: bytes,
    message_id: str,
    device_id: str,
    key_id: str,
    priority: str,
    expires_at: datetime,
    plaintext: bytes,
    nonce: bytes | None = None,
) -> dict[str, str]:
    expires_text = canonical_utc(expires_at)
    aad = envelope_aad(
        message_id=message_id,
        device_id=device_id,
        key_id=key_id,
        priority=priority,
        expires_at=expires_text,
    )
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ProtocolError("plaintext_too_large")
    selected_nonce = nonce or __import__("secrets").token_bytes(12)
    if len(selected_nonce) != 12:
        raise ProtocolError("invalid_nonce")
    message_key, _ = derive_device_keys(content_root_key, device_id)
    ciphertext = AESGCM(message_key).encrypt(selected_nonce, plaintext, aad)
    envelope = {
        "version": str(PROTOCOL_VERSION),
        "message_id": message_id,
        "device_id": device_id,
        "key_id": key_id,
        "priority": priority,
        "expires_at": expires_text,
        "nonce": b64url_encode(selected_nonce),
        "ciphertext": b64url_encode(ciphertext),
    }
    serialized_size = len(json.dumps({"message": {"data": envelope}}, separators=(",", ":")).encode("utf-8"))
    if serialized_size > MAX_FCM_DATA_BYTES:
        raise ProtocolError("fcm_data_too_large")
    return envelope


def decrypt_envelope(content_root_key: bytes, envelope: dict[str, str]) -> dict[str, Any]:
    required = {"version", "message_id", "device_id", "key_id", "priority", "expires_at", "nonce", "ciphertext"}
    if set(envelope) != required or envelope.get("version") != "1":
        raise ProtocolError("invalid_envelope")
    aad = envelope_aad(
        message_id=envelope["message_id"],
        device_id=envelope["device_id"],
        key_id=envelope["key_id"],
        priority=envelope["priority"],
        expires_at=envelope["expires_at"],
    )
    nonce = b64url_decode(envelope["nonce"], expected_length=12)
    ciphertext = b64url_decode(envelope["ciphertext"])
    message_key, _ = derive_device_keys(content_root_key, envelope["device_id"])
    try:
        clear = AESGCM(message_key).decrypt(nonce, ciphertext, aad)
        payload = json.loads(clear)
    except Exception as exc:
        raise ProtocolError("decrypt_failed") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema", "kind", "title", "body", "created_at", "sensitive"}:
        raise ProtocolError("invalid_plaintext")
    return payload


def new_opaque_id() -> str:
    return b64url_encode(uuid.uuid4().bytes)


def canonical_device_request(
    *, method: str, path_and_query: str, body: bytes, timestamp: str, nonce: str
) -> bytes:
    if not path_and_query.startswith("/") or "\n" in path_and_query or "\r" in path_and_query:
        raise ProtocolError("invalid_request_target")
    if method.upper() not in {"GET", "POST"}:
        raise ProtocolError("invalid_method")
    b64url_decode(nonce, expected_length=16)
    if not re.fullmatch(r"[0-9]{10}", timestamp):
        raise ProtocolError("invalid_request_timestamp")
    body_hash = hashlib.sha256(body).hexdigest()
    return f"v1\n{method.upper()}\n{path_and_query}\n{body_hash}\n{timestamp}\n{nonce}".encode("utf-8")


def sign_device_request(
    key: bytes, *, method: str, path_and_query: str, body: bytes, timestamp: str, nonce: str
) -> str:
    canonical = canonical_device_request(
        method=method, path_and_query=path_and_query, body=body, timestamp=timestamp, nonce=nonce
    )
    return b64url_encode(hmac.new(key, canonical, hashlib.sha256).digest())
