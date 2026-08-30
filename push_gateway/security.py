from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, expected_length: int | None = None) -> bytes:
    if not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ValueError("invalid_base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("invalid_binary_length")
    return decoded


@lru_cache(maxsize=8)
def _derive(master_key: str) -> bytes:
    return hashlib.scrypt(
        master_key.encode("utf-8"), salt=b"mail-sentinel-push-gateway-v1", n=2**14, r=8, p=1, dklen=32
    )


class GatewayCipher:
    def __init__(self, master_key: str) -> None:
        derived = _derive(master_key)
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))
        self._fingerprint_key = hashlib.sha256(b"gateway-fingerprint:" + derived).digest()

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("encrypted_value_unavailable") from exc

    def encrypt_json(self, value: dict[str, Any]) -> str:
        return self.encrypt(json.dumps(value, separators=(",", ":"), sort_keys=True))

    def decrypt_json(self, value: str) -> dict[str, Any]:
        parsed = json.loads(self.decrypt(value))
        if not isinstance(parsed, dict):
            raise ValueError("encrypted_value_invalid")
        return parsed

    def fingerprint(self, value: str) -> str:
        return hmac.new(self._fingerprint_key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def new_token() -> str:
    return b64url_encode(secrets.token_bytes(32))


def bearer_token(header: str | None) -> str:
    if not header or not header.startswith("Bearer ") or header.count(" ") != 1:
        raise ValueError("authentication_required")
    token = header.removeprefix("Bearer ")
    b64url_decode(token, expected_length=32)
    return token


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
