from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from functools import lru_cache
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


@lru_cache(maxsize=8)
def _derived_key(selected: str) -> bytes:
    return hashlib.scrypt(
        selected.encode("utf-8"),
        salt=b"mail-sentinel-fernet-v1",
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )


class Cipher:
    """Application-level encryption derived from the NAS-provided master key."""

    def __init__(self, master_key: str | None = None) -> None:
        selected = get_settings().master_key if master_key is None else master_key
        if not selected:
            raise ValueError("Master key cannot be empty")
        derived = _derived_key(selected)
        key = base64.urlsafe_b64encode(derived)
        self._fernet = Fernet(key)
        self._hmac_key = hashlib.sha256(b"fingerprint:" + derived).digest()

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Encrypted value cannot be opened with the configured master key") from exc

    def encrypt_json(self, value: dict[str, Any]) -> str:
        return self.encrypt(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    def decrypt_json(self, token: str) -> dict[str, Any]:
        value = json.loads(self.decrypt(token))
        if not isinstance(value, dict):
            raise ValueError("Encrypted payload is not an object")
        return value

    def fingerprint(self, value: str) -> str:
        return hmac.new(self._hmac_key, value.encode("utf-8"), hashlib.sha256).hexdigest()


password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return password_hasher.verify(encoded, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def mask_secret(value: str, visible: int = 2) -> str:
    if len(value) <= visible * 2:
        return "•" * len(value)
    return f"{value[:visible]}{'•' * min(12, len(value) - visible * 2)}{value[-visible:]}"


def mask_otp(value: str) -> str:
    if len(value) <= 2:
        return "•" * len(value)
    return value[0] + "•" * (len(value) - 2) + value[-1]
