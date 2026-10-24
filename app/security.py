from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import deque
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


class LoginThrottle:
    """Bounded per-source failure tracking for the administrator password.

    Argon2 makes each verification expensive for the attacker, but an unlimited
    oracle still allows a slow offline-style brute force at network speed. The
    table is capped and pruned so rotating source addresses cannot turn the
    limiter itself into a memory exhaustion vector.
    """

    def __init__(
        self,
        *,
        limit: int = 5,
        window_seconds: float = 900.0,
        lock_seconds: float = 300.0,
        max_sources: int = 2048,
    ) -> None:
        self.limit = max(1, limit)
        self.window_seconds = window_seconds
        self.lock_seconds = lock_seconds
        self.max_sources = max(1, max_sources)
        self._failures: dict[str, deque[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def blocked_for(self, source: str) -> float:
        """Return the remaining lockout in seconds, or 0 when the source may try."""
        with self._lock:
            now = time.monotonic()
            until = self._blocked_until.get(source, 0.0)
            if until > now:
                return until - now
            self._blocked_until.pop(source, None)
            return 0.0

    def record_failure(self, source: str) -> float:
        """Track one failed attempt and return the new lockout (0 when still allowed)."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            if source not in self._failures and len(self._failures) >= self.max_sources:
                oldest = min(self._failures, key=lambda key: self._failures[key][-1] if self._failures[key] else 0.0)
                self._failures.pop(oldest, None)
            entries = self._failures.setdefault(source, deque())
            entries.append(now)
            while len(entries) > self.limit:
                entries.popleft()
            if len(entries) >= self.limit:
                entries.clear()
                self._blocked_until[source] = now + self.lock_seconds
                return self.lock_seconds
            return 0.0

    def reset(self, source: str) -> None:
        with self._lock:
            self._failures.pop(source, None)
            self._blocked_until.pop(source, None)

    @property
    def tracked_sources(self) -> int:
        with self._lock:
            return len(self._failures)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        for key in [key for key, values in self._failures.items() if not values or values[-1] < cutoff]:
            self._failures.pop(key, None)
        for key in [key for key, until in self._blocked_until.items() if until <= now]:
            self._blocked_until.pop(key, None)


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
