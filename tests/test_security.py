from __future__ import annotations

import pytest

from app.security import (
    Cipher,
    LoginThrottle,
    hash_password,
    mask_otp,
    mask_secret,
    new_csrf_token,
    verify_password,
)


def test_cipher_round_trip_and_json_preserves_unicode() -> None:
    cipher = Cipher("a-test-master-key")
    assert cipher.decrypt(cipher.encrypt("验证码：你好")) == "验证码：你好"
    payload = {"邮箱": "user@example.com", "enabled": True}
    assert cipher.decrypt_json(cipher.encrypt_json(payload)) == payload


def test_cipher_rejects_wrong_key_and_non_object_json() -> None:
    token = Cipher("key-one").encrypt("secret")
    with pytest.raises(ValueError, match="Encrypted value"):
        Cipher("key-two").decrypt(token)

    token = Cipher("key-one").encrypt("[1, 2]")
    with pytest.raises(ValueError, match="not an object"):
        Cipher("key-one").decrypt_json(token)


def test_fingerprint_is_deterministic_but_keyed() -> None:
    first = Cipher("key-one").fingerprint("123456")
    assert first == Cipher("key-one").fingerprint("123456")
    assert first != Cipher("key-one").fingerprint("654321")
    assert first != Cipher("key-two").fingerprint("123456")
    assert len(first) == 64


def test_password_hash_verification_and_csrf_entropy() -> None:
    encoded = hash_password("correct horse battery staple")
    assert verify_password(encoded, "correct horse battery staple")
    assert not verify_password(encoded, "wrong password")
    assert not verify_password("not-a-password-hash", "wrong password")
    assert len(new_csrf_token()) >= 32


@pytest.mark.parametrize(
    ("value", "expected"),
    [("123456", "1••••6"), ("AB", "••"), ("A", "•"), ("", "")],
)
def test_mask_otp_never_exposes_middle_digits(value: str, expected: str) -> None:
    assert mask_otp(value) == expected


def test_mask_secret_only_exposes_edges() -> None:
    assert mask_secret("abcdefghijkl", visible=2) == "ab••••••••kl"
    assert mask_secret("abcd", visible=2) == "••••"


def test_login_throttle_locks_only_the_failing_source() -> None:
    throttle = LoginThrottle(limit=3, window_seconds=60, lock_seconds=30)
    assert throttle.record_failure("10.0.0.5") == 0
    assert throttle.record_failure("10.0.0.5") == 0
    assert throttle.record_failure("10.0.0.5") == 30

    assert throttle.blocked_for("10.0.0.5") > 0
    assert throttle.blocked_for("10.0.0.6") == 0

    throttle.reset("10.0.0.5")
    assert throttle.blocked_for("10.0.0.5") == 0


def test_login_throttle_bounds_tracked_sources() -> None:
    throttle = LoginThrottle(limit=5, max_sources=4)
    for index in range(50):
        throttle.record_failure(f"source-{index}")
    assert throttle.tracked_sources <= 4
