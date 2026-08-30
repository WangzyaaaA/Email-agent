from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from push_gateway.security import b64url_decode


ID_PATTERN = r"^[A-Za-z0-9_-]{8,128}$"
B64_PATTERN = r"^[A-Za-z0-9_-]+$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProvisionRequest(StrictModel):
    device_id: str = Field(pattern=ID_PATTERN)
    key_id: str = Field(pattern=ID_PATTERN)
    device_token: str = Field(min_length=43, max_length=64, pattern=B64_PATTERN)
    device_auth_key: str = Field(min_length=43, max_length=64, pattern=B64_PATTERN)
    activation_expires_at: str = Field(min_length=20, max_length=32)


class RegisterRequest(StrictModel):
    device_id: str = Field(pattern=ID_PATTERN)
    fcm_token: str = Field(min_length=16, max_length=4096)
    registration_version: int = Field(ge=1, le=2_147_483_647)
    app_protocol_version: int = Field(ge=1, le=100)


class DeviceStatusRequest(StrictModel):
    device_id: str = Field(pattern=ID_PATTERN)
    notifications_enabled: bool
    otp_channel_enabled: bool
    important_channel_enabled: bool
    digest_channel_enabled: bool
    app_protocol_version: int = Field(ge=1, le=100)


class Envelope(StrictModel):
    version: Literal["1"]
    message_id: str = Field(pattern=ID_PATTERN)
    device_id: str = Field(pattern=ID_PATTERN)
    key_id: str = Field(pattern=ID_PATTERN)
    priority: Literal["normal", "high"]
    expires_at: str = Field(min_length=20, max_length=32)
    nonce: str = Field(min_length=16, max_length=32, pattern=B64_PATTERN)
    ciphertext: str = Field(min_length=22, max_length=3500, pattern=B64_PATTERN)

    @field_validator("nonce")
    @classmethod
    def nonce_is_96_bits(cls, value: str) -> str:
        try:
            b64url_decode(value, expected_length=12)
        except ValueError as exc:
            raise ValueError("invalid_nonce") from exc
        return value

    @field_validator("ciphertext")
    @classmethod
    def ciphertext_contains_tag(cls, value: str) -> str:
        try:
            decoded = b64url_decode(value)
        except ValueError as exc:
            raise ValueError("invalid_ciphertext") from exc
        if len(decoded) < 16:
            raise ValueError("invalid_ciphertext")
        return value


class MessageRequest(StrictModel):
    idempotency_key: str = Field(pattern=ID_PATTERN)
    envelope: Envelope


class AckRequest(StrictModel):
    device_id: str = Field(pattern=ID_PATTERN)
    result: Literal["shown", "stored_notifications_disabled", "expired", "decrypt_failed"]


class PendingQuery(StrictModel):
    cursor: str | None = Field(default=None, pattern=ID_PATTERN)
    limit: int = Field(default=50, ge=1, le=50)
