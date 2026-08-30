from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from push_gateway.database import GatewayBase


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GatewayCredential(GatewayBase):
    __tablename__ = "gateway_credentials"
    __table_args__ = (UniqueConstraint("kind", "token_fingerprint", name="uq_gateway_credential"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    token_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(GatewayBase):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    key_id: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(40), default="pending_activation", index=True)
    device_token_fingerprint: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    device_auth_key_encrypted: Mapped[str | None] = mapped_column(Text)
    fcm_token_encrypted: Mapped[str | None] = mapped_column(Text)
    registration_version: Mapped[int] = mapped_column(Integer, default=0)
    activation_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notifications_enabled: Mapped[bool | None] = mapped_column(Boolean)
    otp_channel_enabled: Mapped[bool | None] = mapped_column(Boolean)
    important_channel_enabled: Mapped[bool | None] = mapped_column(Boolean)
    digest_channel_enabled: Mapped[bool | None] = mapped_column(Boolean)
    app_protocol_version: Mapped[int | None] = mapped_column(Integer)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class GatewayMessage(GatewayBase):
    __tablename__ = "gateway_messages"
    __table_args__ = (
        Index("ix_gateway_delivery", "status", "next_attempt_at"),
        UniqueConstraint("idempotency_fingerprint", name="uq_gateway_idempotency"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_message_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    message_id: Mapped[str] = mapped_column(String(128), index=True)
    idempotency_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    envelope_digest: Mapped[str] = mapped_column(String(64))
    envelope_encrypted: Mapped[str | None] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(10))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(40), default="accepted", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fcm_name_fingerprint: Mapped[str | None] = mapped_column(String(64))
    last_error_code: Mapped[str | None] = mapped_column(String(60))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class RequestNonce(GatewayBase):
    __tablename__ = "request_nonces"
    __table_args__ = (UniqueConstraint("device_id", "nonce_fingerprint", name="uq_device_nonce"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    nonce_fingerprint: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class OperationalEvent(GatewayBase):
    __tablename__ = "operational_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    code: Mapped[str] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
