from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProviderPreset(StrEnum):
    QQ = "qq"
    GMAIL = "gmail"
    ALIBABA = "alibaba"
    CUSTOM = "custom"


class ActionStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    SNOOZED = "snoozed"
    DONE = "done"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SENDING = "sending"
    EXPIRED = "expired"


class MailboxAccount(Base):
    __tablename__ = "mailbox_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email_address: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(30))
    detected_provider: Mapped[str | None] = mapped_column(String(30))
    imap_host: Mapped[str] = mapped_column(String(255))
    imap_port: Mapped[int] = mapped_column(Integer, default=993)
    username: Mapped[str] = mapped_column(String(320))
    password_encrypted: Mapped[str] = mapped_column(Text)
    host_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    last_error_code: Mapped[str | None] = mapped_column(String(60))
    last_error: Mapped[str | None] = mapped_column(Text)
    capabilities: Mapped[str | None] = mapped_column(Text)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    messages: Mapped[list[MessageMetadata]] = relationship(back_populates="account", cascade="all, delete-orphan")


class FolderCheckpoint(Base):
    __tablename__ = "folder_checkpoints"
    __table_args__ = (UniqueConstraint("account_id", "folder", name="uq_checkpoint_account_folder"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("mailbox_accounts.id", ondelete="CASCADE"), index=True)
    folder: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(30), default="other")
    uidvalidity: Mapped[str] = mapped_column(String(64))
    last_uid: Mapped[int] = mapped_column(Integer, default=0)
    initialized: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class MessageMetadata(Base):
    __tablename__ = "message_metadata"
    __table_args__ = (
        UniqueConstraint("account_id", "folder", "uidvalidity", "uid", name="uq_message_remote"),
        Index("ix_message_received_category", "received_at", "category"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("mailbox_accounts.id", ondelete="CASCADE"), index=True)
    folder: Mapped[str] = mapped_column(String(512))
    uidvalidity: Mapped[str] = mapped_column(String(64))
    uid: Mapped[int] = mapped_column(Integer)
    message_id: Mapped[str | None] = mapped_column(String(998), index=True)
    thread_key: Mapped[str | None] = mapped_column(String(998), index=True)
    direction: Mapped[str] = mapped_column(String(20), default="inbox")
    from_address: Mapped[str] = mapped_column(String(320), default="")
    from_name: Mapped[str] = mapped_column(String(320), default="")
    to_addresses: Mapped[str] = mapped_column(Text, default="")
    subject: Mapped[str] = mapped_column(Text, default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    auth_status: Mapped[str] = mapped_column(String(20), default="unknown")
    category: Mapped[str] = mapped_column(String(60), default="other")
    importance: Mapped[str] = mapped_column(String(20), default="low")
    summary: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    action_required: Mapped[bool] = mapped_column(Boolean, default=False)
    deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    llm_status: Mapped[str] = mapped_column(String(30), default="not_used")
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    account: Mapped[MailboxAccount] = relationship(back_populates="messages")


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_rule_kind_value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    value: Mapped[str] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OtpCandidate(Base):
    __tablename__ = "otp_candidates"
    __table_args__ = (UniqueConstraint("message_id", name="uq_otp_candidate_message"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("message_metadata.id", ondelete="CASCADE"), index=True)
    sender_address: Mapped[str] = mapped_column(String(320))
    sender_domain: Mapped[str] = mapped_column(String(255))
    code_fingerprint: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(30), default="pending")
    risk: Mapped[str] = mapped_column(String(30), default="unknown_auth")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionItem(Base):
    __tablename__ = "action_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int | None] = mapped_column(ForeignKey("message_metadata.id", ondelete="SET NULL"), index=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(Text)
    detail: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default=ActionStatus.NEW.value, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    thread_key: Mapped[str | None] = mapped_column(String(998), index=True)
    reminder_24_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    reminder_2_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    followup_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notification_outbox", "status", "next_attempt_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    priority: Mapped[str] = mapped_column(String(20), default="normal")
    title: Mapped[str] = mapped_column(Text)
    content_preview: Mapped[str] = mapped_column(Text, default="")
    payload_encrypted: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default=NotificationStatus.PENDING.value, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(128), unique=True)
    external_id: Mapped[str | None] = mapped_column(String(128))
    channel: Mapped[str] = mapped_column(String(30), default="wxpusher")
    route: Mapped[str] = mapped_column(String(30), default="primary")
    route_attempts: Mapped[int] = mapped_column(Integer, default=0)
    first_route_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    wire_envelope_encrypted: Mapped[str | None] = mapped_column(Text)
    gateway_message_id: Mapped[str | None] = mapped_column(String(128))
    fallback_reason_code: Mapped[str | None] = mapped_column(String(60))
    last_error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PushDevice(Base):
    __tablename__ = "push_devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    key_id: Mapped[str] = mapped_column(String(128))
    gateway_url: Mapped[str] = mapped_column(String(500))
    content_root_key_encrypted: Mapped[str | None] = mapped_column(Text)
    pending_device_token_encrypted: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(40), default="pending_activation", index=True)
    pairing_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_pending: Mapped[bool] = mapped_column(Boolean, default=False)
    last_error_code: Mapped[str | None] = mapped_column(String(60))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ProcessingJob(Base):
    __tablename__ = "processing_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("message_metadata.id", ondelete="CASCADE"), unique=True)
    payload_encrypted: Mapped[str | None] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DigestRun(Base):
    __tablename__ = "digest_runs"
    __table_args__ = (UniqueConstraint("period_key", name="uq_digest_period"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    period_key: Mapped[str] = mapped_column(String(100))
    digest_types: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(500), default="")
    content_encrypted: Mapped[str | None] = mapped_column(Text)
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    notification_id: Mapped[int | None] = mapped_column(ForeignKey("notifications.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value_encrypted: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
