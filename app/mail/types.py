from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class FolderInfo:
    name: str
    role: str
    flags: tuple[str, ...] = ()


@dataclass(slots=True)
class ParsedMail:
    message_id: str | None
    subject: str
    from_address: str
    from_name: str
    to_addresses: list[str]
    received_at: datetime
    text: str
    auth_status: str
    references: list[str] = field(default_factory=list)
    in_reply_to: str | None = None
    attachment_names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RemoteMessage:
    folder: str
    folder_role: str
    uidvalidity: str
    uid: int
    raw: bytes
    internal_date: datetime | None
    historical: bool


@dataclass(slots=True)
class DetectionResult:
    provider: str
    host: str
    port: int
    confidence: str
    evidence: list[str]


@dataclass(slots=True)
class ConnectionTestResult:
    ok: bool
    code: str
    message: str
    capabilities: list[str] = field(default_factory=list)
    folders: list[FolderInfo] = field(default_factory=list)
