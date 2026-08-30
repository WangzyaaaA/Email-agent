from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, SystemSetting
from app.security import Cipher


def set_setting(db: Session, key: str, value: str, cipher: Cipher | None = None) -> None:
    cipher = cipher or Cipher()
    row = db.get(SystemSetting, key)
    encrypted = cipher.encrypt(value)
    if row:
        row.value_encrypted = encrypted
    else:
        db.add(SystemSetting(key=key, value_encrypted=encrypted))


def get_setting(db: Session, key: str, default: str | None = None, cipher: Cipher | None = None) -> str | None:
    row = db.get(SystemSetting, key)
    if not row:
        return default
    return (cipher or Cipher()).decrypt(row.value_encrypted)


def has_admin(db: Session) -> bool:
    return db.get(SystemSetting, "admin_password_hash") is not None


def audit(db: Session, event_type: str, detail: str) -> None:
    # Detail must be metadata-only and must never include message bodies or secrets.
    db.add(AuditEvent(event_type=event_type, detail=detail[:2000]))


def all_settings(db: Session, keys: list[str]) -> dict[str, str]:
    rows = db.scalars(select(SystemSetting).where(SystemSetting.key.in_(keys))).all()
    cipher = Cipher()
    return {row.key: cipher.decrypt(row.value_encrypted) for row in rows}
