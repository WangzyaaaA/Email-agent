from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Engine, inspect, text


NOTIFICATION_COLUMNS: dict[str, str] = {
    "channel": "VARCHAR(30) NOT NULL DEFAULT 'wxpusher'",
    "route": "VARCHAR(30) NOT NULL DEFAULT 'primary'",
    "route_attempts": "INTEGER NOT NULL DEFAULT 0",
    "first_route_attempt_at": "DATETIME",
    "wire_envelope_encrypted": "TEXT",
    "gateway_message_id": "VARCHAR(128)",
    "fallback_reason_code": "VARCHAR(60)",
}


def upgrade_schema(engine: Engine) -> list[str]:
    """Idempotently upgrades legacy SQLite databases without deleting user rows."""
    existing_tables = set(inspect(engine).get_table_names())
    if "notifications" not in existing_tables:
        return []
    existing = {column["name"] for column in inspect(engine).get_columns("notifications")}
    added: list[str] = []
    with engine.begin() as connection:
        for name, declaration in NOTIFICATION_COLUMNS.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE notifications ADD COLUMN {name} {declaration}"))
                added.append(name)
    return added


def downgrade_schema(engine: Engine) -> list[str]:
    """Removes only v1 push columns; callers must make a backup first."""
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Only the documented SQLite downgrade is supported")
    existing = {column["name"] for column in inspect(engine).get_columns("notifications")}
    removed: list[str] = []
    with engine.begin() as connection:
        for name in reversed(list(NOTIFICATION_COLUMNS)):
            if name in existing:
                connection.execute(text(f"ALTER TABLE notifications DROP COLUMN {name}"))
                removed.append(name)
    return removed


def _sqlite_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix) or database_url.endswith(":memory:"):
        raise ValueError("The backup helper only supports file-backed sqlite:/// URLs")
    return Path(database_url.removeprefix(prefix)).expanduser().resolve()


def backup_database(database_url: str) -> Path:
    """Create a WAL-consistent backup with the SQLite online backup API.

    Copying the database file is unsafe while the application (or a crashed
    process) still has committed pages in ``-wal``: the copy would silently miss
    the newest rows. The backup API reads a consistent snapshot instead, and the
    result is verified before it is handed back to the operator.
    """
    source = _sqlite_path(database_url)
    if not source.is_file():
        raise FileNotFoundError("Database does not exist")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = source.with_name(f"{source.name}.pre-fcm-{stamp}.bak")
    if target.exists():
        raise FileExistsError("Backup target already exists")
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
        result = target_db.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        target.unlink(missing_ok=True)
        raise RuntimeError("Database backup integrity check failed")
    return target


def main() -> None:
    from sqlalchemy import create_engine

    parser = argparse.ArgumentParser(description="Mail Sentinel schema upgrade with an explicit pre-upgrade backup")
    parser.add_argument("command", choices=("upgrade", "downgrade"))
    parser.add_argument("--database-url", required=True)
    args = parser.parse_args()
    backup = backup_database(args.database_url)
    engine = create_engine(args.database_url)
    changed = upgrade_schema(engine) if args.command == "upgrade" else downgrade_schema(engine)
    print(f"backup={backup}")
    print(f"changed={','.join(changed) if changed else 'none'}")


if __name__ == "__main__":
    main()
