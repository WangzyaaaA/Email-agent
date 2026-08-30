from __future__ import annotations

import argparse
import shutil
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
    source = _sqlite_path(database_url)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = source.with_name(f"{source.name}.pre-fcm-{stamp}.bak")
    shutil.copy2(source, target)
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
