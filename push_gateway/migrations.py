from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Engine, inspect, text

from push_gateway.database import GatewayBase


SCHEMA_VERSION = 1
MIGRATION_TABLE = "gateway_schema_migrations"


def _validate_model_schema(connection) -> None:  # type: ignore[no-untyped-def]
    inspector = inspect(connection)
    existing_tables = set(inspector.get_table_names())
    for table in GatewayBase.metadata.sorted_tables:
        if table.name not in existing_tables:
            raise RuntimeError(f"gateway_schema_incompatible:{table.name}:missing_table")
        existing_columns = {column["name"] for column in inspector.get_columns(table.name)}
        missing = sorted(column.name for column in table.columns if column.name not in existing_columns)
        if missing:
            raise RuntimeError(f"gateway_schema_incompatible:{table.name}:missing_columns:{','.join(missing)}")


def upgrade_schema(engine: Engine) -> list[int]:
    """Record and verify the v1 gateway schema without rewriting existing rows."""
    applied: list[int] = []
    with engine.begin() as connection:
        connection.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} ("
                "version INTEGER PRIMARY KEY NOT NULL, "
                "applied_at DATETIME NOT NULL"
                ")"
            )
        )
        current = connection.execute(text(f"SELECT COALESCE(MAX(version), 0) FROM {MIGRATION_TABLE}")).scalar_one()
        if current > SCHEMA_VERSION:
            raise RuntimeError("gateway_schema_newer_than_application")
        _validate_model_schema(connection)
        if current < 1:
            connection.execute(
                text(f"INSERT INTO {MIGRATION_TABLE} (version, applied_at) VALUES (:version, :applied_at)"),
                {"version": 1, "applied_at": datetime.now(timezone.utc).isoformat()},
            )
            applied.append(1)
    return applied


def schema_version(engine: Engine) -> int:
    if MIGRATION_TABLE not in set(inspect(engine).get_table_names()):
        return 0
    with engine.connect() as connection:
        return int(connection.execute(text(f"SELECT COALESCE(MAX(version), 0) FROM {MIGRATION_TABLE}")).scalar_one())


def _sqlite_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix) or database_url.endswith(":memory:"):
        raise ValueError("Gateway backup only supports file-backed sqlite:/// URLs")
    return Path(database_url.removeprefix(prefix)).expanduser().resolve()


def backup_database(database_url: str) -> Path:
    """Create a WAL-consistent SQLite backup and verify it before returning."""
    source = _sqlite_path(database_url)
    if not source.is_file():
        raise FileNotFoundError("Gateway database does not exist")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = source.with_name(f"{source.name}.pre-gateway-upgrade-{stamp}.bak")
    if target.exists():
        raise FileExistsError("Gateway backup target already exists")
    with sqlite3.connect(source) as source_db, sqlite3.connect(target) as target_db:
        source_db.backup(target_db)
        result = target_db.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        target.unlink(missing_ok=True)
        raise RuntimeError("Gateway backup integrity check failed")
    return target
