from __future__ import annotations

import sqlite3

from sqlalchemy import create_engine, inspect, text

from app.migrations import NOTIFICATION_COLUMNS, backup_database, downgrade_schema, upgrade_schema


def test_notification_schema_upgrade_preserves_legacy_rows_and_is_reversible() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE notifications (id INTEGER PRIMARY KEY, kind VARCHAR(40), title TEXT)"))
        connection.execute(text("INSERT INTO notifications (id, kind, title) VALUES (7, 'otp', 'masked')"))
    assert set(upgrade_schema(engine)) == set(NOTIFICATION_COLUMNS)
    assert upgrade_schema(engine) == []
    with engine.connect() as connection:
        row = connection.execute(text("SELECT id, kind, title, channel FROM notifications WHERE id=7")).one()
        assert row == (7, "otp", "masked", "wxpusher")
    assert set(downgrade_schema(engine)) == set(NOTIFICATION_COLUMNS)
    assert {column["name"] for column in inspect(engine).get_columns("notifications")} == {"id", "kind", "title"}


def test_backup_uses_sqlite_snapshot_so_committed_wal_rows_are_included(tmp_path) -> None:
    path = tmp_path / "mail_sentinel.db"
    writer = sqlite3.connect(path)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE notifications (id INTEGER PRIMARY KEY, title TEXT)")
        writer.execute("INSERT INTO notifications (id, title) VALUES (1, 'wal-row')")
        writer.commit()
        # Keep the writer open: the newest commit may still live only in the WAL,
        # which a plain file copy would miss.
        backup = backup_database(f"sqlite:///{path.as_posix()}")
        with sqlite3.connect(backup) as copy:
            assert copy.execute("SELECT title FROM notifications").fetchone() == ("wal-row",)
    finally:
        writer.close()
