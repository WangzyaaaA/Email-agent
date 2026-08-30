from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from app.migrations import NOTIFICATION_COLUMNS, downgrade_schema, upgrade_schema


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
