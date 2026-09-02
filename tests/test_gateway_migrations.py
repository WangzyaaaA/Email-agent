from __future__ import annotations

from sqlalchemy import create_engine, inspect, select

from push_gateway.config import GatewaySettings
from push_gateway.database import create_gateway_engine, create_session_factory, init_gateway_db
from push_gateway.migrations import MIGRATION_TABLE, backup_database, schema_version, upgrade_schema
from push_gateway.models import Device


def test_gateway_schema_baseline_is_versioned_idempotent_and_preserves_rows() -> None:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
    )
    engine = create_gateway_engine(settings)
    init_gateway_db(engine)
    factory = create_session_factory(engine)
    with factory() as db:
        db.add(Device(device_id="device_schema_baseline", key_id="key_schema_baseline", status="active"))
        db.commit()

    assert schema_version(engine) == 1
    assert MIGRATION_TABLE in inspect(engine).get_table_names()
    assert upgrade_schema(engine) == []
    with factory() as db:
        assert db.scalar(select(Device.device_id)) == "device_schema_baseline"


def test_gateway_backup_is_consistent_and_contains_existing_rows(tmp_path) -> None:
    database = tmp_path / "gateway.db"
    database_url = f"sqlite:///{database.as_posix()}"
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url=database_url,
        firebase_project_id="test-project",
    )
    engine = create_gateway_engine(settings)
    init_gateway_db(engine)
    factory = create_session_factory(engine)
    with factory() as db:
        db.add(Device(device_id="device_in_backup", key_id="key_in_backup", status="active"))
        db.commit()

    backup = backup_database(database_url)
    backup_engine = create_engine(f"sqlite:///{backup.as_posix()}")
    with backup_engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA integrity_check").scalar_one() == "ok"
    backup_factory = create_session_factory(backup_engine)
    with backup_factory() as db:
        assert db.scalar(select(Device.device_id)) == "device_in_backup"


def test_gateway_schema_baseline_rejects_incomplete_existing_tables() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE devices (id INTEGER PRIMARY KEY)")

    try:
        upgrade_schema(engine)
    except RuntimeError as exc:
        assert str(exc).startswith("gateway_schema_incompatible:")
    else:
        raise AssertionError("Incomplete gateway schema must fail closed")
