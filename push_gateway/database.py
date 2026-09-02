from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from push_gateway.config import GatewaySettings


class GatewayBase(DeclarativeBase):
    pass


def create_gateway_engine(settings: GatewaySettings) -> Engine:
    connect_args = {"check_same_thread": False, "timeout": 30} if settings.database_url.startswith("sqlite") else {}
    pool_options = {"poolclass": StaticPool} if settings.database_url == "sqlite:///:memory:" else {}
    engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True, **pool_options)
    if settings.database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragmas(connection, _record) -> None:  # type: ignore[no-untyped-def]
            cursor = connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


def init_gateway_db(engine: Engine) -> None:
    from push_gateway import models  # noqa: F401
    from push_gateway.migrations import upgrade_schema

    GatewayBase.metadata.create_all(engine)
    upgrade_schema(engine)


def session_dependency(factory: sessionmaker[Session]):
    def _get_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session
    return _get_db
