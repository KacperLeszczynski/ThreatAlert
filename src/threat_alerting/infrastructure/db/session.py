from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from threat_alerting.infrastructure.db.tables import Base
from threat_alerting.settings import Settings

SessionFactory = sessionmaker[Session]


def create_database_engine(settings: Settings, **engine_options: Any) -> Engine:
    url = make_url(settings.database_url)
    if url.get_backend_name() == "sqlite" and url.database not in {None, "", ":memory:"}:
        Path(url.database).parent.mkdir(parents=True, exist_ok=True)

    connect_args = dict(engine_options.pop("connect_args", {}))
    if url.get_backend_name() == "sqlite":
        connect_args.setdefault("check_same_thread", False)

    engine = create_engine(url, connect_args=connect_args, **engine_options)
    if url.get_backend_name() == "sqlite":
        _register_sqlite_foreign_keys(engine)
    return engine


def _register_sqlite_foreign_keys(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def configure_connection(dbapi_connection, _connection_record) -> None:
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    @event.listens_for(engine, "begin")
    def emit_begin(connection) -> None:
        connection.exec_driver_sql("BEGIN")


def create_session_factory(engine: Engine) -> SessionFactory:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(session_factory: SessionFactory) -> Iterator[Session]:
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
