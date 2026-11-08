import os
from contextlib import contextmanager

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./surfacemap.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
if engine.dialect.name == "sqlite":
    @event.listens_for(engine, "connect")
    def enforce_sqlite_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass


@contextmanager
def run_lock(namespace: int, run_id: int):
    """Keep a PostgreSQL session lock across the run's short write transactions."""
    if engine.dialect.name != "postgresql":
        yield True
        return
    params = {"namespace": namespace, "id": run_id}
    with engine.connect() as connection:
        acquired = connection.scalar(text("SELECT pg_try_advisory_lock(:namespace, :id)"), params)
        connection.commit()
        try:
            yield acquired
        finally:
            if acquired:
                connection.execute(text("SELECT pg_advisory_unlock(:namespace, :id)"), params)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
