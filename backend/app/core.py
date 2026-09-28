"""Settings, DB models, session."""
from datetime import datetime, timezone

from pgvector.sqlalchemy import Vector
from pydantic_settings import BaseSettings
from sqlalchemy import Column, text
from sqlmodel import Field, Session, SQLModel, create_engine


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://app:app@db:5432/app"
    openai_api_key: str
    jwt_secret: str
    llm_base_url: str | None = None
    embed_dims: int = 1536
    chat_model: str = "gpt-4o-mini"
    embed_model: str = "text-embedding-3-small"  # 1536 dims


settings = Settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(unique=True, index=True)
    password_hash: str
    role: str = "viewer"  # admin | analyst | viewer


class Chunk(SQLModel, table=True):  # RAG knowledge base
    id: int | None = Field(default=None, primary_key=True)
    source: str
    text: str
    embedding: list[float] = Field(sa_column=Column(Vector(1536)))


class AuditLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int
    action: str
    detail: str = ""
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def init_db():
    with engine.begin() as c:
        c.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as s:
        yield s
