from sqlmodel import SQLModel, create_engine, Session
from app.config import settings
import os

# Ensure data directory exists for sqlite
if settings.database_url.startswith("sqlite:///"):
    db_path = settings.database_url.replace("sqlite:///,"")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

engine = create_engine(
    settings.database_url,
    echo=False,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
)

def get_session():
    with Session(engine) as session:
        yield session


def init_db():
    from app import models  # ensure models are imported
    SQLModel.metadata.create_all(engine)