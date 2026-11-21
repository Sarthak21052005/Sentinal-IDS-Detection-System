
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Resolve the backend directory.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SQLite database location.
DATABASE_PATH = os.path.join(BASE_DIR, "sentinal.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Create SQLite engine.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Create database sessions.
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for SQLAlchemy models.
Base = declarative_base()


# FastAPI database dependency.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
