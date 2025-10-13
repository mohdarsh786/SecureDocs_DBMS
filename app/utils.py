"""
Utility functions for SecureDocs.
Common helper functions used across the application.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.models import Base


def get_database_url() -> str:
    """Get database URL from environment variable."""
    return os.getenv("DATABASE_URL", "mysql+pymysql://admin:password@localhost:3306/securedocs")


def init_database():
    """
    Initialize database connection and create all tables.
    Called at application startup.
    """
    database_url = get_database_url()
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(bind=engine)
    return engine


def get_db_session(engine):
    """Create a new database session."""
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


def get_db():
    """
    Dependency function for FastAPI to get database session.
    Yields session and ensures cleanup after request.
    """
    database_url = get_database_url()
    engine = create_engine(database_url, echo=False)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def validate_file_size(file_size: int, max_size_mb: int = 100) -> bool:
    """
    Validate file size against maximum allowed size.
    Default max size is 100MB.
    """
    max_size_bytes = max_size_mb * 1024 * 1024
    return file_size <= max_size_bytes


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal attacks.
    Removes path separators and hidden file indicators.
    """
    filename = os.path.basename(filename)
    filename = filename.replace("..", "")
    filename = filename.replace("/", "")
    filename = filename.replace("\\", "")
    return filename


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def get_log_level() -> str:
    """Get logging level from environment variable."""
    return os.getenv("LOG_LEVEL", "info").upper()
