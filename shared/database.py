"""Database module - SQLAlchemy engine, session factory, Base."""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from shared.config import settings

# Create database engine
engine = create_engine(settings.DATABASE_URL, echo=False)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()

def get_db():
    """Dependency for getting database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)
