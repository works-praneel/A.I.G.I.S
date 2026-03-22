from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from backend.config import settings
import logging

# Configure logging to track database connection issues
logger = logging.getLogger(__name__)

# 1. Create the SQL Engine
# We add 'pool_pre_ping' to handle stale connections (common in Docker)
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

# 2. Configure the Session Factory
# SessionLocal is used to create unique sessions for each request/task
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# 3. Define the Declarative Base
# All models in models.py must inherit from this Base
Base = declarative_base()

def get_db():
    """
    Dependency for FastAPI routes. 
    Usage: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database session error: {e}")
        raise
    finally:
        db.close()

def init_db():
    """
    Utility to initialize tables. 
    Called in main.py on startup.
    """
    try:
        from backend.database import models
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")