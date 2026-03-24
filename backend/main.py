import logging
from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text

from backend.api.scan_routes import router as scan_router
from backend.api.url_scan_routes import router as url_scan_router
from backend.api.auth_routes import router as auth_router
from backend.api.admin_routes import router as admin_router
from backend.api.report_routes import router as report_router
from backend.database.database import engine
from backend.database.models import Base

# Setup basic logging for the migrations
logger = logging.getLogger(__name__)

def run_auto_migrations():
    """Automatically update existing database tables with new columns."""
    logger.info("Running automatic database migrations...")
    migration_sql = """
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id);
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS scan_type VARCHAR DEFAULT 'file';
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS target VARCHAR DEFAULT '';
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS vulnerability_count INTEGER DEFAULT 0;
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS threat_score FLOAT DEFAULT 0.0;
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS highest_severity VARCHAR DEFAULT 'none';
        ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id);
    """
    try:
        # engine.begin() automatically commits the transaction if successful
        with engine.begin() as conn:
            conn.execute(text(migration_sql))
        logger.info("Database migrations completed successfully.")
    except Exception as e:
        logger.error(f"Database migration failed: {e}")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="A.I.G.I.S — AI-powered Security Scanner")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Run automatic schema migrations for existing tables
run_auto_migrations()


# Route map:
#   /api/scan/upload          ← scan_router  (file upload)
#   /api/scan/upload/zip      ← scan_router  (zip upload)
#   /api/scan/url             ← url_scan_router
#   /api/scan/repository      ← url_scan_router
#   /api/scan/status/{job_id} ← url_scan_router
#   /api/scan/cancel/{job_id} ← url_scan_router  (single definition)
#   /api/auth/...             ← auth_router
#   /api/admin/...            ← admin_router
#   /api/reports/...          ← report_router

app.include_router(scan_router,     prefix="/api/scan")
app.include_router(url_scan_router)          
app.include_router(auth_router,     prefix="/api/auth")
app.include_router(admin_router,    prefix="/api/admin")
app.include_router(report_router,   prefix="/api/reports")
