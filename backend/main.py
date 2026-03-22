from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from backend.api.scan_routes import router as scan_router
from backend.database.database import engine
from backend.database.models import Base
import os

# --- DATABASE INITIALIZATION ---
# Automatically creates all tables defined in your models
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="A.I.G.I.S API",
    description="Backend for Autonomous Guard & Inspection System",
    version="1.0.0"
)

# --- CORS MIDDLEWARE ---
# Essential for allowing the Streamlit frontend to communicate with the FastAPI backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ROUTER REGISTRATION ---
# Mounted with /api/v1 prefix to maintain versioning consistency
app.include_router(scan_router, prefix="/api/v1")

@app.get("/")
async def health_check():
    return {"status": "AIGIS Backend Online", "version": "v1"}

@app.get("/api/v1/scan/download/{job_id}")
async def download_report(job_id: str):
    """Bridge to serve files from the internal container to the user's browser."""
    # Path where the worker saves the PDF inside the container
    report_path = f"/app/backend/reporting/reports/report_{job_id}.pdf"
    
    if os.path.exists(report_path):
        return FileResponse(
            path=report_path, 
            filename=f"AIGIS_Report_{job_id}.pdf", 
            media_type='application/pdf'
        )
    else:
        raise HTTPException(status_code=404, detail="Report not found. The scan might still be in progress.")