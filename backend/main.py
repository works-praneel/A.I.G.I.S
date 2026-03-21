from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.api.scan_routes import router as scan_router
from backend.database.database import engine
from backend.database.models import Base

# Initialize DB Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="A.I.G.I.S API")

# Enable CORS for internal Docker traffic
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prefix must be /api/v1 to match the frontend constant
app.include_router(scan_router, prefix="/api/v1")

@app.get("/")
async def health_check():
    return {"status": "AIGIS Backend Online"}