from fastapi import APIRouter

from backend.api.auth_routes import router as auth_router
from backend.api.scan_routes import router as scan_router
from backend.api.url_scan_routes import router as url_scan_router
from backend.api.report_routes import router as report_router
from backend.api.admin_routes import router as admin_router


api_router = APIRouter(prefix="/api")


api_router.include_router(auth_router, prefix="/auth")
api_router.include_router(scan_router, prefix="/scan")
api_router.include_router(url_scan_router, prefix="/scan")
api_router.include_router(report_router, prefix="/reports")
api_router.include_router(admin_router, prefix="/admin")