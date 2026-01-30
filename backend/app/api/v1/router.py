"""
API v1 Router

Aggregates all v1 API routes.
"""

from fastapi import APIRouter
from app.api.v1 import auth, dashboard, scans, assets, discovery, cbom, posture, rating, reports

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(scans.router)
api_router.include_router(assets.router)
api_router.include_router(discovery.router)
api_router.include_router(cbom.router)
api_router.include_router(posture.router)
api_router.include_router(rating.router)
api_router.include_router(reports.router)
