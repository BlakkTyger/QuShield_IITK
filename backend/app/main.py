"""
QuShield API - Main Application

FastAPI backend for QuShield Quantum-Safe Cryptography Scanner.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.database import init_db
from app.api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
## QuShield API

Quantum-Safe Cryptography Scanner API for:
- **Asset Discovery**: CT logs, DNS enumeration, subdomain brute-forcing
- **TLS Analysis**: Deep protocol inspection with SSLyze
- **PQC Classification**: NIST FIPS 203/204/205 compliance checking
- **HNDL Risk Scoring**: Harvest Now, Decrypt Later threat assessment
- **CBOM Generation**: CycloneDX 1.6 with CERT-In QBOM extension
- **PQC Certification**: ML-DSA signed quantum-safety certificates

### Authentication
All endpoints except `/api/v1/auth/login` and `/api/v1/auth/register` require JWT authentication.
Include the token in the Authorization header: `Bearer <token>`
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "redoc": "/redoc",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
