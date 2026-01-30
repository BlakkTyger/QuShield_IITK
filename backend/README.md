# QuShield Backend API

FastAPI backend for the QuShield Quantum-Safe Cryptography Scanner.

## Features

- **JWT Authentication**: Secure user registration, login, and token refresh
- **Real-time Streaming**: Scan results streamed to database as collected
- **Scan Management**: Trigger scans, monitor progress, retrieve results
- **Dashboard Metrics**: Real-time counts and distributions
- **Asset Inventory**: CRUD operations for discovered assets
- **CBOM Generation**: CycloneDX 1.6 export with CERT-In QBOM extension
- **PQC Posture**: Compliance tracking and remediation recommendations
- **Cyber Rating**: Enterprise and per-asset scoring (0-1000)
- **Reporting**: On-demand and scheduled report generation

---

## Prerequisites

- **Python 3.11+**
- **pip** (Python package manager)
- Internet connection (for scanning external domains)

---

## Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/BlakkTyger/QuShield-Quantum_Safe_Crypto_Scanner.git
cd QuShield-Quantum_Safe_Crypto_Scanner
```

### Step 2: Create Virtual Environment

```bash
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
.\venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment

```bash
cd backend
cp .env.example .env
```

Edit `.env` with your settings:
```env
# REQUIRED: Change this to a random 32+ character string
SECRET_KEY=your-super-secret-key-change-in-production-minimum-32-chars

# Database (SQLite by default, PostgreSQL for production)
DATABASE_URL=sqlite:///./qushield.db

# CORS origins for frontend (add your frontend URL)
CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]

# JWT token expiry
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Step 5: Start the Server

```bash
# Development (with auto-reload)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Step 6: Verify Installation

```bash
# Health check
curl http://localhost:8000/health
# Response: {"status":"healthy"}

# API documentation
open http://localhost:8000/docs
```

---

## Quick Start (TL;DR)

```bash
cd backend
cp .env.example .env
# Edit .env and set SECRET_KEY
uvicorn app.main:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000/docs
```

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login (OAuth2 form) |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| GET | `/api/v1/auth/me` | Get current user |

### Scans
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/scans` | List user's scans |
| POST | `/api/v1/scans/trigger` | Trigger new scan |
| GET | `/api/v1/scans/{id}` | Get scan details |
| GET | `/api/v1/scans/{id}/status` | Get scan progress |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dashboard/metrics` | Get dashboard metrics |
| GET | `/api/v1/dashboard/risk-distribution` | Get risk charts data |

### Assets
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets` | List assets (paginated) |
| POST | `/api/v1/assets` | Add manual asset |
| GET | `/api/v1/assets/{id}` | Get asset details |
| GET | `/api/v1/assets/{id}/certificates` | Get asset certs |
| GET | `/api/v1/assets/{id}/crypto` | Get crypto details |

### Discovery
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/discovery/summary` | Get discovery summary |
| GET | `/api/v1/discovery/domains` | List discovered domains |
| GET | `/api/v1/discovery/graph` | Get relationship graph |

### CBOM
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/cbom/metrics` | Get CBOM aggregations |
| GET | `/api/v1/cbom/export` | Export CycloneDX JSON |

### Posture
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/posture/summary` | Get PQC posture summary |
| GET | `/api/v1/posture/recommendations` | Get remediation items |
| GET | `/api/v1/posture/certificates` | List PQC certificates |

### Rating
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/rating/enterprise` | Get enterprise score |
| GET | `/api/v1/rating/assets` | Get per-asset ratings |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reports` | List generated reports |
| POST | `/api/v1/reports/generate` | Generate new report |
| POST | `/api/v1/reports/schedule` | Schedule automated reports |

## Database Schema

SQLite by default (PostgreSQL supported for production).

**Tables:**
- `users` - User accounts with roles
- `scans` - Scan jobs and status
- `scan_summaries` - Dashboard metrics per scan
- `assets` - Discovered hosts
- `certificates` - SSL/TLS certificates
- `dns_records` - DNS records
- `crypto_security` - TLS/cipher details
- `graph_nodes` / `graph_edges` - Asset relationships
- `pqc_certifications` - Issued PQC certificates
- `whois_info` - WHOIS data
- `port_scan_results` - Port scan results
- `scheduled_reports` / `generated_reports` - Reports

## Testing

### Using Swagger UI
1. Start server: `uvicorn app.main:app --reload`
2. Open http://localhost:8000/docs
3. Click "Authorize" and login
4. Test any endpoint interactively

### Using Test Script
```bash
cd backend
python -m tests.test_api
```

### Using curl
```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"Pass123!","full_name":"Test"}'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=user@example.com&password=Pass123!"

# Use token
curl http://localhost:8000/api/v1/dashboard/metrics \
  -H "Authorization: Bearer <token>"
```

## Configuration

Copy `.env.example` to `.env` and configure:

```env
SECRET_KEY=your-secret-key-min-32-chars
DATABASE_URL=sqlite:///./qushield.db
CORS_ORIGINS=["http://localhost:3000"]
```

## Architecture

```
backend/
├── app/
│   ├── main.py          # FastAPI app entry
│   ├── config.py        # Settings
│   ├── database.py      # SQLAlchemy setup
│   ├── models/          # ORM models
│   ├── schemas/         # Pydantic schemas
│   ├── api/v1/          # Route handlers
│   ├── services/        # Business logic
│   └── core/            # Auth, security
├── tests/               # API tests
└── requirements.txt
```

## Integration with qushield

The backend integrates with the `qushield` package:

1. **Scan Trigger** → Creates scan record, starts background task
2. **Background Task** → Runs `QuShieldWorkflow.run()`
3. **Persistence** → Stores results in database tables
4. **API Access** → Serves data via REST endpoints

## License

MIT License - See LICENSE file
