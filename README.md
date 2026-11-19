
# SecurePay Sentinel

### Secure Payment API and Security Assessment Platform

SecurePay Sentinel is a Python-based secure payment API project built with FastAPI. It demonstrates application security concepts through simulated payment transactions, authentication, authorization, data encryption, and automated security testing.

## Features

- JWT-based user authentication
- Argon2 password hashing
- Role-Based Access Control (RBAC)
- Secure simulated transaction APIs
- SQL injection protection using SQLAlchemy
- Login brute-force protection
- API rate limiting
- Fernet encryption for sensitive application data
- User-specific data access
- Audit logging
- HTTP security headers
- Automated security tests using Pytest

## Technology Stack

| Category | Technologies |
|---|---|
| Language | Python |
| Backend | FastAPI |
| Database | SQLite, SQLAlchemy |
| Authentication | JWT, OAuth2 |
| Password Security | Argon2 |
| Encryption | Fernet, Cryptography |
| Testing | Pytest, HTTPX |
| API Documentation | Swagger UI |

## Project Structure

```text
SecurePay-Sentinel/
├── app/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   └── schemas.py
├── security/
│   ├── password.py
│   ├── jwt.py
│   ├── permissions.py
│   ├── audit.py
│   ├── rate_limit.py
│   ├── security_headers.py
│   └── encryption.py
├── tests/
│   ├── conftest.py
│   └── test_security.py
├── docs/
│   ├── SECURITY.md
│   ├── ARCHITECTURE.md
│   └── THREAT_MODEL.md
├── .gitignore
├── requirements.txt
└── create_admin.py
```

## Running Locally

### 1. Clone the repository

```bash
git clone https://github.com/nikitam2612/SecurePay-Sentinel.git
cd SecurePay-Sentinel
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate it on Windows

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Create a `.env` file containing:

```env
JWT_SECRET_KEY=your_generated_secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
ENCRYPTION_KEY=your_generated_fernet_key
```

Generate your own secrets. Never commit your actual `.env` file.

### 6. Start the application

```bash
python -m uvicorn app.main:app --reload --reload-dir app
```

### 7. Open API documentation

Visit:

http://127.0.0.1:8000/docs

## Running Tests

```bash
python -m pytest -v
```

Latest verified result: **11 tests passed**.

## Documentation

- [Security Documentation](docs/SECURITY.md)
- [System Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)

## Disclaimer

This is an educational security project using simulated transactions and dummy data. It is not a production payment processing system and does not claim PCI DSS compliance.
