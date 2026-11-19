
# SecurePay Sentinel – System Architecture

## 1. Architecture Overview

SecurePay Sentinel follows a layered architecture.

## 2. Application Flow

```text
             Client / Swagger UI
                     |
                     v
              FastAPI Application
                     |
                     v
             Security Middleware
                     |
          +----------+----------+
          |                     |
          v                     v
   Authentication          API Endpoints
     (JWT/OAuth2)                |
          |              +------+------+
          v              |             |
   Authorization         v             v
      (RBAC)         Transactions   Encrypted Data
                         |             |
                         v             v
                    Audit Logging   Fernet
                         |          Encryption
                         +------+------+
                                |
                                v
                         SQLAlchemy ORM
                                |
                                v
                           SQLite DB
```

## 3. Main Components

### Application Layer
- FastAPI handles HTTP requests.
- Pydantic validates incoming request data.
- Swagger UI provides API documentation and testing.

### Security Layer
- JWT verifies authenticated users.
- Argon2 protects stored passwords.
- RBAC restricts administrator endpoints.
- Fernet encrypts sensitive application data.
- Rate limiting restricts excessive requests.
- Security middleware adds HTTP response headers.

### Database Layer
- SQLAlchemy manages database operations.
- SQLite stores users, transactions, audit logs, and encrypted data.

### Testing Layer
- Pytest runs automated security tests.
- FastAPI TestClient tests API endpoints.

## 4. Request Lifecycle

1. Client sends an HTTP request.
2. Security middleware processes the request.
3. Authentication verifies the user's JWT when required.
4. Authorization checks the user's permissions.
5. FastAPI validates request data.
6. SQLAlchemy performs the database operation.
7. Audit events are recorded where implemented.
8. API returns the response.

## 5. Deployment Considerations

For a production deployment, additional controls would be required, including centralized rate limiting, managed secrets, database hardening, monitoring, and security assessments.
