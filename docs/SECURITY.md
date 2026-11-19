
# SecurePay Sentinel – Security Documentation

## 1. Project Overview

SecurePay Sentinel is an educational secure payment API and security assessment platform built using Python, FastAPI, SQLAlchemy, and SQLite.

The project demonstrates common application security controls through simulated payment transactions. It does not process real payments or store real card information.

## 2. Implemented Security Controls

### Authentication
- JWT-based authentication.
- OAuth2 password authentication flow.
- Argon2 password hashing.

### Authorization
- Role-Based Access Control (RBAC).
- Separate customer and administrator permissions.
- User-specific transaction and encrypted-data access.

### Data Protection
- Fernet encryption for sensitive application data.
- Encrypted data is stored in SQLite.
- Data is decrypted when retrieved by its authorized owner.
- Encryption keys are stored in environment variables.

### API Security
- Login brute-force protection.
- Transaction API rate limiting.
- Input validation using Pydantic.
- Protection against SQL injection through SQLAlchemy parameterized queries.
- HTTP security headers.

### Audit Logging
- User registration events.
- Successful login events.
- Transaction creation events.
- Administrator-only audit log access.

## 3. Security Testing

Automated tests are implemented using Pytest and FastAPI TestClient.

The test suite covers:

- Unauthenticated transaction access.
- Invalid transaction amounts.
- SQL injection login attempts.
- Unauthorized administrator access.
- Security response headers.
- Transaction rate limiting.
- Encryption and decryption.
- Encrypted data storage and retrieval.
- User data isolation.

Latest recorded test result: 11 tests passed.

## 4. Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite
- JWT
- Argon2
- Fernet Cryptography
- Pytest

## 5. Security Limitations

This is an educational demonstration, not a production payment platform.

- Rate limiting currently uses in-memory storage.
- Encryption key management requires additional production safeguards.
- Production deployment would require stronger monitoring, centralized rate limiting, secure secret management, and additional security testing.
- This project does not claim PCI DSS compliance.

## 6. Disclaimer

All transactions and test data are simulated. Never use real payment card information or real customer confidential data in this project.
