
# SecurePay Sentinel – Threat Model

## 1. Objective

Identify potential security threats to the SecurePay Sentinel API and document the security controls implemented to reduce their impact.

## 2. Assets to Protect

- User account credentials.
- JWT authentication tokens.
- User transaction records.
- Sensitive application data.
- Encryption keys.
- Administrator endpoints.
- Audit logs.

## 3. Potential Threats and Mitigations

| Threat | Potential Impact | Implemented Mitigation |
|---|---|---|
| SQL Injection | Unauthorized database access | SQLAlchemy parameterized queries |
| Brute-force Login | Unauthorized account access | Login rate limiting |
| Broken Access Control | Unauthorized access to admin APIs | RBAC |
| IDOR / Data Exposure | Access to another user's records | User-specific database filtering |
| Password Exposure | Compromised user credentials | Argon2 hashing |
| Sensitive Data Exposure | Disclosure of stored application data | Fernet encryption |
| Excessive API Requests | API abuse | Transaction rate limiting |
| Invalid Input | Invalid transaction records | Pydantic validation |

## 4. Authentication and Authorization

JWT authentication verifies user identity.

Role-Based Access Control restricts administrative operations to authorized administrators.

Customer endpoints use the authenticated user's identity to retrieve their own records.

## 5. Data Protection

Passwords are hashed using Argon2.

Sensitive application data is encrypted using Fernet before storage in SQLite.

The encryption key is maintained outside the source code in an environment file.

## 6. Testing Strategy

The project uses automated Pytest tests to validate authentication, authorization, input validation, rate limiting, security headers, encryption, and user data isolation.

## 7. Remaining Risks

The current implementation is a learning project and has limitations:

- Rate limiting is in-memory and does not support multiple application instances.
- No centralized security monitoring or alerting is implemented.
- Production-grade encryption key rotation and management are not implemented.
- External penetration testing has not yet been completed.
- PCI DSS compliance has not been established.

## 8. Conclusion

SecurePay Sentinel demonstrates practical application security concepts through a simulated payment API. Its security controls are tested through automated tests, with further hardening required before any production use.
