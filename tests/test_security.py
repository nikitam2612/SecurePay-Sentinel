
def create_customer_and_login(client):
    # Register a test customer
    client.post(
        "/auth/register",
        json={
            "name": "Security Test User",
            "email": "securitytest@example.com",
            "password": "TestPassword@123"
        }
    )

    # Login and get JWT token
    response = client.post(
        "/auth/login",
        data={
            "username": "securitytest@example.com",
            "password": "TestPassword@123"
        }
    )

    assert response.status_code == 200

    return response.json()["access_token"]


def test_transaction_requires_authentication(client):
    response = client.post(
        "/transactions",
        json={
            "amount": 500,
            "currency": "INR",
            "description": "Security test"
        }
    )

    assert response.status_code == 401


def test_negative_transaction_amount_rejected(client):
    token = create_customer_and_login(client)

    response = client.post(
        "/transactions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "amount": -500,
            "currency": "INR",
            "description": "Negative amount test"
        }
    )

    assert response.status_code == 422


def test_customer_cannot_access_admin_audit_logs(client):
    token = create_customer_and_login(client)

    response = client.get(
        "/admin/audit-logs",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403


def test_sql_injection_login_rejected(client):
    response = client.post(
        "/auth/login",
        data={
            "username": "' OR '1'='1",
            "password": "anything123"
        }
    )

    assert response.status_code == 401


def test_zero_transaction_amount_rejected(client):
    token = create_customer_and_login(client)

    response = client.post(
        "/transactions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "amount": 0,
            "currency": "INR",
            "description": "Zero amount test"
        }
    )

    assert response.status_code == 422


def test_customer_cannot_access_admin_dashboard(client):
    token = create_customer_and_login(client)

    response = client.get(
        "/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403

def test_security_headers_present(client):
    response = client.get("/")

    assert response.status_code == 200

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"

    assert response.headers["referrer-policy"] == (
        "strict-origin-when-cross-origin"
    )

    assert response.headers["content-security-policy"] == (
        "default-src 'self'"
    )

def test_transaction_rate_limit(client):
    token = create_customer_and_login(client)

    headers = {
        "Authorization": f"Bearer {token}"
    }

    transaction_data = {
        "amount": 100,
        "currency": "INR",
        "description": "Rate limit automated test"
    }

    # First 10 requests should succeed
    for _ in range(10):
        response = client.post(
            "/transactions",
            headers=headers,
            json=transaction_data
        )

        assert response.status_code == 201

    # 11th request should be blocked
    response = client.post(
        "/transactions",
        headers=headers,
        json=transaction_data
    )

    assert response.status_code == 429


def test_data_encryption_and_decryption():
    from security.encryption import encrypt_data, decrypt_data

    original_data = "Sensitive demo data"

    encrypted_data = encrypt_data(original_data)

    assert encrypted_data != original_data
    assert decrypt_data(encrypted_data) == original_data

def test_encrypted_data_storage_and_retrieval(client):
    token = create_customer_and_login(client)

    headers = {
        "Authorization": f"Bearer {token}"
    }

    content = "Encrypted storage test note"

    create_response = client.post(
        "/encrypted-data",
        headers=headers,
        json={"content": content}
    )

    assert create_response.status_code == 201
    assert create_response.json()["content"] == content

    get_response = client.get(
        "/encrypted-data/my",
        headers=headers
    )

    assert get_response.status_code == 200

    assert any(
        item["content"] == content
        for item in get_response.json()
    )

def test_users_can_only_access_their_own_encrypted_data(client):
    # Create and log in Customer 1
    token1 = create_customer_and_login(client)

    headers1 = {
        "Authorization": f"Bearer {token1}"
    }

    # Store Customer 1's data
    client.post(
        "/encrypted-data",
        headers=headers1,
        json={"content": "Customer One Secret"}
    )

    # Register Customer 2
    client.post(
        "/auth/register",
        json={
            "name": "Second Customer",
            "email": "customer2@example.com",
            "password": "CustomerTwo@123"
        }
    )

    # Log in Customer 2
    login_response = client.post(
        "/auth/login",
        data={
            "username": "customer2@example.com",
            "password": "CustomerTwo@123"
        }
    )

    assert login_response.status_code == 200

    token2 = login_response.json()["access_token"]

    headers2 = {
        "Authorization": f"Bearer {token2}"
    }

    # Customer 2 retrieves their own data
    response = client.get(
        "/encrypted-data/my",
        headers=headers2
    )

    assert response.status_code == 200

    # Customer 2 must not see Customer 1's data
    assert all(
        item["content"] != "Customer One Secret"
        for item in response.json()
    )