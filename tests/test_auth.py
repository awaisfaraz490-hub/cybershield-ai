"""Tests for registration/login/logout and access control."""


def test_register_success(client):
    resp = client.post("/api/auth/register", json={
        "full_name": "Alice Example",
        "email": "alice@example.com",
        "password": "Passw0rd123",
        "confirm_password": "Passw0rd123",
    })
    assert resp.status_code == 201
    assert resp.json()["email"] == "alice@example.com"


def test_register_duplicate_email(client):
    payload = {
        "full_name": "Bob Example",
        "email": "bob@example.com",
        "password": "Passw0rd123",
        "confirm_password": "Passw0rd123",
    }
    first = client.post("/api/auth/register", json=payload)
    assert first.status_code == 201
    second = client.post("/api/auth/register", json=payload)
    assert second.status_code == 409


def test_register_weak_password(client):
    resp = client.post("/api/auth/register", json={
        "full_name": "Weak Pw",
        "email": "weak@example.com",
        "password": "weak",
        "confirm_password": "weak",
    })
    assert resp.status_code == 422


def test_register_password_mismatch(client):
    resp = client.post("/api/auth/register", json={
        "full_name": "Mismatch",
        "email": "mismatch@example.com",
        "password": "Passw0rd123",
        "confirm_password": "Different123",
    })
    assert resp.status_code == 422


def test_register_empty_fields(client):
    resp = client.post("/api/auth/register", json={
        "full_name": "",
        "email": "",
        "password": "",
        "confirm_password": "",
    })
    assert resp.status_code == 422


def test_login_success(registered_client):
    resp = registered_client.post("/api/auth/login", json={
        "email": "fixture_user@example.com",
        "password": "Passw0rd123",
    })
    assert resp.status_code == 200


def test_login_wrong_password(registered_client):
    resp = registered_client.post("/api/auth/login", json={
        "email": "fixture_user@example.com",
        "password": "WrongPassword1",
    })
    assert resp.status_code == 401


def test_login_nonexistent_user(client):
    resp = client.post("/api/auth/login", json={
        "email": "doesnotexist@example.com",
        "password": "Whatever123",
    })
    assert resp.status_code == 401


def test_logout(registered_client):
    registered_client.post("/api/auth/login", json={
        "email": "fixture_user@example.com",
        "password": "Passw0rd123",
    })
    resp = registered_client.post("/api/auth/logout")
    assert resp.status_code == 200


def test_dashboard_requires_auth(client):
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/login"


def test_dashboard_accessible_when_authenticated(registered_client):
    registered_client.post("/api/auth/login", json={
        "email": "fixture_user@example.com",
        "password": "Passw0rd123",
    })
    resp = registered_client.get("/dashboard")
    assert resp.status_code == 200


def test_scan_endpoints_require_auth(client):
    resp = client.post("/api/scan/url", json={"url": "https://example.com"})
    assert resp.status_code == 401
