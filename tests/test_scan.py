"""Tests for the URL, message, and image scanners."""
import io
from PIL import Image


def _login(client):
    client.post("/api/auth/login", json={
        "email": "fixture_user@example.com",
        "password": "Passw0rd123",
    })


def test_scan_suspicious_url(registered_client):
    _login(registered_client)
    resp = registered_client.post("/api/scan/url", json={
        "url": "http://secure-login-verify.tk/account/reward-claim"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 0
    assert data["risk_level"] in ("Low Risk", "Moderate Risk", "High Risk", "Critical Risk")
    assert len(data["findings"]) > 0


def test_scan_safe_url(registered_client):
    _login(registered_client)
    resp = registered_client.post("/api/scan/url", json={"url": "https://www.wikipedia.org"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "Low Risk"


def test_scan_empty_url_rejected(registered_client):
    _login(registered_client)
    resp = registered_client.post("/api/scan/url", json={"url": ""})
    assert resp.status_code == 422


def test_scan_suspicious_message(registered_client):
    _login(registered_client)
    resp = registered_client.post("/api/scan/message", json={
        "message": "Congratulations! You have won an iPhone. Click this link immediately to claim your prize: https://bit.ly/xyz"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 30
    assert any("urgency" in f.lower() or "prize" in f.lower() or "click" in f.lower() for f in data["findings"])


def test_scan_empty_message_rejected(registered_client):
    _login(registered_client)
    resp = registered_client.post("/api/scan/message", json={"message": "   "})
    assert resp.status_code == 422


def test_scan_otp_message_flags_credential_request(registered_client):
    _login(registered_client)
    resp = registered_client.post("/api/scan/message", json={
        "message": "Please share your OTP code immediately to verify your account."
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] > 0


def _make_test_image_bytes() -> bytes:
    img = Image.new("RGB", (400, 100), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_scan_image_invalid_type_rejected(registered_client):
    _login(registered_client)
    resp = registered_client.post(
        "/api/scan/image",
        files={"file": ("test.txt", b"not an image", "text/plain")},
    )
    assert resp.status_code == 415


def test_scan_image_empty_file_rejected(registered_client):
    _login(registered_client)
    resp = registered_client.post(
        "/api/scan/image",
        files={"file": ("test.png", b"", "image/png")},
    )
    assert resp.status_code == 400


def test_scan_image_oversized_rejected(registered_client):
    _login(registered_client)
    big_bytes = b"0" * (6 * 1024 * 1024)
    resp = registered_client.post(
        "/api/scan/image",
        files={"file": ("big.png", big_bytes, "image/png")},
    )
    assert resp.status_code == 413


def test_scan_image_valid_blank_image(registered_client):
    _login(registered_client)
    img_bytes = _make_test_image_bytes()
    resp = registered_client.post(
        "/api/scan/image",
        files={"file": ("blank.png", img_bytes, "image/png")},
    )
    # A blank image has no extractable text -> 422, OR OCR unavailable -> 503.
    # Both are acceptable graceful outcomes; a hard crash (500) is not.
    assert resp.status_code in (422, 503)


def test_scan_history_after_scans(registered_client):
    _login(registered_client)
    registered_client.post("/api/scan/url", json={"url": "https://example.com/verify-login"})
    resp = registered_client.get("/api/scans")
    assert resp.status_code == 200
    scans = resp.json()
    assert len(scans) >= 1
    assert "risk_score" in scans[0]


def test_security_tips_endpoint(client):
    resp = client.get("/api/security-tips")
    assert resp.status_code == 200
    assert len(resp.json()["tips"]) > 0
