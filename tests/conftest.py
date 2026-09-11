"""Pytest fixtures — uses an isolated temporary SQLite database for tests."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Point the app at a throwaway database BEFORE importing it, so tests never
# touch the developer's real cybershield.db.
_tmp_dir = tempfile.mkdtemp()
_test_db_path = Path(_tmp_dir) / "test_cybershield.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["DEBUG"] = "true"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402
from app.database import init_db  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    init_db()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def registered_client(client):
    client.post("/api/auth/register", json={
        "full_name": "Test User",
        "email": "fixture_user@example.com",
        "password": "Passw0rd123",
        "confirm_password": "Passw0rd123",
    })
    return client
