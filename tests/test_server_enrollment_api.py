import pytest

from basesentinel import create_app, db
from basesentinel.services.users import UserService


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    PAIRING_CODE_PEPPER = "test-pairing-pepper-value-at-least-32-bytes"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin(app):
    return UserService.create_user(
        username="enrollment-admin",
        password="test-password-123",
        role="admin",
    )


def _login(client):
    response = client.post("/api/v1/auth/login", json={
        "username": "enrollment-admin",
        "password": "test-password-123",
    })
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def test_server_enrollment_settings_create_secret_once(client, admin):
    headers = _login(client)
    first = client.get("/api/v1/server/enrollment", headers=headers)
    second = client.get("/api/v1/server/enrollment", headers=headers)

    assert first.status_code == 200
    assert first.get_json() == {"enrollment_mode": "automatic"}
    assert second.status_code == 200
    assert second.get_json() == {"enrollment_mode": "automatic"}
    assert first.headers["Cache-Control"] == "no-store"


def test_server_enrollment_secret_can_be_rotated(client, admin):
    headers = _login(client)
    client.get("/api/v1/server/enrollment", headers=headers)
    rotated = client.post("/api/v1/server/enrollment/rotate-secret", headers=headers)

    assert rotated.status_code == 200
    assert rotated.get_json()["server_secret"]
    assert rotated.get_json()["server_id"]


def test_server_enrollment_settings_require_admin(client):
    response = client.get("/api/v1/server/enrollment")
    assert response.status_code == 401


def test_server_enrollment_password_is_optional_and_hashed(client, admin, app):
    headers = _login(client)
    response = client.put("/api/v1/server/enrollment", headers=headers, json={
        "enrollment_mode": "automatic",
        "connection_password": "local-connection-password",
    })
    assert response.status_code == 200
    assert response.get_json() == {"enrollment_mode": "automatic"}

    from basesentinel.models import ServerSettings
    with app.app_context():
        settings = db.session.get(ServerSettings, 1)
        assert settings.connection_password_hash != "local-connection-password"


def test_agent_can_enroll_with_server_access_code(client, admin):
    headers = _login(client)
    client.get("/api/v1/server/enrollment", headers=headers)
    legacy_access = client.post("/api/v1/server/enrollment/rotate-secret", headers=headers).get_json()
    response = client.post("/api/v1/agents/enroll-server", json={
        "server_id": legacy_access["server_id"],
        "server_secret": legacy_access["server_secret"],
        "connection_password": None,
        "hostname": "server-enrollment-test",
        "platform": "windows",
        "agent_version": "0.1.0",
        "platform_version": "Windows 11",
        "architecture": "AMD64",
    })
    assert response.status_code == 201
    assert response.get_json()["agent_id"]
    assert response.get_json()["token"]


def test_agent_enrollment_rejects_wrong_server_secret(client, admin):
    headers = _login(client)
    client.get("/api/v1/server/enrollment", headers=headers)
    legacy_access = client.post("/api/v1/server/enrollment/rotate-secret", headers=headers).get_json()
    response = client.post("/api/v1/agents/enroll-server", json={
        "server_id": legacy_access["server_id"],
        "server_secret": "incorrect-server-secret-value-000000",
        "hostname": "server-enrollment-test",
        "platform": "windows",
        "agent_version": "0.1.0",
        "platform_version": "Windows 11",
        "architecture": "AMD64",
    })
    assert response.status_code == 401


def test_disabled_server_rejects_new_agent_enrollment(client, admin):
    headers = _login(client)
    client.get("/api/v1/server/enrollment", headers=headers)
    legacy_access = client.post("/api/v1/server/enrollment/rotate-secret", headers=headers).get_json()
    updated = client.put("/api/v1/server/enrollment", headers=headers, json={
        "enrollment_mode": "disabled",
        "connection_password": "",
    })
    assert updated.status_code == 200
    response = client.post("/api/v1/agents/enroll-server", json={
        "server_id": legacy_access["server_id"],
        "server_secret": legacy_access["server_secret"],
        "hostname": "server-enrollment-test",
        "platform": "windows",
        "agent_version": "0.1.0",
        "platform_version": "Windows 11",
        "architecture": "AMD64",
    })
    assert response.status_code == 401
