import pytest
from uuid import UUID

from basesentinel import create_app, db
from basesentinel.models import AgentInvitation
from basesentinel.services.users import UserService
from basesentinel_agent.client import BaseSentinelClient


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
def admin(client):
    UserService.create_user(
        username="invitation-admin",
        password="test-password-123",
        role="admin",
    )
    response = client.post("/api/v1/auth/login", json={
        "username": "invitation-admin",
        "password": "test-password-123",
    })
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def _initialize_server(client, headers):
    response = client.get("/api/v1/server/enrollment", headers=headers)
    assert response.status_code == 200


def _create_invitation(client, headers, ttl=60):
    response = client.post(
        "/api/v1/server/enrollment/invitations",
        headers=headers,
        json={"ttl_minutes": ttl},
    )
    assert response.status_code == 201
    return response.get_json()


def _enroll(client, token, hostname="invited-workstation"):
    return client.post("/api/v1/agents/enroll-invitation", json={
        "invitation_token": token,
        "hostname": hostname,
        "platform": "windows",
        "agent_version": "0.1.0",
        "platform_version": "Windows 11",
        "architecture": "AMD64",
    })


def test_invitation_token_is_only_returned_once_and_only_hash_is_stored(client, admin, app):
    _initialize_server(client, admin)
    created = _create_invitation(client, admin)

    assert created["invitation_token"]
    assert created["expires_at"]
    with app.app_context():
        record = db.session.get(AgentInvitation, UUID(created["id"]))
        assert record.token_hash != created["invitation_token"]
        assert len(record.token_hash) == 64

    listed = client.get("/api/v1/server/enrollment/invitations", headers=admin)
    assert listed.status_code == 200
    assert listed.get_json()["items"][0]["status"] == "active"
    assert "invitation_token" not in listed.get_json()["items"][0]


def test_invitation_enrolls_once_and_issues_individual_agent_token(client, admin):
    _initialize_server(client, admin)
    invitation = _create_invitation(client, admin)

    first = _enroll(client, invitation["invitation_token"])
    second = _enroll(client, invitation["invitation_token"], "second-workstation")

    assert first.status_code == 201
    assert first.get_json()["agent_id"]
    assert first.get_json()["token"]
    assert first.headers["Cache-Control"] == "no-store"
    assert second.status_code == 401


def test_revoked_invitation_cannot_be_used(client, admin):
    _initialize_server(client, admin)
    invitation = _create_invitation(client, admin)
    revoked = client.post(
        f"/api/v1/server/enrollment/invitations/{invitation['id']}/revoke",
        headers=admin,
    )
    assert revoked.status_code == 200
    assert revoked.get_json()["revoked"] is True
    assert _enroll(client, invitation["invitation_token"]).status_code == 401


def test_disabled_enrollment_rejects_existing_invitation(client, admin):
    _initialize_server(client, admin)
    invitation = _create_invitation(client, admin)
    updated = client.put("/api/v1/server/enrollment", headers=admin, json={
        "enrollment_mode": "disabled",
        "connection_password": "",
    })
    assert updated.status_code == 200
    assert _enroll(client, invitation["invitation_token"]).status_code == 401


def test_invitation_lifetime_is_bounded(client, admin):
    _initialize_server(client, admin)
    response = client.post(
        "/api/v1/server/enrollment/invitations",
        headers=admin,
        json={"ttl_minutes": 4},
    )
    assert response.status_code == 400


def test_invitation_creation_requires_admin(client):
    response = client.post("/api/v1/server/enrollment/invitations", json={})
    assert response.status_code == 401


def test_invitation_link_parser_extracts_server_and_token():
    server, token = BaseSentinelClient.parse_invitation_link(
        "https://sentinel.example/agent-invite#invite=temporary-token-value-1234567890"
    )
    assert server == "https://sentinel.example"
    assert token == "temporary-token-value-1234567890"


@pytest.mark.parametrize("link", [
    "http://sentinel.example/agent-invite#invite=temporary-token-value-1234567890",
    "https://sentinel.example/agent-invite?invite=temporary-token-value-1234567890",
    "https://sentinel.example/other#invite=temporary-token-value-1234567890",
    "https://user:pass@sentinel.example/agent-invite#invite=temporary-token-value-1234567890",
])
def test_invitation_link_parser_rejects_unsafe_or_invalid_links(link):
    with pytest.raises(ValueError):
        BaseSentinelClient.parse_invitation_link(link)
