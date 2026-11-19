
import uuid
from datetime import timedelta

import pytest

from basesentinel import create_app, db
from basesentinel.core.security import generate_agent_token, hash_agent_token
from basesentinel.models import Agent, AgentCredential, Asset, Alert, SecurityEvent
from basesentinel.models.base import utcnow_naive
from basesentinel.services.authentication import AgentAuthenticationService
from basesentinel.services.users import UserService


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
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
    user = UserService.create_user(
        username="apiadmin",
        password="test-password-123",
        role="admin",
    )
    return user.id


@pytest.fixture
def viewer(app):
    user = UserService.create_user(
        username="apiviewer",
        password="test-password-123",
        role="viewer",
    )
    return user.id


@pytest.fixture
def agent(app):
    now = utcnow_naive()

    asset = Asset(
        display_name="API Test Workstation",
        hostname="api-test-workstation",
        asset_type="workstation",
    )

    agent = Agent(
        asset=asset,
        platform="windows",
        platform_version="11",
        architecture="x64",
        agent_version="0.1.0",
        status="active",
    )

    token = generate_agent_token()

    credential = AgentCredential(
        agent=agent,
        secret_hash=hash_agent_token(token),
        created_at=now,
        expires_at=now + timedelta(days=90),
    )

    db.session.add_all([asset, agent, credential])
    db.session.commit()

    return {
        "id": agent.id,
        "token": token,
        "credential_id": credential.id,
    }


def login(client, username, password="test-password-123"):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert response.status_code == 200

    return response.get_json()["token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_list_agents_requires_authentication(client, agent):
    response = client.get("/api/v1/agents")

    assert response.status_code == 401


def test_viewer_can_list_agents(client, viewer, agent):
    token = login(client, "apiviewer")

    response = client.get(
        "/api/v1/agents",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1
    assert data["items"][0]["id"] == str(agent["id"])


def test_agent_detail_includes_asset_information(client, viewer, agent):
    token = login(client, "apiviewer")

    response = client.get(
        f"/api/v1/agents/{agent['id']}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["id"] == str(agent["id"])
    assert data["asset"]["hostname"] == "api-test-workstation"
    assert data["platform"] == "windows"
    assert data["status"] == "active"


def test_agent_detail_rejects_invalid_uuid(client, viewer):
    token = login(client, "apiviewer")

    response = client.get(
        "/api/v1/agents/not-a-uuid",
        headers=auth_headers(token),
    )

    assert response.status_code == 400


def test_agent_detail_returns_404_for_unknown_agent(client, viewer):
    import uuid

    token = login(client, "apiviewer")

    response = client.get(
        f"/api/v1/agents/{uuid.uuid4()}",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


def test_agent_list_validates_pagination(client, viewer):
    token = login(client, "apiviewer")

    response = client.get(
        "/api/v1/agents?limit=500",
        headers=auth_headers(token),
    )

    assert response.status_code == 400


def test_viewer_cannot_revoke_agent(client, app, viewer, agent):
    token = login(client, "apiviewer")

    response = client.post(
        f"/api/v1/agents/{agent['id']}/revoke",
        headers=auth_headers(token),
    )

    assert response.status_code == 403

    stored_agent = db.session.get(Agent, agent["id"])
    assert stored_agent.status == "active"


def test_admin_can_revoke_agent(client, app, admin, agent):
    token = login(client, "apiadmin")

    response = client.post(
        f"/api/v1/agents/{agent['id']}/revoke",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "revoked"
    assert response.get_json()["changed"] is True

    stored_agent = db.session.get(Agent, agent["id"])
    stored_credential = db.session.get(
        AgentCredential,
        agent["credential_id"],
    )

    assert stored_agent.status == "revoked"
    assert stored_agent.revoked_at is not None
    assert stored_credential.revoked_at is not None

    assert AgentAuthenticationService.authenticate(agent["token"]) is None


def test_admin_can_list_credentials_without_secrets(
    client,
    admin,
    agent,
):
    token = login(client, "apiadmin")

    response = client.get(
        f"/api/v1/agents/{agent['id']}/credentials",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 1
    assert len(data["items"]) == 1

    credential = data["items"][0]

    assert credential["id"] == str(agent["credential_id"])
    assert "secret_hash" not in credential
    assert "token" not in credential

    response_text = response.get_data(as_text=True)

    assert agent["token"] not in response_text


def test_viewer_cannot_list_credentials(client, viewer, agent):
    token = login(client, "apiviewer")

    response = client.get(
        f"/api/v1/agents/{agent['id']}/credentials",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


def test_admin_can_rotate_agent_credentials(client, app, admin, agent):
    token = login(client, "apiadmin")

    response = client.post(
        f"/api/v1/agents/{agent['id']}/credentials/rotate",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["agent_id"] == str(agent["id"])
    assert data["token"]
    assert data["token"] != agent["token"]
    assert data["token_type"] == "Bearer"

    assert AgentAuthenticationService.authenticate(agent["token"]) is None

    authenticated = AgentAuthenticationService.authenticate(data["token"])
    assert authenticated is not None
    assert authenticated.agent.id == agent["id"]

    assert "secret_hash" not in response.get_data(as_text=True)


def test_viewer_cannot_rotate_agent_credentials(client, viewer, agent):
    token = login(client, "apiviewer")

    response = client.post(
        f"/api/v1/agents/{agent['id']}/credentials/rotate",
        headers=auth_headers(token),
    )

    assert response.status_code == 403

    assert AgentAuthenticationService.authenticate(agent["token"]) is not None


def test_rotation_rejects_invalid_lifetime(client, admin, agent):
    token = login(client, "apiadmin")

    response = client.post(
        f"/api/v1/agents/{agent['id']}/credentials/rotate",
        headers=auth_headers(token),
        json={"ttl_days": 500},
    )

    assert response.status_code == 400

    assert AgentAuthenticationService.authenticate(agent["token"]) is not None


def test_rotation_returns_409_for_revoked_agent(
    client,
    app,
    admin,
    agent,
):
    stored_agent = db.session.get(Agent, agent["id"])
    stored_agent.status = "revoked"
    stored_agent.revoked_at = utcnow_naive()
    db.session.commit()

    token = login(client, "apiadmin")

    response = client.post(
        f"/api/v1/agents/{agent['id']}/credentials/rotate",
        headers=auth_headers(token),
    )

    assert response.status_code == 409


def test_rotation_returns_404_for_unknown_agent(client, admin):
    import uuid

    token = login(client, "apiadmin")

    response = client.post(
        f"/api/v1/agents/{uuid.uuid4()}/credentials/rotate",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


def test_viewer_cannot_delete_agent(client, viewer, agent):
    token = login(client, "apiviewer")
    response = client.delete(
        f"/api/v1/agents/{agent['id']}",
        headers=auth_headers(token),
    )
    assert response.status_code == 403
    assert db.session.get(Agent, agent["id"]) is not None


def test_admin_can_permanently_delete_agent_and_telemetry(client, app, admin, agent):
    stored_agent = db.session.get(Agent, agent["id"])
    event = SecurityEvent(
        agent_id=stored_agent.id,
        event_uid=uuid.uuid4(),
        schema_version=1,
        category="authentication",
        event_type="login.failed",
        severity=7,
        source="Windows Security",
        event_code="4625",
        message="Test failed login",
        event_data={"record_id": 123},
        occurred_at=utcnow_naive(),
        received_at=utcnow_naive(),
    )
    db.session.add(event)
    db.session.flush()
    alert = Alert(
        rule_key="test_rule",
        title="Test alert",
        description="Test alert description",
        severity=7,
        status="open",
        agent_id=stored_agent.id,
        source_event_id=event.id,
        deduplication_key="a" * 64,
    )
    db.session.add(alert)
    db.session.commit()

    token = login(client, "apiadmin")
    response = client.delete(
        f"/api/v1/agents/{agent['id']}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["deleted"] is True
    assert payload["deleted_events"] == 1
    assert payload["deleted_alerts"] == 1
    assert payload["deleted_credentials"] == 1
    assert payload["asset_deleted"] is True
    assert db.session.get(Agent, agent["id"]) is None
    assert db.session.get(AgentCredential, agent["credential_id"]) is None
    assert SecurityEvent.query.count() == 0
    assert Alert.query.count() == 0
    assert client.get(
        "/api/v1/agents",
        headers=auth_headers(token),
    ).get_json()["pagination"]["total"] == 0


def test_delete_agent_returns_404_for_unknown_agent(client, admin):
    token = login(client, "apiadmin")
    response = client.delete(
        f"/api/v1/agents/{uuid.uuid4()}",
        headers=auth_headers(token),
    )
    assert response.status_code == 404
