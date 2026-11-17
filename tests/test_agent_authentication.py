
from datetime import timedelta

import pytest

from basesentinel import create_app, db
from basesentinel.core.security import (
    generate_agent_token,
    hash_agent_token,
)
from basesentinel.models import (
    Agent,
    AgentCredential,
    Asset,
)
from basesentinel.models.base import utcnow_naive
from basesentinel.services import AgentAuthenticationService


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


def create_agent_with_token(
    expires_at=None,
    credential_revoked_at=None,
    agent_status="active",
    agent_revoked_at=None,
    agent_uninstalled_at=None,
):
    now = utcnow_naive()

    asset = Asset(
        display_name="Authentication Test",
        hostname="auth-test-pc",
        asset_type="workstation",
    )

    agent = Agent(
        asset=asset,
        platform="windows",
        platform_version="11",
        architecture="x64",
        agent_version="0.1.0",
        status=agent_status,
        revoked_at=agent_revoked_at,
        uninstalled_at=agent_uninstalled_at,
    )

    token = generate_agent_token()

    credential = AgentCredential(
        agent=agent,
        secret_hash=hash_agent_token(token),
        created_at=now,
        expires_at=expires_at or now + timedelta(days=90),
        revoked_at=credential_revoked_at,
    )

    db.session.add_all([asset, agent, credential])
    db.session.commit()

    return token, agent.id, credential.id


def test_valid_agent_token_is_authenticated(app):
    token, agent_id, credential_id = create_agent_with_token()

    result = AgentAuthenticationService.authenticate(token)

    assert result is not None
    assert result.agent.id == agent_id
    assert result.credential.id == credential_id
    assert result.agent.status == "active"
    assert result.credential.last_used_at is not None
    assert result.agent.last_checkin_at is not None


def test_invalid_agent_token_is_rejected(app):
    create_agent_with_token()

    result = AgentAuthenticationService.authenticate(
        generate_agent_token()
    )

    assert result is None


def test_expired_credential_is_rejected(app):
    token, _, _ = create_agent_with_token(
        expires_at=utcnow_naive() - timedelta(seconds=1)
    )

    result = AgentAuthenticationService.authenticate(token)

    assert result is None


def test_revoked_credential_is_rejected(app):
    token, _, _ = create_agent_with_token(
        credential_revoked_at=utcnow_naive()
    )

    result = AgentAuthenticationService.authenticate(token)

    assert result is None


def test_revoked_agent_is_rejected(app):
    token, _, _ = create_agent_with_token(
        agent_status="revoked",
        agent_revoked_at=utcnow_naive(),
    )

    result = AgentAuthenticationService.authenticate(token)

    assert result is None


def test_uninstalled_agent_is_rejected(app):
    token, _, _ = create_agent_with_token(
        agent_status="uninstalled",
        agent_uninstalled_at=utcnow_naive(),
    )

    result = AgentAuthenticationService.authenticate(token)

    assert result is None


def test_activity_timestamps_are_not_updated_on_every_request(app):
    token, _, credential_id = create_agent_with_token()

    AgentAuthenticationService.authenticate(token)

    credential = db.session.get(AgentCredential, credential_id)
    first_used_at = credential.last_used_at

    AgentAuthenticationService.authenticate(token)

    db.session.refresh(credential)

    assert credential.last_used_at == first_used_at


def test_agent_endpoint_requires_authentication(app):
    client = app.test_client()

    response = client.get("/api/v1/agents/me")

    assert response.status_code == 401
    assert response.json["error"]["code"] == "unauthorized"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_agent_endpoint_rejects_wrong_authentication_scheme(app):
    client = app.test_client()

    response = client.get(
        "/api/v1/agents/me",
        headers={"Authorization": "Basic invalid-token"},
    )

    assert response.status_code == 401


def test_agent_endpoint_rejects_invalid_token(app):
    client = app.test_client()

    response = client.get(
        "/api/v1/agents/me",
        headers={"Authorization": "Bearer " + generate_agent_token()},
    )

    assert response.status_code == 401


def test_agent_endpoint_accepts_valid_token(app):
    token, agent_id, _ = create_agent_with_token()

    client = app.test_client()

    response = client.get(
        "/api/v1/agents/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json["agent_id"] == str(agent_id)
    assert response.json["platform"] == "windows"
    assert response.json["status"] == "active"


def test_health_endpoint_remains_public(app):
    client = app.test_client()

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json["status"] == "ok"
