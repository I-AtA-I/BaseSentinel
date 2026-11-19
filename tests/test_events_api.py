
import uuid
from datetime import timedelta

import pytest

from basesentinel import create_app, db
from basesentinel.core.security import generate_agent_token, hash_agent_token
from basesentinel.models import Agent, AgentCredential, Asset, SecurityEvent
from basesentinel.models.base import utcnow_naive
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
def agent(app):
    now = utcnow_naive()

    asset = Asset(
        display_name="Event API Test",
        hostname="event-api-test",
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


def make_event(**overrides):
    payload = {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": "authentication",
        "event_type": "login.failed",
        "severity": 7,
        "source": "Windows Security",
        "event_code": "4625",
        "message": "Failed authentication attempt",
        "event_data": {"username": "example"},
        "occurred_at": "2026-11-17T15:30:00Z",
    }

    payload.update(overrides)
    return payload


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_events_endpoint_requires_authentication(client):
    response = client.post(
        "/api/v1/events",
        json=make_event(),
    )

    assert response.status_code == 401


def test_authenticated_agent_can_ingest_event(client, agent):
    response = client.post(
        "/api/v1/events",
        json=make_event(),
        headers=auth_headers(agent["token"]),
    )

    assert response.status_code == 201

    data = response.get_json()

    assert data["event_id"]
    assert data["event_uid"]
    assert data["duplicate"] is False
    assert data["received_at"]

    assert response.headers["Cache-Control"] == "no-store"
    assert SecurityEvent.query.count() == 1


def test_duplicate_event_returns_existing_event(client, agent):
    payload = make_event()
    headers = auth_headers(agent["token"])

    first = client.post(
        "/api/v1/events",
        json=payload,
        headers=headers,
    )

    second = client.post(
        "/api/v1/events",
        json=payload,
        headers=headers,
    )

    assert first.status_code == 201
    assert second.status_code == 200

    assert first.get_json()["event_id"] == second.get_json()["event_id"]
    assert second.get_json()["duplicate"] is True

    assert SecurityEvent.query.count() == 1


def test_invalid_event_returns_400(client, agent):
    payload = make_event(severity=15)

    response = client.post(
        "/api/v1/events",
        json=payload,
        headers=auth_headers(agent["token"]),
    )

    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "invalid_event"

    assert SecurityEvent.query.count() == 0


def test_agent_cannot_supply_its_own_identity(client, agent):
    payload = make_event(agent_id=str(agent["id"]))

    response = client.post(
        "/api/v1/events",
        json=payload,
        headers=auth_headers(agent["token"]),
    )

    assert response.status_code == 400
    assert SecurityEvent.query.count() == 0


def test_invalid_json_returns_400(client, agent):
    response = client.post(
        "/api/v1/events",
        data="{invalid json",
        content_type="application/json",
        headers=auth_headers(agent["token"]),
    )

    assert response.status_code == 400


def test_oversized_request_returns_413(client, agent):
    payload = make_event(
        event_data={
            "large": "x" * (33 * 1024),
        }
    )

    response = client.post(
        "/api/v1/events",
        json=payload,
        headers=auth_headers(agent["token"]),
    )

    assert response.status_code == 413
    assert SecurityEvent.query.count() == 0


def test_revoked_agent_cannot_ingest_event(client, app, agent):
    stored_agent = db.session.get(Agent, agent["id"])
    stored_agent.status = "revoked"
    stored_agent.revoked_at = utcnow_naive()
    db.session.commit()

    response = client.post(
        "/api/v1/events",
        json=make_event(),
        headers=auth_headers(agent["token"]),
    )

    assert response.status_code == 401
    assert SecurityEvent.query.count() == 0


def test_unknown_agent_token_cannot_ingest_event(client):
    response = client.post(
        "/api/v1/events",
        json=make_event(),
        headers=auth_headers(generate_agent_token()),
    )

    assert response.status_code == 401
    assert SecurityEvent.query.count() == 0


def test_ingested_event_is_visible_in_user_event_registry(client, agent):
    payload = make_event()
    ingested = client.post(
        "/api/v1/events",
        json=payload,
        headers=auth_headers(agent["token"]),
    )
    assert ingested.status_code == 201

    UserService.create_user(
        username="eventviewer",
        password="test-password-123",
        role="viewer",
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "eventviewer", "password": "test-password-123"},
    )
    assert login.status_code == 200

    response = client.get(
        "/api/v1/events?limit=50&offset=0",
        headers=auth_headers(login.get_json()["token"]),
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["pagination"]["total"] == 1
    assert data["items"][0]["event_uid"] == payload["event_uid"]
    assert data["items"][0]["event_type"] == "login.failed"
