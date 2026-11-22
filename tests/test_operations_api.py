from datetime import timedelta
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Alert, Asset, SecurityEvent
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


def login_admin(client):
    UserService.create_user(
        username="operations_admin",
        password="test-password-123",
        role="admin",
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "operations_admin", "password": "test-password-123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def add_agent(last_checkin_at=None):
    asset = Asset(
        display_name="Operations test host",
        hostname="operations-test",
        asset_type="workstation",
    )
    agent = Agent(
        asset=asset,
        platform="windows",
        platform_version="11",
        architecture="x64",
        agent_version="0.1.0",
        status="active",
        last_checkin_at=last_checkin_at or utcnow_naive(),
    )
    db.session.add(agent)
    db.session.flush()
    return agent


def test_agent_health_requires_user_authentication(client):
    response = client.get("/api/v1/operations/agents")
    assert response.status_code == 401


def test_agent_health_classifies_recent_and_disconnected_agents(client, app):
    headers = login_admin(client)
    now = utcnow_naive()
    online = add_agent(now - timedelta(seconds=30))
    disconnected = add_agent(now - timedelta(minutes=30))
    db.session.commit()

    response = client.get("/api/v1/operations/agents", headers=headers)

    assert response.status_code == 200
    agents = {item["agent_id"]: item for item in response.get_json()["agents"]}
    assert agents[str(online.id)]["health"] == "online"
    assert agents[str(disconnected.id)]["health"] == "disconnected"
    assert response.get_json()["counts"]["online"] == 1
    assert response.get_json()["counts"]["disconnected"] == 1


def test_alert_investigation_returns_events_from_same_agent(client, app):
    headers = login_admin(client)
    agent = add_agent()
    now = utcnow_naive()
    event = SecurityEvent(
        agent_id=agent.id,
        event_uid=uuid.uuid4(),
        schema_version=1,
        category="system",
        event_type="service.installed",
        severity=8,
        source="Windows Security",
        event_code="7045",
        message="A service was installed",
        event_data={"service": "Example"},
        occurred_at=now,
        received_at=now,
    )
    db.session.add(event)
    db.session.flush()
    alert = Alert(
        rule_key="important_security_event",
        title="Windows service installed",
        description="Review the service.",
        severity=8,
        status="open",
        agent_id=agent.id,
        source_event_id=event.id,
        deduplication_key="a" * 64,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.session.add(alert)
    db.session.commit()

    response = client.get(
        f"/api/v1/operations/alerts/{alert.id}/investigation",
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["alert"]["id"] == str(alert.id)
    assert payload["related_event_count"] == 1
    assert payload["related_events"][0]["id"] == str(event.id)


def test_security_csv_report_has_header_and_event_data(client, app):
    headers = login_admin(client)
    agent = add_agent()
    now = utcnow_naive()
    db.session.add(SecurityEvent(
        agent_id=agent.id,
        event_uid=uuid.uuid4(),
        schema_version=1,
        category="system",
        event_type="service.installed",
        severity=8,
        source="Windows Security",
        event_code="7045",
        message="Example service installed",
        event_data=None,
        occurred_at=now,
        received_at=now,
    ))
    db.session.commit()

    response = client.get("/api/v1/reports/security.csv?hours=24", headers=headers)

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "hostname" in response.get_data(as_text=True)
    assert "operations-test" in response.get_data(as_text=True)
    assert "Example service installed" in response.get_data(as_text=True)


def test_security_csv_rejects_out_of_range_period(client):
    headers = login_admin(client)
    response = client.get("/api/v1/reports/security.csv?hours=721", headers=headers)
    assert response.status_code == 400
