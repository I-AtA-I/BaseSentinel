from datetime import datetime, timedelta, timezone
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Alert, Asset, DetectionRule
from basesentinel.services.events import EventIngestionService
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


def login(client, role="admin"):
    username = f"rules_{role}"
    UserService.create_user(
        username=username,
        password="test-password-123",
        role=role,
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "test-password-123"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


def add_agent():
    asset = Asset(
        display_name="Detection rule test",
        hostname="detection-rule-test",
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
    db.session.add(agent)
    db.session.commit()
    return agent


def rule_payload(**overrides):
    payload = {
        "name": "Suspicious service registration",
        "description": "Detect a named service installation.",
        "category": "system",
        "event_type": "system.custom_test",
        "source": "Windows Security",
        "event_code": "7045",
        "min_event_severity": 5,
        "conditions": {"service_name": "UnexpectedService"},
        "threshold": 2,
        "window_seconds": 300,
        "severity": 9,
        "enabled": True,
    }
    payload.update(overrides)
    return payload


def event_payload(occurred_at, service_name="UnexpectedService"):
    return {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": "system",
        "event_type": "system.custom_test",
        "severity": 6,
        "source": "Windows Security",
        "event_code": "7045",
        "message": "A service was installed.",
        "event_data": {"service_name": service_name},
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
    }


def test_detection_rules_require_authentication(client):
    response = client.get("/api/v1/detection-rules")
    assert response.status_code == 401


def test_viewer_can_list_but_cannot_create_detection_rules(client):
    headers = login(client, "viewer")
    assert client.get("/api/v1/detection-rules", headers=headers).status_code == 200
    response = client.post(
        "/api/v1/detection-rules",
        json=rule_payload(),
        headers=headers,
    )
    assert response.status_code == 403


def test_admin_can_create_update_disable_and_delete_rule(client):
    headers = login(client)
    created = client.post(
        "/api/v1/detection-rules",
        json=rule_payload(),
        headers=headers,
    )
    assert created.status_code == 201
    rule_id = created.get_json()["id"]

    updated = client.patch(
        f"/api/v1/detection-rules/{rule_id}",
        json={"enabled": False, "severity": 8},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.get_json()["enabled"] is False
    assert updated.get_json()["severity"] == 8

    deleted = client.delete(
        f"/api/v1/detection-rules/{rule_id}",
        headers=headers,
    )
    assert deleted.status_code == 200
    assert db.session.get(DetectionRule, uuid.UUID(rule_id)) is None


def test_rule_rejects_unsafe_or_invalid_configuration(client):
    headers = login(client)
    response = client.post(
        "/api/v1/detection-rules",
        json=rule_payload(threshold=101),
        headers=headers,
    )
    assert response.status_code == 400

    response = client.post(
        "/api/v1/detection-rules",
        json=rule_payload(conditions={"field": ["not", "a", "scalar"]}),
        headers=headers,
    )
    assert response.status_code == 400


def test_custom_rule_creates_correlated_alert_after_threshold_is_met(client, app):
    headers = login(client)
    created = client.post(
        "/api/v1/detection-rules",
        json=rule_payload(),
        headers=headers,
    )
    assert created.status_code == 201

    agent = add_agent()
    now = datetime.now(timezone.utc)
    bucket_start = int(now.timestamp()) // 300 * 300
    first_time = datetime.fromtimestamp(bucket_start + 60, timezone.utc)

    first = EventIngestionService.ingest(
        agent.id,
        event_payload(first_time),
    )
    assert Alert.query.count() == 0

    second = EventIngestionService.ingest(
        agent.id,
        event_payload(first_time + timedelta(seconds=20)),
    )
    alerts = Alert.query.filter(Alert.rule_key.like("custom_%")).all()
    assert len(alerts) == 1
    assert alerts[0].title == "Suspicious service registration"
    assert alerts[0].severity == 9
    assert alerts[0].occurrence_count == 2
    assert alerts[0].source_event_id == second.event.id


def test_disabled_rule_does_not_generate_alert(client, app):
    headers = login(client)
    created = client.post(
        "/api/v1/detection-rules",
        json=rule_payload(threshold=1, enabled=False),
        headers=headers,
    )
    assert created.status_code == 201

    agent = add_agent()
    now = datetime.now(timezone.utc)
    EventIngestionService.ingest(agent.id, event_payload(now))

    assert Alert.query.filter(Alert.rule_key.like("custom_%")).count() == 0
