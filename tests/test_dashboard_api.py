
import uuid

from datetime import datetime, timedelta, timezone

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Alert, Asset
from basesentinel.models.base import utcnow_naive
from basesentinel.services import EventIngestionService, UserService


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
def users(app):
    with app.app_context():
        result = {}

        for role in ("admin", "analyst", "viewer"):
            user = UserService.create_user(
                username=f"dashboard_{role}",
                password="test-password-123",
                role=role,
            )
            result[role] = user.id

        return result


def login(client, role):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": f"dashboard_{role}",
            "password": "test-password-123",
        },
    )

    assert response.status_code == 200
    return response.get_json()["token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def timestamp_at(base, minutes):
    value = base + timedelta(minutes=minutes)
    return value.isoformat().replace("+00:00", "Z")


def create_agent(name, platform="windows"):
    asset = Asset(
        display_name=name,
        hostname=name.lower().replace(" ", "-"),
        asset_type="workstation",
    )

    agent = Agent(
        asset=asset,
        platform=platform,
        agent_version="0.1.0",
        status="active",
    )

    db.session.add_all([asset, agent])
    db.session.commit()

    return agent.id


def ingest(agent_id, occurred_at, category, event_type, severity):
    return EventIngestionService.ingest(
        agent_id,
        {
            "event_uid": str(uuid.uuid4()),
            "schema_version": 1,
            "category": category,
            "event_type": event_type,
            "severity": severity,
            "source": "Dashboard Test",
            "message": f"Test event: {event_type}",
            "event_data": {"dashboard_test": True},
            "occurred_at": occurred_at,
        },
    ).event


@pytest.fixture
def seeded_dashboard(app, users):
    with app.app_context():
        base = datetime.now(timezone.utc).replace(microsecond=0)

        agent_one = create_agent("Dashboard Workstation One")
        agent_two = create_agent("Dashboard Workstation Two")

        events = []

        # Three recent events from the first agent.
        events.append(ingest(
            agent_one,
            timestamp_at(base, -10),
            "authentication",
            "login.failed",
            7,
        ))

        events.append(ingest(
            agent_one,
            timestamp_at(base, -9),
            "network",
            "connection.opened",
            3,
        ))

        acknowledged_event = ingest(
            agent_one,
            timestamp_at(base, -8),
            "system",
            "security.critical",
            9,
        )
        events.append(acknowledged_event)

        # One recent event from the second agent.
        events.append(ingest(
            agent_two,
            timestamp_at(base, -7),
            "system",
            "security.critical",
            10,
        ))

        # One event outside the one-hour period.
        events.append(ingest(
            agent_two,
            timestamp_at(base, -120),
            "system",
            "security.critical",
            10,
        ))

        # One future event. It must not be included in analytics.
        events.append(ingest(
            agent_two,
            timestamp_at(base, 120),
            "system",
            "security.critical",
            10,
        ))

        acknowledged_alert = Alert.query.filter_by(
            source_event_id=acknowledged_event.id
        ).one()

        acknowledged_alert.status = "acknowledged"
        acknowledged_alert.acknowledged_by_user_id = users["analyst"]
        acknowledged_alert.acknowledged_at = utcnow_naive()

        db.session.commit()

        return {
            "agent_one": agent_one,
            "agent_two": agent_two,
            "event_ids": [event.id for event in events],
        }


def test_dashboard_requires_authentication(client):
    response = client.get("/api/v1/dashboard/overview")

    assert response.status_code == 401


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_all_roles_can_access_dashboard(client, users, role):
    token = login(client, role)

    response = client.get(
        "/api/v1/dashboard/overview",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_dashboard_returns_correct_aggregations(
    client,
    users,
    seeded_dashboard,
):
    token = login(client, "admin")

    response = client.get(
        "/api/v1/dashboard/overview?period_hours=1",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["period"]["hours"] == 1

    # Four events fall inside the selected period.
    assert data["events"]["total"] == 4

    categories = {
        item["category"]: item["count"]
        for item in data["events"]["by_category"]
    }

    assert categories == {
        "authentication": 1,
        "network": 1,
        "system": 2,
    }

    severities = {
        item["severity"]: item["count"]
        for item in data["events"]["by_severity"]
    }

    assert severities == {
        3: 1,
        7: 1,
        9: 1,
        10: 1,
    }

    # Only two recent events created alerts.
    assert data["alerts"]["total"] == 2

    statuses = {
        item["status"]: item["count"]
        for item in data["alerts"]["by_status"]
    }

    assert statuses == {
        "acknowledged": 1,
        "open": 1,
    }

    alert_severities = {
        item["severity"]: item["count"]
        for item in data["alerts"]["by_severity"]
    }

    assert alert_severities == {
        9: 1,
        10: 1,
    }

    assert data["agents"]["total"] == 2
    assert data["agents"]["active"] == 2

    top_agents = data["agents"]["top_by_event_count"]

    assert len(top_agents) == 2
    assert top_agents[0]["agent_id"] == str(
        seeded_dashboard["agent_one"]
    )
    assert top_agents[0]["event_count"] == 3
    assert top_agents[1]["agent_id"] == str(
        seeded_dashboard["agent_two"]
    )
    assert top_agents[1]["event_count"] == 1


def test_dashboard_respects_top_agents_limit(
    client,
    users,
    seeded_dashboard,
):
    token = login(client, "analyst")

    response = client.get(
        "/api/v1/dashboard/overview?period_hours=1&top_agents_limit=1",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    top_agents = response.get_json()["agents"]["top_by_event_count"]

    assert len(top_agents) == 1
    assert top_agents[0]["agent_id"] == str(
        seeded_dashboard["agent_one"]
    )


def test_dashboard_returns_empty_metrics_for_empty_database(
    client,
    users,
):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/dashboard/overview",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["events"]["total"] == 0
    assert data["events"]["by_category"] == []
    assert data["events"]["by_severity"] == []

    assert data["alerts"]["total"] == 0
    assert data["alerts"]["by_status"] == []
    assert data["alerts"]["by_severity"] == []

    assert data["agents"]["total"] == 0
    assert data["agents"]["active"] == 0
    assert data["agents"]["top_by_event_count"] == []


@pytest.mark.parametrize(
    "query",
    [
        "?period_hours=0",
        "?period_hours=721",
        "?period_hours=abc",
        "?period_hours=1.5",
        "?top_agents_limit=0",
        "?top_agents_limit=21",
        "?top_agents_limit=abc",
        "?top_agents_limit=1.5",
    ],
)
def test_dashboard_rejects_invalid_parameters(
    client,
    users,
    query,
):
    token = login(client, "admin")

    response = client.get(
        f"/api/v1/dashboard/overview{query}",
        headers=auth_headers(token),
    )

    assert response.status_code == 400
