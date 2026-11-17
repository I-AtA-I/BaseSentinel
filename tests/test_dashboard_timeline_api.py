
import uuid

import pytest

from datetime import datetime, timedelta

from basesentinel import create_app, db
from basesentinel.models import Agent, Alert, Asset
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    AlertService,
    EventIngestionService,
    UserService,
)


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
                username=f"timeline_{role}",
                password="test-password-123",
                role=role,
            )
            result[role] = user.id

        return result


def login(client, role):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": f"timeline_{role}",
            "password": "test-password-123",
        },
    )

    assert response.status_code == 200
    return response.get_json()["token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_agent(name):
    asset = Asset(
        display_name=name,
        hostname=name.lower().replace(" ", "-"),
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

    db.session.add_all([asset, agent])
    db.session.commit()

    return agent.id


def ingest(agent_id, occurred_at, severity):
    result = EventIngestionService.ingest(
        agent_id,
        {
            "event_uid": str(uuid.uuid4()),
            "schema_version": 1,
            "category": "system",
            "event_type": "system.activity",
            "severity": severity,
            "source": "Timeline Test",
            "message": "Timeline test event",
            "event_data": {"timeline_test": True},
            "occurred_at": occurred_at.isoformat() + "Z",
        },
    )

    return result.event


@pytest.fixture
def seeded_timeline(app, users):
    with app.app_context():
        base = utcnow_naive().replace(second=0, microsecond=0)

        first_agent = create_agent("Timeline Workstation One")
        second_agent = create_agent("Timeline Workstation Two")

        old_event_one = ingest(
            first_agent,
            base - timedelta(hours=2, minutes=10),
            3,
        )

        old_event_two = ingest(
            first_agent,
            base - timedelta(hours=2, minutes=5),
            4,
        )

        recent_event = ingest(
            second_agent,
            base - timedelta(minutes=10),
            9,
        )

        alert = Alert.query.filter_by(
            source_event_id=recent_event.id,
        ).one()

        AlertService.resolve(
            alert.id,
            users["analyst"],
        )

        # Store plain values instead of detached ORM objects.
        result = {
            "first_agent": first_agent,
            "second_agent": second_agent,
            "old_event_times": [
                old_event_one.occurred_at,
                old_event_two.occurred_at,
            ],
            "recent_event_time": recent_event.occurred_at,
            "alert_id": alert.id,
        }

        return result


def parse_bucket(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).replace(tzinfo=None)


def floor_hour(value):
    return value.replace(
        minute=0,
        second=0,
        microsecond=0,
    )


def test_timeline_requires_authentication(client):
    response = client.get("/api/v1/dashboard/timeline")

    assert response.status_code == 401


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_all_roles_can_access_timeline(client, users, role):
    token = login(client, role)

    response = client.get(
        "/api/v1/dashboard/timeline",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_timeline_returns_event_and_agent_activity(
    client,
    users,
    seeded_timeline,
):
    token = login(client, "admin")

    response = client.get(
        "/api/v1/dashboard/timeline?period_hours=24",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["granularity"] == "hour"
    assert data["bucket_interval_hours"] == 1
    assert data["period"]["hours"] == 24

    buckets = data["buckets"]

    assert len(buckets) >= 24

    for bucket in buckets:
        assert "start" in bucket
        assert "event_count" in bucket
        assert "severity_counts" in bucket
        assert "alerts_created" in bucket
        assert "alerts_resolved" in bucket
        assert "active_agents" in bucket

        assert len(bucket["severity_counts"]) == 11

    assert sum(
        bucket["event_count"]
        for bucket in buckets
    ) == 3

    severity_totals = {
        severity: sum(
            item["count"]
            for bucket in buckets
            for item in bucket["severity_counts"]
            if item["severity"] == severity
        )
        for severity in range(11)
    }

    assert severity_totals[3] == 1
    assert severity_totals[4] == 1
    assert severity_totals[9] == 1

    old_bucket = floor_hour(
        seeded_timeline["old_event_times"][0]
    )

    recent_bucket = floor_hour(
        seeded_timeline["recent_event_time"]
    )

    by_start = {
        parse_bucket(bucket["start"]): bucket
        for bucket in buckets
    }

    assert by_start[old_bucket]["event_count"] == 2
    assert by_start[old_bucket]["active_agents"] == 1

    assert by_start[recent_bucket]["event_count"] == 1
    assert by_start[recent_bucket]["active_agents"] == 1

    intermediate = old_bucket + timedelta(hours=1)

    assert by_start[intermediate]["event_count"] == 0
    assert by_start[intermediate]["active_agents"] == 0


def test_timeline_tracks_alert_creation_and_resolution(
    client,
    users,
    seeded_timeline,
):
    token = login(client, "analyst")

    response = client.get(
        "/api/v1/dashboard/timeline?period_hours=24",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    buckets = response.get_json()["buckets"]

    assert sum(
        bucket["alerts_created"]
        for bucket in buckets
    ) == 1

    assert sum(
        bucket["alerts_resolved"]
        for bucket in buckets
    ) == 1


def test_timeline_empty_database_returns_zero_filled_buckets(
    client,
    users,
):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/dashboard/timeline?period_hours=24",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["buckets"]

    for bucket in data["buckets"]:
        assert bucket["event_count"] == 0
        assert bucket["alerts_created"] == 0
        assert bucket["alerts_resolved"] == 0
        assert bucket["active_agents"] == 0

        assert all(
            item["count"] == 0
            for item in bucket["severity_counts"]
        )


@pytest.mark.parametrize(
    ("period_hours", "expected_granularity", "expected_interval"),
    [
        (24, "hour", 1),
        (120, "four_hours", 4),
        (720, "day", 24),
    ],
)
def test_timeline_selects_granularity(
    client,
    users,
    period_hours,
    expected_granularity,
    expected_interval,
):
    token = login(client, "admin")

    response = client.get(
        f"/api/v1/dashboard/timeline?period_hours={period_hours}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["granularity"] == expected_granularity
    assert data["bucket_interval_hours"] == expected_interval
    assert data["period"]["hours"] == period_hours
    assert data["buckets"]


@pytest.mark.parametrize(
    "query",
    [
        "?period_hours=0",
        "?period_hours=721",
        "?period_hours=abc",
        "?period_hours=1.5",
    ],
)
def test_timeline_rejects_invalid_period(client, users, query):
    token = login(client, "admin")

    response = client.get(
        f"/api/v1/dashboard/timeline{query}",
        headers=auth_headers(token),
    )

    assert response.status_code == 400
