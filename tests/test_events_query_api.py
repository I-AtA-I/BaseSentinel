
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Asset
from basesentinel.services import (
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
                username=f"query_{role}",
                password="test-password-123",
                role=role,
            )
            result[role] = user.id

        return result


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


def make_event(
    category,
    event_type,
    severity,
    occurred_at,
    message,
):
    return {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "source": "Query API Test",
        "message": message,
        "event_data": {
            "test": True,
            "value": severity,
        },
        "occurred_at": occurred_at,
    }


@pytest.fixture
def seeded_events(app):
    with app.app_context():
        first_agent = create_agent("Query Workstation One")
        second_agent = create_agent("Query Workstation Two")

        records = {}

        records["failed_login"] = EventIngestionService.ingest(
            first_agent,
            make_event(
                "authentication",
                "login.failed",
                7,
                "2026-11-17T15:30:00Z",
                "Failed login",
            ),
        ).event

        records["network"] = EventIngestionService.ingest(
            first_agent,
            make_event(
                "network",
                "connection.opened",
                3,
                "2026-11-17T15:00:00Z",
                "Network connection opened",
            ),
        ).event

        records["successful_login"] = EventIngestionService.ingest(
            first_agent,
            make_event(
                "authentication",
                "login.success",
                0,
                "2026-11-17T16:00:00Z",
                "Successful login",
            ),
        ).event

        records["service_stopped"] = EventIngestionService.ingest(
            second_agent,
            make_event(
                "system",
                "service.stopped",
                6,
                "2026-11-17T14:00:00Z",
                "Service stopped",
            ),
        ).event

        return {
            "agent_one": first_agent,
            "agent_two": second_agent,
            "events": {
                name: str(event.id)
                for name, event in records.items()
            },
        }


def login(client, role):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": f"query_{role}",
            "password": "test-password-123",
        },
    )

    assert response.status_code == 200

    return response.get_json()["token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_event_list_requires_authentication(client, seeded_events):
    response = client.get("/api/v1/events")

    assert response.status_code == 401


def test_event_detail_requires_authentication(client, seeded_events):
    event_id = seeded_events["events"]["failed_login"]

    response = client.get(f"/api/v1/events/{event_id}")

    assert response.status_code == 401


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_all_roles_can_list_events(client, users, seeded_events, role):
    token = login(client, role)

    response = client.get(
        "/api/v1/events",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"

    data = response.get_json()

    assert data["pagination"]["total"] == 3
    assert len(data["items"]) == 3


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_all_roles_can_view_event_detail(
    client,
    users,
    seeded_events,
    role,
):
    token = login(client, role)
    event_id = seeded_events["events"]["failed_login"]

    response = client.get(
        f"/api/v1/events/{event_id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["id"] == event_id
    assert data["category"] == "authentication"
    assert data["event_type"] == "login.failed"
    assert data["event_data"] == {
        "test": True,
        "value": 7,
    }
    assert data["device"]["name"] == "Query Workstation One"
    assert data["device"]["hostname"] == "query-workstation-one"
    assert data["device"]["platform"] == "windows"


def test_list_does_not_include_event_data(client, users, seeded_events):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/events",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    for event in response.get_json()["items"]:
        assert "event_data" not in event


def test_filter_by_agent_id(client, users, seeded_events):
    token = login(client, "analyst")

    response = client.get(
        f"/api/v1/events?agent_id={seeded_events['agent_one']}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 2

    assert all(
        item["agent_id"] == str(seeded_events["agent_one"])
        for item in data["items"]
    )


def test_filter_by_category(client, users, seeded_events):
    token = login(client, "analyst")

    response = client.get(
        "/api/v1/events?category=authentication",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 1

    assert all(
        item["category"] == "authentication"
        for item in data["items"]
    )


def test_filter_by_event_type(client, users, seeded_events):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/events?event_type=login.failed",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["message"] == "Failed login"


def test_filter_by_severity_range(client, users, seeded_events):
    token = login(client, "analyst")

    response = client.get(
        "/api/v1/events?severity_min=7&severity_max=9",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 1

    assert all(
        7 <= item["severity"] <= 9
        for item in data["items"]
    )


def test_filter_by_time_range(client, users, seeded_events):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/events"
        "?from=2026-11-17T15:00:00Z"
        "&to=2026-11-17T15:45:00Z",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 2


def test_events_are_ordered_newest_first(client, users, seeded_events):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/events",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    items = response.get_json()["items"]

    assert [item["message"] for item in items] == [
        "Failed login",
        "Network connection opened",
        "Service stopped",
    ]


def test_event_pagination(client, users, seeded_events):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/events?limit=2&offset=1",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"] == {
        "limit": 2,
        "offset": 1,
        "total": 3,
    }

    assert [item["message"] for item in data["items"]] == [
        "Network connection opened",
        "Service stopped",
    ]


@pytest.mark.parametrize(
    "query",
    [
        "?agent_id=invalid",
        "?category=unknown",
        "?event_type=Invalid%20Type",
        "?severity_min=abc",
        "?severity_min=11",
        "?severity_max=-1",
        "?severity_min=9&severity_max=3",
        "?limit=0",
        "?limit=101",
        "?offset=-1",
        "?from=not-a-timestamp",
        "?from=2026-11-17T15:00:00",
        "?from=2026-11-17T16:00:00Z&to=2026-11-17T14:00:00Z",
    ],
)
def test_invalid_event_filters_return_400(
    client,
    users,
    seeded_events,
    query,
):
    token = login(client, "viewer")

    response = client.get(
        f"/api/v1/events{query}",
        headers=auth_headers(token),
    )

    assert response.status_code == 400


def test_level_zero_is_hidden_by_default_and_available_via_explicit_filter(
    client,
    users,
    seeded_events,
):
    EventIngestionService.ingest(
        seeded_events["agent_one"],
        make_event(
            "authentication",
            "login.success",
            0,
            "2026-11-17T17:00:00Z",
            "Successful sign-in retained for audit",
        ),
    )
    token = login(client, "viewer")

    default_response = client.get("/api/v1/events", headers=auth_headers(token))
    assert default_response.status_code == 200
    assert default_response.get_json()["pagination"]["total"] == 3
    assert all(item["severity"] >= 1 for item in default_response.get_json()["items"])

    level_zero_response = client.get(
        "/api/v1/events?severity_min=0&severity_max=0",
        headers=auth_headers(token),
    )
    assert level_zero_response.status_code == 200
    data = level_zero_response.get_json()
    assert data["pagination"]["total"] == 2
    assert data["items"][0]["severity"] == 0
    assert data["items"][0]["event_type"] == "login.success"


def test_invalid_event_id_returns_400(client, users):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/events/not-a-uuid",
        headers=auth_headers(token),
    )

    assert response.status_code == 400


def test_unknown_event_returns_404(client, users):
    token = login(client, "viewer")

    response = client.get(
        f"/api/v1/events/{uuid.uuid4()}",
        headers=auth_headers(token),
    )

    assert response.status_code == 404
