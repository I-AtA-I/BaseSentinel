
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Alert, Asset
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
                username=f"alert_{role}",
                password="test-password-123",
                role=role,
            )
            result[role] = user.id

        return result


@pytest.fixture
def seeded_alerts(app):
    with app.app_context():
        asset_one = Asset(
            display_name="Alert Test One",
            hostname="alert-test-one",
            asset_type="workstation",
        )

        asset_two = Asset(
            display_name="Alert Test Two",
            hostname="alert-test-two",
            asset_type="workstation",
        )

        agent_one = Agent(
            asset=asset_one,
            platform="windows",
            platform_version="11",
            architecture="x64",
            agent_version="0.1.0",
            status="active",
        )

        agent_two = Agent(
            asset=asset_two,
            platform="linux",
            architecture="x64",
            agent_version="0.1.0",
            status="active",
        )

        db.session.add_all([asset_one, asset_two, agent_one, agent_two])
        db.session.commit()

        events = [
            (agent_one.id, 9, "2026-11-17T13:00:00Z"),
            (agent_one.id, 10, "2026-11-17T14:00:00Z"),
            (agent_one.id, 9, "2026-11-17T15:00:00Z"),
            (agent_two.id, 10, "2026-11-17T16:00:00Z"),
        ]

        alert_ids = []

        for agent_id, severity, occurred_at in events:
            result = EventIngestionService.ingest(
                agent_id,
                {
                    "event_uid": str(uuid.uuid4()),
                    "schema_version": 1,
                    "category": "system",
                    "event_type": "security.critical",
                    "severity": severity,
                    "source": "Alert API Test",
                    "message": "Critical security event",
                    "event_data": {"test": True},
                    "occurred_at": occurred_at,
                },
            )

            alerts = [
                alert
                for alert in Alert.query.filter_by(
                    source_event_id=result.event.id
                ).all()
            ]

            assert len(alerts) == 1
            alert_ids.append(alerts[0].id)

        return {
            "agent_one": agent_one.id,
            "agent_two": agent_two.id,
            "alert_ids": alert_ids,
        }


def login(client, role):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": f"alert_{role}",
            "password": "test-password-123",
        },
    )

    assert response.status_code == 200

    return response.get_json()["token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_alert_list_requires_authentication(client, seeded_alerts):
    response = client.get("/api/v1/alerts")

    assert response.status_code == 401


def test_alert_detail_requires_authentication(client, seeded_alerts):
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.get(f"/api/v1/alerts/{alert_id}")

    assert response.status_code == 401


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_all_roles_can_list_alerts(
    client,
    users,
    seeded_alerts,
    role,
):
    token = login(client, role)

    response = client.get(
        "/api/v1/alerts",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"

    data = response.get_json()

    assert data["pagination"]["total"] == 4
    assert len(data["items"]) == 4


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_all_roles_can_view_alert_detail(
    client,
    users,
    seeded_alerts,
    role,
):
    token = login(client, role)
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.get(
        f"/api/v1/alerts/{alert_id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["id"] == str(alert_id)
    assert data["rule_key"] == "high_severity_event"
    assert data["title"] == "High-severity security event"
    assert data["severity"] == 9
    assert data["status"] == "open"
    assert data["occurrence_count"] == 1


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_alert_detail_does_not_expose_deduplication_key(
    client,
    users,
    seeded_alerts,
    role,
):
    token = login(client, role)
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.get(
        f"/api/v1/alerts/{alert_id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert "deduplication_key" not in response.get_json()


def test_viewer_cannot_acknowledge_alert(
    client,
    users,
    seeded_alerts,
    app,
):
    token = login(client, "viewer")
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=auth_headers(token),
    )

    assert response.status_code == 403

    alert = db.session.get(Alert, alert_id)
    assert alert.status == "open"
    assert alert.acknowledged_at is None


@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_admin_and_analyst_can_acknowledge_alert(
    client,
    users,
    seeded_alerts,
    role,
):
    token = login(client, role)
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["changed"] is True
    assert data["alert"]["status"] == "acknowledged"
    assert data["alert"]["acknowledged_at"] is not None
    assert data["alert"]["acknowledged_by_user_id"] == str(
        users[role]
    )


def test_acknowledgement_is_idempotent(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "analyst")
    alert_id = seeded_alerts["alert_ids"][0]
    headers = auth_headers(token)

    first = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=headers,
    )

    second = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.get_json()["changed"] is True
    assert second.get_json()["changed"] is False

    assert (
        first.get_json()["alert"]["acknowledged_at"]
        == second.get_json()["alert"]["acknowledged_at"]
    )


def test_viewer_cannot_resolve_alert(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "viewer")
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=auth_headers(token),
    )

    assert response.status_code == 403


@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_admin_and_analyst_can_resolve_alert(
    client,
    users,
    seeded_alerts,
    role,
):
    token = login(client, role)
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["changed"] is True
    assert data["alert"]["status"] == "resolved"
    assert data["alert"]["resolved_at"] is not None


def test_acknowledged_alert_can_be_resolved(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "analyst")
    headers = auth_headers(token)
    alert_id = seeded_alerts["alert_ids"][0]

    acknowledge = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=headers,
    )

    assert acknowledge.status_code == 200

    resolve = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=headers,
    )

    assert resolve.status_code == 200
    assert resolve.get_json()["alert"]["status"] == "resolved"


def test_resolving_alert_is_idempotent(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "analyst")
    alert_id = seeded_alerts["alert_ids"][0]
    headers = auth_headers(token)

    first = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=headers,
    )

    second = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=headers,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.get_json()["changed"] is True
    assert second.get_json()["changed"] is False


def test_resolved_alert_cannot_be_acknowledged(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "analyst")
    headers = auth_headers(token)
    alert_id = seeded_alerts["alert_ids"][0]

    resolve = client.post(
        f"/api/v1/alerts/{alert_id}/resolve",
        headers=headers,
    )

    assert resolve.status_code == 200

    acknowledge = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=headers,
    )

    assert acknowledge.status_code == 409


def test_filter_alerts_by_status(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "analyst")
    alert_id = seeded_alerts["alert_ids"][0]

    client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge",
        headers=auth_headers(token),
    )

    response = client.get(
        "/api/v1/alerts?status=acknowledged",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["id"] == str(alert_id)


def test_filter_alerts_by_agent_id(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "viewer")

    response = client.get(
        f"/api/v1/alerts?agent_id={seeded_alerts['agent_one']}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"]["total"] == 3

    assert all(
        item["agent_id"] == str(seeded_alerts["agent_one"])
        for item in data["items"]
    )


def test_filter_alerts_by_rule_key(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/alerts?rule_key=high_severity_event",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.get_json()["pagination"]["total"] == 4


def test_filter_alerts_by_severity(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/alerts?severity_min=10&severity_max=10",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.get_json()["pagination"]["total"] == 2


def test_filter_alerts_by_time_range(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/alerts"
        "?from=2026-11-17T13:30:00Z"
        "&to=2026-11-17T15:30:00Z",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.get_json()["pagination"]["total"] == 2


def test_alert_pagination(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/alerts?limit=2&offset=1",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["pagination"] == {
        "limit": 2,
        "offset": 1,
        "total": 4,
    }

    assert len(data["items"]) == 2


@pytest.mark.parametrize(
    "query",
    [
        "?status=invalid",
        "?agent_id=not-a-uuid",
        "?rule_key=Invalid%20Rule",
        "?severity_min=abc",
        "?severity_min=11",
        "?severity_max=-1",
        "?severity_min=9&severity_max=3",
        "?limit=0",
        "?limit=101",
        "?offset=-1",
        "?from=not-a-timestamp",
        "?from=2026-11-17T13:00:00",
        "?from=2026-11-17T16:00:00Z&to=2026-11-17T13:00:00Z",
    ],
)
def test_invalid_alert_filters_return_400(
    client,
    users,
    seeded_alerts,
    query,
):
    token = login(client, "viewer")

    response = client.get(
        f"/api/v1/alerts{query}",
        headers=auth_headers(token),
    )

    assert response.status_code == 400


def test_invalid_alert_id_returns_400(client, users):
    token = login(client, "viewer")

    response = client.get(
        "/api/v1/alerts/not-a-uuid",
        headers=auth_headers(token),
    )

    assert response.status_code == 400


def test_unknown_alert_returns_404(client, users):
    token = login(client, "viewer")

    response = client.get(
        f"/api/v1/alerts/{uuid.uuid4()}",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


def test_acknowledging_unknown_alert_returns_404(
    client,
    users,
):
    token = login(client, "analyst")

    response = client.post(
        f"/api/v1/alerts/{uuid.uuid4()}/acknowledge",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


def test_resolving_unknown_alert_returns_404(
    client,
    users,
):
    token = login(client, "analyst")

    response = client.post(
        f"/api/v1/alerts/{uuid.uuid4()}/resolve",
        headers=auth_headers(token),
    )

    assert response.status_code == 404


def test_viewer_cannot_delete_alert(client, users, seeded_alerts):
    token = login(client, "viewer")
    alert_id = seeded_alerts["alert_ids"][0]

    response = client.delete(
        f"/api/v1/alerts/{alert_id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 403
    assert db.session.get(Alert, alert_id) is not None


def test_admin_can_delete_alert_without_deleting_source_event(
    client,
    users,
    seeded_alerts,
    app,
):
    token = login(client, "admin")
    alert_id = seeded_alerts["alert_ids"][0]
    source_event_id = db.session.get(Alert, alert_id).source_event_id

    response = client.delete(
        f"/api/v1/alerts/{alert_id}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "alert_id": str(alert_id),
        "deleted": True,
    }
    assert db.session.get(Alert, alert_id) is None
    from basesentinel.models import SecurityEvent
    assert db.session.get(SecurityEvent, source_event_id) is not None


def test_admin_can_flush_all_alerts_but_preserve_events(
    client,
    users,
    seeded_alerts,
):
    token = login(client, "admin")

    response = client.delete(
        "/api/v1/alerts",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.get_json()["deleted"] == 4
    assert Alert.query.count() == 0
    from basesentinel.models import SecurityEvent
    assert SecurityEvent.query.count() == 4


def test_viewer_cannot_flush_all_alerts(client, users, seeded_alerts):
    token = login(client, "viewer")

    response = client.delete(
        "/api/v1/alerts",
        headers=auth_headers(token),
    )

    assert response.status_code == 403
    assert Alert.query.count() == 4
