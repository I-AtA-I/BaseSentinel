
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Alert, Asset
from basesentinel.services import (
    DetectionService,
    EventIngestionService,
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
def agent(app):
    asset = Asset(
        display_name="Detection Test",
        hostname="detection-test",
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


def ingest_event(
    agent_id,
    severity=5,
    event_type="login.failed",
    username="testuser",
    minute=0,
    category="authentication",
):
    payload = {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "source": "Detection Test",
        "message": "Detection test event",
        "event_data": {
            "username": username,
        },
        "occurred_at": (
            f"2026-11-17T15:{minute:02d}:00Z"
        ),
    }

    return EventIngestionService.ingest(
        agent_id,
        payload,
    ).event


def process(event):
    alerts = DetectionService.process_event(event)
    db.session.commit()
    return alerts


def test_high_severity_event_creates_alert(app, agent):
    event = ingest_event(
        agent,
        severity=9,
        event_type="security.critical",
        category="system",
    )

    alerts = process(event)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_key == "high_severity_event"
    assert alert.severity == 9
    assert alert.status == "open"
    assert alert.agent_id == agent
    assert alert.source_event_id == event.id
    assert alert.occurrence_count == 1


def test_severity_below_threshold_does_not_create_alert(app, agent):
    event = ingest_event(
        agent,
        severity=8,
        event_type="system.warning",
        category="system",
    )

    alerts = process(event)

    assert alerts == []
    assert Alert.query.count() == 0


def test_high_severity_alert_is_idempotent(app, agent):
    event = ingest_event(
        agent,
        severity=10,
        event_type="security.critical",
        category="system",
    )

    first = process(event)
    second = process(event)

    assert len(first) == 1
    assert len(second) == 1
    assert first[0].id == second[0].id

    assert Alert.query.filter_by(
        rule_key="high_severity_event"
    ).count() == 1


def test_repeated_failed_logins_create_alert_at_threshold(app, agent):
    for minute in range(4):
        event = ingest_event(
            agent,
            minute=minute,
        )

        assert process(event) == []

    assert Alert.query.count() == 0

    fifth_event = ingest_event(
        agent,
        minute=4,
    )

    alerts = process(fifth_event)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_key == "repeated_failed_logins"
    assert alert.severity == 8
    assert alert.status == "open"
    assert alert.occurrence_count == 5
    assert alert.source_event_id == fifth_event.id



def test_repeated_failed_logins_update_existing_alert(app, agent):
    for minute in range(5):
        event = ingest_event(
            agent,
            minute=minute,
        )
        process(event)

    original = Alert.query.filter_by(
        rule_key="repeated_failed_logins"
    ).one()

    # Keep the sixth event inside the same five-minute window.
    sixth_event = ingest_event(
        agent,
        minute=4,
    )

    alerts = process(sixth_event)

    assert len(alerts) == 1
    assert alerts[0].id == original.id
    assert alerts[0].occurrence_count == 6

    assert Alert.query.filter_by(
        rule_key="repeated_failed_logins"
    ).count() == 1



def test_different_accounts_create_separate_alerts(app, agent):
    for username in ("alice", "bob"):
        for minute in range(5):
            event = ingest_event(
                agent,
                username=username,
                minute=minute,
            )
            process(event)

    alerts = Alert.query.filter_by(
        rule_key="repeated_failed_logins"
    ).all()

    assert len(alerts) == 2
    assert all(alert.occurrence_count == 5 for alert in alerts)


def test_different_agents_create_separate_alerts(app, agent):
    second_asset = Asset(
        display_name="Second Detection Test",
        hostname="second-detection-test",
        asset_type="workstation",
    )

    second_agent = Agent(
        asset=second_asset,
        platform="linux",
        agent_version="0.1.0",
        status="active",
    )

    db.session.add_all([second_asset, second_agent])
    db.session.commit()

    for agent_id in (agent, second_agent.id):
        for minute in range(5):
            event = ingest_event(
                agent_id,
                minute=minute,
            )
            process(event)

    alerts = Alert.query.filter_by(
        rule_key="repeated_failed_logins"
    ).all()

    assert len(alerts) == 2
    assert alerts[0].agent_id != alerts[1].agent_id


def test_other_event_types_do_not_trigger_login_rule(app, agent):
    for minute in range(6):
        event = ingest_event(
            agent,
            event_type="login.success",
            minute=minute,
            severity=3,
        )

        assert process(event) == []

    assert Alert.query.count() == 0


def test_failed_login_without_username_is_ignored(app, agent):
    event = ingest_event(
        agent,
        username=None,
    )

    # Replace event data with an object lacking username.
    event.event_data = {"source": "test"}
    db.session.commit()

    assert process(event) == []
    assert Alert.query.count() == 0


def test_failed_logins_in_different_time_windows_do_not_combine(app, agent):
    first_window = [0, 1, 2]
    second_window = [5, 6, 7]

    for minute in first_window + second_window:
        event = ingest_event(
            agent,
            minute=minute,
        )

        assert process(event) == []

    assert Alert.query.count() == 0
