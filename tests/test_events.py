from basesentinel.models import Alert
from basesentinel.services.detection import DetectionService
import uuid
from datetime import datetime, timedelta

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Asset, SecurityEvent
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    EventIngestionService,
    InvalidEventPayloadError,
    UnavailableAgentForIngestionError,
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
        display_name="Event Test Workstation",
        hostname="event-test",
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


def make_event(event_uid=None, **overrides):
    payload = {
        "event_uid": str(event_uid or uuid.uuid4()),
        "schema_version": 1,
        "category": "authentication",
        "event_type": "login.failed",
        "severity": 7,
        "source": "Windows Security",
        "event_code": "4625",
        "message": "Failed authentication attempt",
        "event_data": {
            "username": "example",
            "logon_type": 3,
        },
        "occurred_at": "2026-11-17T15:30:00Z",
    }

    payload.update(overrides)
    return payload


def test_ingest_valid_event(app, agent):
    payload = make_event(
        occurred_at="2026-11-17T14:30:00+02:00"
    )

    result = EventIngestionService.ingest(agent, payload)

    assert result.duplicate is False
    assert result.event.agent_id == agent
    assert result.event.event_uid == uuid.UUID(payload["event_uid"])
    assert result.event.category == "authentication"
    assert result.event.event_type == "login.failed"
    assert result.event.severity == 7
    assert result.event.source == "Windows Security"
    assert result.event.event_code == "4625"
    assert result.event.message == "Failed authentication attempt"

    assert result.event.event_data == {
        "username": "example",
        "logon_type": 3,
    }

    assert result.event.occurred_at == datetime(2026, 11, 17, 12, 30)
    assert result.event.received_at is not None

    stored = db.session.get(SecurityEvent, result.event.id)
    assert stored is not None


def test_ingest_returns_existing_event_for_duplicate(app, agent):
    event_uid = uuid.uuid4()

    first = EventIngestionService.ingest(
        agent,
        make_event(event_uid=event_uid),
    )

    second = EventIngestionService.ingest(
        agent,
        make_event(
            event_uid=event_uid,
            message="Different message",
            severity=2,
        ),
    )

    assert first.duplicate is False
    assert second.duplicate is True
    assert second.event.id == first.event.id

    # A duplicate must not overwrite the original event.
    assert second.event.message == "Failed authentication attempt"
    assert second.event.severity == 7

    assert SecurityEvent.query.count() == 1


def test_same_event_uid_is_allowed_for_different_agents(app, agent):
    second_asset = Asset(
        display_name="Second Workstation",
        hostname="second-workstation",
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

    event_uid = uuid.uuid4()

    first = EventIngestionService.ingest(
        agent,
        make_event(event_uid=event_uid),
    )

    second = EventIngestionService.ingest(
        second_agent.id,
        make_event(event_uid=event_uid),
    )

    assert first.duplicate is False
    assert second.duplicate is False
    assert first.event.id != second.event.id
    assert SecurityEvent.query.count() == 2


@pytest.mark.parametrize("payload", [None, [], "invalid", 123])
def test_rejects_non_object_payload(app, agent, payload):
    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)

    assert SecurityEvent.query.count() == 0


def test_rejects_missing_required_fields(app, agent):
    payload = make_event()
    del payload["event_uid"]

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)

    assert SecurityEvent.query.count() == 0


def test_rejects_unsupported_fields(app, agent):
    payload = make_event(agent_id=str(agent))

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)

    assert SecurityEvent.query.count() == 0


@pytest.mark.parametrize("version", [0, 2, -1, True])
def test_rejects_unsupported_schema_version(app, agent, version):
    payload = make_event(schema_version=version)

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


@pytest.mark.parametrize("severity", [-1, 11, True, 7.5, "7"])
def test_rejects_invalid_severity(app, agent, severity):
    payload = make_event(severity=severity)

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_unsupported_category(app, agent):
    payload = make_event(category="unknown_category")

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_invalid_event_type(app, agent):
    payload = make_event(event_type="Invalid Event Type")

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_invalid_event_uid(app, agent):
    payload = make_event(event_uid="not-a-uuid")

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_timestamp_without_timezone(app, agent):
    payload = make_event(
        occurred_at="2026-11-17T15:30:00"
    )

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_invalid_timestamp(app, agent):
    payload = make_event(occurred_at="not-a-timestamp")

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_non_object_event_data(app, agent):
    payload = make_event(event_data=["invalid", "data"])

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_event_data_over_size_limit(app, agent):
    payload = make_event(
        event_data={
            "large_value": "x" * (
                EventIngestionService.MAX_EVENT_DATA_BYTES + 1
            )
        }
    )

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_non_json_event_data(app, agent):
    payload = make_event(
        event_data={"invalid": float("nan")}
    )

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


def test_rejects_message_over_maximum_length(app, agent):
    payload = make_event(
        message="x" * (
            EventIngestionService.MAX_MESSAGE_LENGTH + 1
        )
    )

    with pytest.raises(InvalidEventPayloadError):
        EventIngestionService.ingest(agent, payload)


@pytest.mark.parametrize("state", ["revoked", "inactive", "uninstalled"])
def test_rejects_unavailable_agent(app, agent, state):
    stored_agent = db.session.get(Agent, agent)

    if state == "revoked":
        stored_agent.status = "revoked"
        stored_agent.revoked_at = utcnow_naive()

    elif state == "inactive":
        stored_agent.status = "inactive"

    elif state == "uninstalled":
        stored_agent.uninstalled_at = utcnow_naive()

    db.session.commit()

    with pytest.raises(UnavailableAgentForIngestionError):
        EventIngestionService.ingest(
            agent,
            make_event(),
        )

    assert SecurityEvent.query.count() == 0


def test_rejects_unknown_agent(app):
    with pytest.raises(UnavailableAgentForIngestionError):
        EventIngestionService.ingest(
            uuid.uuid4(),
            make_event(),
        )

    assert SecurityEvent.query.count() == 0


def test_ingestion_triggers_detection_automatically(app, agent):
    payload = make_event(
        severity=10,
        category="system",
        event_type="security.critical",
    )

    result = EventIngestionService.ingest(agent, payload)

    alerts = Alert.query.filter_by(
        rule_key="high_severity_event",
        source_event_id=result.event.id,
    ).all()

    assert len(alerts) == 1
    assert alerts[0].severity == 10
    assert alerts[0].agent_id == agent


def test_detection_failure_rolls_back_event(app, agent, monkeypatch):
    def fail_detection(event):
        raise RuntimeError("Simulated detection failure.")

    monkeypatch.setattr(
        DetectionService,
        "process_event",
        fail_detection,
    )

    payload = make_event(
        severity=10,
        category="system",
        event_type="security.critical",
    )

    with pytest.raises(RuntimeError):
        EventIngestionService.ingest(agent, payload)

    event_uid = uuid.UUID(payload["event_uid"])

    assert SecurityEvent.query.filter_by(
        event_uid=event_uid
    ).count() == 0

    assert Alert.query.count() == 0



def test_successful_windows_logon_is_normalized_to_level_zero(app, agent):
    result = EventIngestionService.ingest(
        agent,
        make_event(
            category="authentication",
            event_type="login.success",
            severity=2,
            event_code="4624",
            source="Windows Security",
            message="An account was successfully logged on.",
        ),
    )

    assert result.event.severity == 0
    assert Alert.query.count() == 0
