import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.models import Agent, Asset, CorrelatedActivity, CorrelatedActivityEvent, SecurityEvent
from basesentinel.services.correlation import CorrelationService
from basesentinel.services.events import EventIngestionService


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
        display_name="Correlation Test",
        hostname="correlation-test",
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


def ingest_privilege_event(agent_id, timestamp, **overrides):
    data = {
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "SubjectLogonId": "0x3e7",
        "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege SeTcbPrivilege",
    }
    data.update(overrides)
    return EventIngestionService.ingest(agent_id, {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": "authentication",
        "event_type": "privilege.special_assignment",
        "severity": 5,
        "source": "Windows Security",
        "event_code": "4672",
        "message": "Special privileges assigned to new logon.",
        "event_data": data,
        "occurred_at": timestamp,
    }).event


def test_matching_4672_events_create_one_activity_with_both_raw_events(app, agent):
    first = ingest_privilege_event(agent, "2026-11-22T11:05:52Z")
    second = ingest_privilege_event(agent, "2026-11-22T11:05:55Z")

    activities = CorrelatedActivity.query.all()
    assert len(activities) == 1
    activity = activities[0]
    assert activity.activity_type == CorrelationService.PRIVILEGE_ASSIGNMENT_TYPE
    assert activity.occurrence_count == 2
    assert activity.first_seen_at == first.occurred_at
    assert activity.last_seen_at == second.occurred_at
    assert {event.id for event in activity.source_events} == {first.id, second.id}
    assert SecurityEvent.query.count() == 2
    assert CorrelatedActivityEvent.query.count() == 2
    assert activity.context["account"] == "s-1-5-18"
    assert activity.context["logon_id"] == "0x3e7"


@pytest.mark.parametrize(
    "changes",
    [
        {"SubjectUserSid": "S-1-5-21-1001"},
        {"SubjectLogonId": "0x1234"},
        {"PrivilegeList": "SeDebugPrivilege"},
    ],
)
def test_different_4672_identity_does_not_merge(app, agent, changes):
    ingest_privilege_event(agent, "2026-11-22T11:05:52Z")
    ingest_privilege_event(agent, "2026-11-22T11:05:55Z", **changes)
    assert CorrelatedActivity.query.count() == 2


def test_same_4672_identity_outside_window_creates_new_activity(app, agent):
    ingest_privilege_event(agent, "2026-11-22T11:05:52Z")
    ingest_privilege_event(agent, "2026-11-22T11:12:00Z")
    assert CorrelatedActivity.query.count() == 2


def test_missing_correlation_fields_are_not_grouped(app, agent):
    ingest_privilege_event(agent, "2026-11-22T11:05:52Z", SubjectLogonId="")
    ingest_privilege_event(agent, "2026-11-22T11:05:55Z", SubjectLogonId="")
    assert CorrelatedActivity.query.count() == 2


def test_reprocessing_same_source_event_does_not_increase_count(app, agent):
    event = ingest_privilege_event(agent, "2026-11-22T11:05:52Z")
    activity = CorrelationService.process_event(event)
    db.session.commit()
    assert activity.occurrence_count == 1
    assert CorrelatedActivityEvent.query.count() == 1
