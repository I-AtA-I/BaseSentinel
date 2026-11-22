
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
    event_data=None,
):
    payload = {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "source": "Detection Test",
        "message": "Detection test event",
        "event_data": (
            event_data if event_data is not None else {"username": username}
        ),
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


@pytest.mark.parametrize(
    ("category", "event_type", "expected_title", "expected_severity"),
    [
        ("system", "device.usb_storage_recognized", "USB storage device recognized", 8),
        ("service", "service.installed", "Windows service installed", 8),
        ("audit", "security_log.cleared", "Windows Security log cleared", 10),
    ],
)
def test_important_windows_events_create_alerts(
    app, agent, category, event_type, expected_title, expected_severity
):
    event = ingest_event(
        agent,
        severity=5,
        event_type=event_type,
        category=category,
    )

    alerts = process(event)

    assert len(alerts) == 1
    assert alerts[0].rule_key == DetectionService.IMPORTANT_EVENT_RULE
    assert alerts[0].title == expected_title
    assert alerts[0].severity == expected_severity
    assert alerts[0].source_event_id == event.id
    assert Alert.query.count() == 1


def test_usb_recognition_records_for_same_device_share_one_alert(app, agent):
    device_id = "USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_Duo\\1831BFBD3065C57029600109&0"
    first_event = ingest_event(
        agent,
        event_type="device.usb_storage_recognized",
        category="system",
        minute=0,
        event_data={"DeviceId": device_id},
    )
    first_alert = Alert.query.filter_by(
        rule_key=DetectionService.IMPORTANT_EVENT_RULE
    ).one()

    second_event = ingest_event(
        agent,
        event_type="device.usb_storage_recognized",
        category="system",
        minute=1,
        event_data={"DeviceId": device_id.swapcase()},
    )
    second_alerts = process(second_event)

    assert len(second_alerts) == 1
    assert second_alerts[0].id == first_alert.id
    assert second_alerts[0].title == "USB storage device recognized"
    assert second_alerts[0].occurrence_count == 2
    assert second_alerts[0].source_event_id == first_event.id
    assert Alert.query.filter_by(
        rule_key=DetectionService.IMPORTANT_EVENT_RULE
    ).count() == 1


def test_usb_recognition_records_for_different_devices_create_separate_alerts(
    app, agent
):
    device_ids = ("USBSTOR\\Disk\\DEVICE_A", "USBSTOR\\Disk\\DEVICE_B")
    for minute, device_id in enumerate(device_ids):
        ingest_event(
            agent,
            event_type="device.usb_storage_recognized",
            category="system",
            minute=minute,
            event_data={"DeviceId": device_id},
        )

    alerts = Alert.query.filter_by(
        rule_key=DetectionService.IMPORTANT_EVENT_RULE
    ).all()

    assert len(alerts) == 2
    assert all(alert.occurrence_count == 1 for alert in alerts)


def test_usb_recognition_without_device_id_remains_per_event(app, agent):
    for minute in range(2):
        ingest_event(
            agent,
            event_type="device.usb_storage_recognized",
            category="system",
            minute=minute,
            event_data={"DeviceDescription": "Unknown USB storage"},
        )

    assert Alert.query.filter_by(
        rule_key=DetectionService.IMPORTANT_EVENT_RULE
    ).count() == 2


def test_severity_below_threshold_does_not_create_alert(app, agent):
    event = ingest_event(
        agent,
        severity=7,
        event_type="system.warning",
        category="system",
    )

    alerts = process(event)

    assert alerts == []
    assert Alert.query.count() == 0


def test_severity_eight_event_creates_alert(app, agent):
    event = ingest_event(
        agent,
        severity=8,
        event_type="system.warning",
        category="system",
    )

    alerts = process(event)

    assert len(alerts) == 1
    assert alerts[0].rule_key == "high_severity_event"
    assert alerts[0].severity == 8


@pytest.mark.parametrize(
    ("event_type", "expected_severity"),
    [
        ("malware.detected", 10),
        ("malware.remediation_failed", 10),
        ("attack_surface_reduction.blocked", 8),
    ],
)
def test_endpoint_protection_events_create_alerts(app, agent, event_type, expected_severity):
    event = ingest_event(
        agent,
        severity=expected_severity,
        event_type=event_type,
        category="application",
        event_data={"Threat Name": "Test threat", "Path": "C:\\\\sample.exe"},
    )

    alerts = process(event)

    assert len(alerts) == 1
    assert alerts[0].severity == expected_severity
    assert alerts[0].source_event_id == event.id


def test_defender_malware_records_for_same_threat_and_path_share_one_incident(
    app, agent
):
    identity = {"ID": "2147925201", "Threat Name": "Trojan:Win32/Pomal!rfn"}
    first = ingest_event(
        agent,
        severity=10,
        event_type="malware.detected",
        category="application",
        minute=17,
        event_data={
            **identity,
            "Path": "file:\\_C:\\Users\\MSI\\Downloads\\sample.exe",
            "Process Name": "C:\\Windows\\System32\\RuntimeBroker.exe",
        },
    )
    first_alert = Alert.query.filter_by(
        rule_key=DetectionService.MALWARE_INCIDENT_RULE
    ).one()

    second = ingest_event(
        agent,
        severity=10,
        event_type="malware.detected",
        category="application",
        minute=18,
        event_data={
            **identity,
            "Path": "C:\\Users\\MSI\\Downloads\\SAMPLE.exe",
            "Process Name": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        },
    )

    alerts = DetectionService.process_event(second)
    db.session.commit()

    assert len(alerts) == 1
    assert alerts[0].id == first_alert.id
    assert alerts[0].rule_key == "malware_incident"
    assert alerts[0].occurrence_count == 2
    assert alerts[0].source_event_id == first.id
    assert alerts[0].first_seen_at == first.occurred_at
    assert alerts[0].last_seen_at == second.occurred_at
    assert Alert.query.filter_by(
        rule_key=DetectionService.MALWARE_INCIDENT_RULE
    ).count() == 1


def test_defender_malware_different_threats_create_separate_incidents(app, agent):
    common = {"Path": "C:\\Users\\MSI\\Downloads\\sample.exe"}
    for minute, threat_id in ((17, "1001"), (18, "2002")):
        ingest_event(
            agent,
            severity=10,
            event_type="malware.detected",
            category="application",
            minute=minute,
            event_data={**common, "ID": threat_id, "Threat Name": f"Threat-{threat_id}"},
        )

    incidents = Alert.query.filter_by(
        rule_key=DetectionService.MALWARE_INCIDENT_RULE
    ).all()
    assert len(incidents) == 2


def test_defender_remediation_completed_does_not_create_alert(app, agent):
    event = ingest_event(
        agent,
        severity=3,
        event_type="malware.remediation_completed",
        category="application",
        event_data={
            "ID": "2147925201",
            "Threat Name": "Trojan:Win32/Pomal!rfn",
            "Path": "C:\\Users\\MSI\\Downloads\\sample.exe",
            "Action": "Quarantine",
        },
    )

    assert Alert.query.count() == 0
    assert DetectionService.process_event(event) == []


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
