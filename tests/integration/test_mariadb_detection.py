
import os
import uuid

import pytest
from sqlalchemy import delete, inspect

from basesentinel import create_app, db
from basesentinel.config import Config
from basesentinel.models import (
    Agent,
    Alert,
    Asset,
    SecurityEvent,
)
from basesentinel.services import (
    DetectionService,
    EventIngestionService,
)


pytestmark = pytest.mark.skipif(
    os.getenv("BASESENTINEL_MARIADB_INTEGRATION") != "1",
    reason="MariaDB integration tests are opt-in.",
)


class MariaDBTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = Config.SQLALCHEMY_DATABASE_URI.set(
        database="basesentinel_test"
    )


def create_agent(unique_id):
    asset = Asset(
        display_name=f"Detection Test {unique_id}",
        hostname=f"detection-test-{unique_id}",
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

    return agent.id, asset.id


def ingest_event(agent_id, **overrides):
    payload = {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": "authentication",
        "event_type": "login.failed",
        "severity": 4,
        "source": "MariaDB Detection Test",
        "message": "Failed authentication attempt",
        "event_data": {
            "username": "integration-user",
        },
        "occurred_at": "2026-11-17T15:00:00Z",
    }

    payload.update(overrides)

    return EventIngestionService.ingest(
        agent_id,
        payload,
    ).event


def cleanup(agent_ids, asset_ids):
    db.session.rollback()

    if agent_ids:
        db.session.execute(
            delete(Alert).where(
                Alert.agent_id.in_(agent_ids)
            )
        )

        db.session.execute(
            delete(SecurityEvent).where(
                SecurityEvent.agent_id.in_(agent_ids)
            )
        )

        db.session.execute(
            delete(Agent).where(
                Agent.id.in_(agent_ids)
            )
        )

    if asset_ids:
        db.session.execute(
            delete(Asset).where(
                Asset.id.in_(asset_ids)
            )
        )

    db.session.commit()


def test_mariadb_high_severity_detection():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        assert db.engine.dialect.name == "mysql"

        required_tables = {
            "agents",
            "assets",
            "security_events",
            "alerts",
        }

        existing_tables = set(
            inspect(db.engine).get_table_names()
        )

        assert required_tables.issubset(existing_tables)

        agent_ids = []
        asset_ids = []

        try:
            agent_id, asset_id = create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            event = ingest_event(
                agent_id,
                category="system",
                event_type="security.critical",
                severity=10,
            )

            alerts = DetectionService.process_event(event)
            db.session.commit()

            assert len(alerts) == 1

            alert = alerts[0]

            assert alert.rule_key == "high_severity_event"
            assert alert.severity == 10
            assert alert.agent_id == agent_id
            assert alert.source_event_id == event.id

            db.session.refresh(alert)

            assert Alert.query.filter_by(
                rule_key="high_severity_event",
                deduplication_key=alert.deduplication_key,
            ).count() == 1

        finally:
            cleanup(agent_ids, asset_ids)


def test_mariadb_repeated_failed_login_detection():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        assert db.engine.dialect.name == "mysql"

        agent_ids = []
        asset_ids = []

        try:
            agent_id, asset_id = create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            created_alerts = []

            for minute in range(5):
                event = ingest_event(
                    agent_id,
                    occurred_at=(
                        f"2026-11-17T15:{minute:02d}:00Z"
                    ),
                )

                alerts = DetectionService.process_event(event)
                db.session.commit()

                if alerts:
                    created_alerts.extend(alerts)

            assert len(created_alerts) == 1

            alert = created_alerts[0]

            assert alert.rule_key == "repeated_failed_logins"
            assert alert.occurrence_count == 5
            assert alert.severity == 8

            # A sixth event inside the same window must update
            # the existing alert instead of creating another one.
            sixth_event = ingest_event(
                agent_id,
                occurred_at="2026-11-17T15:04:30Z",
            )

            updated_alerts = DetectionService.process_event(
                sixth_event
            )
            db.session.commit()

            assert len(updated_alerts) == 1
            assert updated_alerts[0].id == alert.id
            assert updated_alerts[0].occurrence_count == 6

            assert Alert.query.filter_by(
                rule_key="repeated_failed_logins",
                deduplication_key=alert.deduplication_key,
            ).count() == 1

        finally:
            cleanup(agent_ids, asset_ids)
