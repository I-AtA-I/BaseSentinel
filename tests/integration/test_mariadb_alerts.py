import os
import uuid

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import delete, inspect, select

from basesentinel import create_app, db
from basesentinel.config import Config
from basesentinel.models import (
    Alert,
    Agent,
    Asset,
    SecurityEvent,
    User,
)
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    AlertService,
    EventIngestionService,
    UserService,
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


def _assert_database():
    assert db.engine.dialect.name == "mysql"
    assert db.engine.url.database == "basesentinel_test"

    required_tables = {
        "users",
        "assets",
        "agents",
        "security_events",
        "alerts",
    }

    existing_tables = set(inspect(db.engine).get_table_names())
    assert required_tables.issubset(existing_tables)


def _create_agent(unique_id):
    asset = Asset(
        display_name=f"Alert Test {unique_id}",
        hostname=f"alert-test-{unique_id}",
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


def _create_alert(agent_id):
    result = EventIngestionService.ingest(
        agent_id,
        {
            "event_uid": str(uuid.uuid4()),
            "schema_version": 1,
            "category": "system",
            "event_type": "security.critical",
            "severity": 10,
            "source": "MariaDB Alert Integration Test",
            "message": "Critical security event",
            "event_data": {"integration_test": True},
            "occurred_at": "2026-11-17T15:00:00Z",
        },
    )

    alert = db.session.scalar(
        select(Alert).where(
            Alert.source_event_id == result.event.id
        )
    )

    assert alert is not None
    return alert.id


def _cleanup(agent_ids, asset_ids, user_ids):
    """Delete integration-test records in foreign-key dependency order."""

    db.session.rollback()

    # Delete alerts before their referenced events, agents and users.
    if agent_ids:
        db.session.execute(
            delete(Alert).where(
                Alert.agent_id.in_(agent_ids)
            )
        )

    if user_ids:
        db.session.execute(
            delete(Alert).where(
                Alert.acknowledged_by_user_id.in_(user_ids)
            )
        )

    if agent_ids:
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

    if user_ids:
        db.session.execute(
            delete(User).where(
                User.id.in_(user_ids)
            )
        )

    db.session.commit()


def test_mariadb_alert_lifecycle():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []
        user_ids = []

        try:
            admin = UserService.create_user(
                username=f"alert_admin_{uuid.uuid4().hex[:12]}",
                password="Integration-Test-Password-123",
                role="admin",
            )
            user_ids.append(admin.id)

            agent_id, asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            alert_id = _create_alert(agent_id)

            alert = db.session.get(Alert, alert_id)

            assert alert.status == "open"
            assert alert.occurrence_count == 1

            acknowledged = AlertService.acknowledge(
                alert_id,
                admin.id,
            )

            assert acknowledged.changed is True
            assert acknowledged.alert.status == "acknowledged"
            assert acknowledged.alert.acknowledged_by_user_id == admin.id
            assert acknowledged.alert.acknowledged_at is not None

            # Repeated acknowledgement must be idempotent.
            repeated = AlertService.acknowledge(
                alert_id,
                admin.id,
            )

            assert repeated.changed is False

            resolved = AlertService.resolve(
                alert_id,
                admin.id,
            )

            assert resolved.changed is True
            assert resolved.alert.status == "resolved"
            assert resolved.alert.resolved_at is not None

            # Repeated resolution must also be idempotent.
            repeated_resolution = AlertService.resolve(
                alert_id,
                admin.id,
            )

            assert repeated_resolution.changed is False

            stored = db.session.get(Alert, alert_id)

            assert stored.status == "resolved"
            assert stored.acknowledged_by_user_id == admin.id
            assert stored.acknowledged_at is not None
            assert stored.resolved_at is not None

        finally:
            _cleanup(agent_ids, asset_ids, user_ids)


def test_mariadb_viewer_cannot_change_alert_state():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []
        user_ids = []

        try:
            viewer = UserService.create_user(
                username=f"alert_viewer_{uuid.uuid4().hex[:12]}",
                password="Integration-Test-Password-123",
                role="viewer",
            )
            user_ids.append(viewer.id)

            agent_id, asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            alert_id = _create_alert(agent_id)

            with pytest.raises(PermissionError):
                AlertService.acknowledge(
                    alert_id,
                    viewer.id,
                )

            db.session.expire_all()

            alert = db.session.get(Alert, alert_id)

            assert alert.status == "open"
            assert alert.acknowledged_at is None

            with pytest.raises(PermissionError):
                AlertService.resolve(
                    alert_id,
                    viewer.id,
                )

            db.session.expire_all()

            alert = db.session.get(Alert, alert_id)
            assert alert.status == "open"

        finally:
            _cleanup(agent_ids, asset_ids, user_ids)


def test_mariadb_concurrent_alert_acknowledgement():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []
        user_ids = []

        try:
            first_analyst = UserService.create_user(
                username=f"alert_analyst_1_{uuid.uuid4().hex[:10]}",
                password="Integration-Test-Password-123",
                role="analyst",
            )

            second_analyst = UserService.create_user(
                username=f"alert_analyst_2_{uuid.uuid4().hex[:10]}",
                password="Integration-Test-Password-123",
                role="analyst",
            )

            user_ids.extend([
                first_analyst.id,
                second_analyst.id,
            ])

            agent_id, asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            alert_id = _create_alert(agent_id)

            barrier = Barrier(2)

            def acknowledge(user_id):
                with app.app_context():
                    barrier.wait(timeout=15)

                    result = AlertService.acknowledge(
                        alert_id,
                        user_id,
                    )

                    return result.changed

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(
                        acknowledge,
                        first_analyst.id,
                    ),
                    executor.submit(
                        acknowledge,
                        second_analyst.id,
                    ),
                ]

                results = [
                    future.result(timeout=30)
                    for future in futures
                ]

            # Exactly one request should change the alert.
            assert sorted(results) == [False, True]

            db.session.rollback()
            db.session.expire_all()

            alert = db.session.get(Alert, alert_id)

            assert alert.status == "acknowledged"
            assert alert.acknowledged_at is not None
            assert alert.acknowledged_by_user_id in user_ids

        finally:
            _cleanup(agent_ids, asset_ids, user_ids)
