
import os
import uuid

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from sqlalchemy import delete, inspect, select

from basesentinel import create_app, db
from basesentinel.config import Config
from basesentinel.models import (
    Agent,
    AgentCredential,
    Asset,
    SecurityEvent,
    User,
)
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    EventIngestionService,
    UnavailableAgentForIngestionError,
    AgentCredentialService,
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
        "assets",
        "agents",
        "agent_credentials",
        "users",
        "security_events",
    }

    existing_tables = set(inspect(db.engine).get_table_names())
    assert required_tables.issubset(existing_tables)


def _create_agent(unique_id):
    asset = Asset(
        display_name=f"Event Test {unique_id}",
        hostname=f"event-test-{unique_id}",
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


def _make_event(event_uid=None, **overrides):
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
            "username": "integration-user",
            "logon_type": 3,
        },
        "occurred_at": "2026-11-17T15:30:00Z",
    }

    payload.update(overrides)
    return payload


def _cleanup(agent_ids, asset_ids, user_ids=None):
    """Delete integration-test records in foreign-key dependency order."""

    agent_ids = list(agent_ids)
    asset_ids = list(asset_ids)
    user_ids = list(user_ids or [])

    db.session.rollback()

    if agent_ids:
        db.session.execute(
            delete(SecurityEvent).where(
                SecurityEvent.agent_id.in_(agent_ids)
            )
        )

        db.session.execute(
            delete(AgentCredential).where(
                AgentCredential.agent_id.in_(agent_ids)
            )
        )

        db.session.execute(
            delete(Agent).where(Agent.id.in_(agent_ids))
        )

    if asset_ids:
        db.session.execute(
            delete(Asset).where(Asset.id.in_(asset_ids))
        )

    if user_ids:
        db.session.execute(
            delete(User).where(User.id.in_(user_ids))
        )

    db.session.commit()


def test_mariadb_event_ingestion_and_deduplication():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []

        try:
            first_agent_id, first_asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            second_agent_id, second_asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.extend([first_agent_id, second_agent_id])
            asset_ids.extend([first_asset_id, second_asset_id])

            event_uid = uuid.uuid4()

            payload = _make_event(event_uid=event_uid)

            first = EventIngestionService.ingest(
                first_agent_id,
                payload,
            )

            duplicate = EventIngestionService.ingest(
                first_agent_id,
                payload,
            )

            # The same event UID is allowed for another agent.
            second_agent_event = EventIngestionService.ingest(
                second_agent_id,
                payload,
            )

            assert first.duplicate is False
            assert duplicate.duplicate is True
            assert second_agent_event.duplicate is False

            assert first.event.id == duplicate.event.id
            assert first.event.id != second_agent_event.event.id

            assert first.event.agent_id == first_agent_id
            assert second_agent_event.event.agent_id == second_agent_id

            # The original data must be preserved after deduplication.
            assert duplicate.event.message == payload["message"]
            assert duplicate.event.severity == payload["severity"]

            # Verify JSON persistence through MariaDB.
            stored_event = db.session.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.id == first.event.id
                )
            )

            assert stored_event.event_data == payload["event_data"]

            # Exactly two records should exist, one per agent.
            assert SecurityEvent.query.filter(
                SecurityEvent.event_uid == event_uid
            ).count() == 2

        finally:
            _cleanup(agent_ids, asset_ids)


def test_mariadb_concurrent_duplicate_event_ingestion():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []

        try:
            agent_id, asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            event_uid = uuid.uuid4()
            payload = _make_event(event_uid=event_uid)

            barrier = Barrier(2)

            def ingest_concurrently():
                with app.app_context():
                    barrier.wait(timeout=15)

                    result = EventIngestionService.ingest(
                        agent_id,
                        payload,
                    )

                    return (
                        result.duplicate,
                        result.event.id,
                    )

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(ingest_concurrently)
                    for _ in range(2)
                ]

                results = [
                    future.result(timeout=30)
                    for future in futures
                ]

            duplicate_flags = sorted(
                result[0] for result in results
            )

            assert duplicate_flags == [False, True]

            # Both requests must resolve to the same database record.
            assert results[0][1] == results[1][1]

            db.session.rollback()

            assert SecurityEvent.query.filter_by(
                agent_id=agent_id,
                event_uid=event_uid,
            ).count() == 1

        finally:
            _cleanup(agent_ids, asset_ids)


def test_mariadb_ingestion_racing_with_agent_revocation():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []
        user_ids = []

        try:
            unique_id = uuid.uuid4().hex[:12]

            user = UserService.create_user(
                username=f"event_rev_{unique_id}",
                password="Integration-Test-Password-123",
                role="admin",
            )

            user_ids.append(user.id)

            agent_id, asset_id = _create_agent(unique_id)

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            event_uid = uuid.uuid4()
            payload = _make_event(event_uid=event_uid)

            barrier = Barrier(2)

            def ingest():
                with app.app_context():
                    barrier.wait(timeout=15)

                    try:
                        result = EventIngestionService.ingest(
                            agent_id,
                            payload,
                        )

                        return (
                            "accepted",
                            result.event.id,
                        )

                    except UnavailableAgentForIngestionError:
                        return ("rejected", None)

            def revoke():
                with app.app_context():
                    barrier.wait(timeout=15)

                    changed = AgentCredentialService.revoke_agent(
                        agent_id,
                        user.id,
                    )

                    return changed

            with ThreadPoolExecutor(max_workers=2) as executor:
                ingestion_future = executor.submit(ingest)
                revocation_future = executor.submit(revoke)

                ingestion_result = ingestion_future.result(timeout=30)
                revocation_result = revocation_future.result(timeout=30)

            assert revocation_result is True
            assert ingestion_result[0] in {"accepted", "rejected"}

            db.session.rollback()

            stored_agent = db.session.get(Agent, agent_id)

            assert stored_agent is not None
            assert stored_agent.status == "revoked"
            assert stored_agent.revoked_at is not None

            stored_events = SecurityEvent.query.filter_by(
                agent_id=agent_id,
                event_uid=event_uid,
            ).all()

            if ingestion_result[0] == "rejected":
                assert len(stored_events) == 0
            else:
                assert len(stored_events) == 1

                # If ingestion won the race, its commit happened
                # before the agent was revoked.
                assert (
                    stored_events[0].received_at
                    <= stored_agent.revoked_at
                )

        finally:
            _cleanup(agent_ids, asset_ids, user_ids)
