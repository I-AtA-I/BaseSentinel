
import os
import uuid
from datetime import timedelta, timezone, datetime

import pytest
from sqlalchemy import delete, inspect

from basesentinel import create_app, db
from basesentinel.config import Config
from basesentinel.models import Agent, Alert, Asset, SecurityEvent
from basesentinel.models.base import utcnow_naive
from basesentinel.services import AnalyticsService, EventIngestionService


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
        "agents",
        "assets",
        "security_events",
        "alerts",
    }

    existing_tables = set(inspect(db.engine).get_table_names())
    assert required_tables.issubset(existing_tables)


def _create_agent(unique_id):
    asset = Asset(
        display_name=f"Analytics Test {unique_id}",
        hostname=f"analytics-test-{unique_id}",
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


def _ingest(agent_id, category, event_type, severity, occurred_at):
    payload = {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "source": "MariaDB Analytics Test",
        "message": f"Analytics integration event: {event_type}",
        "event_data": {
            "integration_test": True,
        },
        "occurred_at": occurred_at,
    }

    return EventIngestionService.ingest(
        agent_id,
        payload,
    ).event


def _row_counts(rows, key):
    return {
        row[key]: row["count"]
        for row in rows
    }


def _cleanup(agent_ids, asset_ids):
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


def test_mariadb_dashboard_aggregations():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []

        try:
            # Capture baseline statistics before creating test records.
            baseline = AnalyticsService.get_overview(
                period_hours=24,
                top_agents_limit=20,
            )

            agent_id, asset_id = _create_agent(
                uuid.uuid4().hex[:12]
            )

            agent_ids.append(agent_id)
            asset_ids.append(asset_id)

            now = datetime.now(timezone.utc)
            first_time = (
                now - timedelta(minutes=2)
            ).isoformat().replace("+00:00", "Z")

            second_time = (
                now - timedelta(minutes=1)
            ).isoformat().replace("+00:00", "Z")

            _ingest(
                agent_id,
                category="network",
                event_type="connection.opened",
                severity=4,
                occurred_at=first_time,
            )

            _ingest(
                agent_id,
                category="system",
                event_type="security.critical",
                severity=10,
                occurred_at=second_time,
            )

            result = AnalyticsService.get_overview(
                period_hours=24,
                top_agents_limit=20,
            )

            # Event totals.
            assert (
                result["events"]["total"]
                == baseline["events"]["total"] + 2
            )

            baseline_categories = _row_counts(
                baseline["events"]["by_category"],
                "category",
            )

            result_categories = _row_counts(
                result["events"]["by_category"],
                "category",
            )

            assert (
                result_categories.get("network", 0)
                - baseline_categories.get("network", 0)
                == 1
            )

            assert (
                result_categories.get("system", 0)
                - baseline_categories.get("system", 0)
                == 1
            )

            baseline_severities = _row_counts(
                baseline["events"]["by_severity"],
                "severity",
            )

            result_severities = _row_counts(
                result["events"]["by_severity"],
                "severity",
            )

            assert (
                result_severities.get(4, 0)
                - baseline_severities.get(4, 0)
                == 1
            )

            assert (
                result_severities.get(10, 0)
                - baseline_severities.get(10, 0)
                == 1
            )

            # The critical event automatically creates one alert.
            assert (
                result["alerts"]["total"]
                == baseline["alerts"]["total"] + 1
            )

            baseline_statuses = _row_counts(
                baseline["alerts"]["by_status"],
                "status",
            )

            result_statuses = _row_counts(
                result["alerts"]["by_status"],
                "status",
            )

            assert (
                result_statuses.get("open", 0)
                - baseline_statuses.get("open", 0)
                == 1
            )

            # Agent inventory.
            assert (
                result["agents"]["total"]
                == baseline["agents"]["total"] + 1
            )

            assert (
                result["agents"]["active"]
                == baseline["agents"]["active"] + 1
            )

            # The newly created agent must appear in the ranking.
            top_agents = result["agents"]["top_by_event_count"]

            matching_agent = next(
                (
                    item
                    for item in top_agents
                    if item["agent_id"] == str(agent_id)
                ),
                None,
            )

            assert matching_agent is not None
            assert matching_agent["event_count"] == 2

        finally:
            _cleanup(agent_ids, asset_ids)
