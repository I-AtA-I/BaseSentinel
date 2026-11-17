
import os
import uuid

from datetime import timedelta

import pytest
from sqlalchemy import delete, inspect

from basesentinel import create_app, db
from basesentinel.config import Config
from basesentinel.models import (
    Agent,
    Alert,
    Asset,
    SecurityEvent,
    User,
    UserSession,
)
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    AlertService,
    AnalyticsService,
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
        "agents",
        "assets",
        "security_events",
        "alerts",
        "users",
        "user_sessions",
    }

    existing_tables = set(inspect(db.engine).get_table_names())
    assert required_tables.issubset(existing_tables)


def _create_agent(unique_id):
    asset = Asset(
        display_name=f"Timeline Test {unique_id}",
        hostname=f"timeline-test-{unique_id}",
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


def _ingest(agent_id, severity, occurred_at):
    payload = {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": "system",
        "event_type": "system.activity",
        "severity": severity,
        "source": "MariaDB Timeline Test",
        "message": "Timeline integration test event",
        "event_data": {
            "timeline_test": True,
        },
        "occurred_at": occurred_at,
    }

    return EventIngestionService.ingest(
        agent_id,
        payload,
    ).event


def _cleanup(agent_ids, asset_ids, alert_ids, user_ids):
    db.session.rollback()

    if alert_ids:
        db.session.execute(
            delete(Alert).where(
                Alert.id.in_(alert_ids)
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
            delete(UserSession).where(
                UserSession.user_id.in_(user_ids)
            )
        )

        db.session.execute(
            delete(User).where(
                User.id.in_(user_ids)
            )
        )

    db.session.commit()


def _floor_hour(value):
    return value.replace(
        minute=0,
        second=0,
        microsecond=0,
    )


def _find_bucket(buckets, timestamp):
    expected = _floor_hour(timestamp).isoformat()

    return next(
        bucket
        for bucket in buckets
        if bucket["start"].startswith(expected)
    )


def _severity_totals(buckets):
    return {
        severity: sum(
            item["count"]
            for bucket in buckets
            for item in bucket["severity_counts"]
            if item["severity"] == severity
        )
        for severity in range(11)
    }


def test_mariadb_timeline_hourly_aggregation():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        agent_ids = []
        asset_ids = []
        alert_ids = []
        user_ids = []

        try:
            baseline = AnalyticsService.get_timeline(
                period_hours=24,
            )

            suffix = uuid.uuid4().hex[:12]

            user = UserService.create_user(
                username=f"timeline_test_{suffix}",
                password="test-password-123",
                role="analyst",
            )
            user_ids.append(user.id)

            first_agent_id, first_asset_id = _create_agent(
                f"one-{suffix}"
            )

            second_agent_id, second_asset_id = _create_agent(
                f"two-{suffix}"
            )

            agent_ids.extend([
                first_agent_id,
                second_agent_id,
            ])

            asset_ids.extend([
                first_asset_id,
                second_asset_id,
            ])

            base = utcnow_naive().replace(
                second=0,
                microsecond=0,
            )

            old_time_one = base - timedelta(
                hours=2,
                minutes=10,
            )

            old_time_two = base - timedelta(
                hours=2,
                minutes=5,
            )

            recent_time = base - timedelta(
                minutes=10,
            )

            _ingest(
                first_agent_id,
                3,
                old_time_one.isoformat() + "Z",
            )

            _ingest(
                first_agent_id,
                4,
                old_time_two.isoformat() + "Z",
            )

            recent_event = _ingest(
                second_agent_id,
                9,
                recent_time.isoformat() + "Z",
            )

            alert = Alert.query.filter_by(
                source_event_id=recent_event.id,
            ).one()

            alert_ids.append(alert.id)

            AlertService.resolve(
                alert.id,
                user.id,
            )

            result = AnalyticsService.get_timeline(
                period_hours=24,
            )

            assert result["granularity"] == "hour"
            assert result["bucket_interval_hours"] == 1

            baseline_buckets = {
                bucket["start"]: bucket
                for bucket in baseline["buckets"]
            }

            result_buckets = {
                bucket["start"]: bucket
                for bucket in result["buckets"]
            }

            assert set(baseline_buckets) == set(result_buckets)

            baseline_event_total = sum(
                bucket["event_count"]
                for bucket in baseline["buckets"]
            )

            result_event_total = sum(
                bucket["event_count"]
                for bucket in result["buckets"]
            )

            assert result_event_total - baseline_event_total == 3

            baseline_severities = _severity_totals(
                baseline["buckets"],
            )

            result_severities = _severity_totals(
                result["buckets"],
            )

            assert (
                result_severities[3] - baseline_severities[3]
                == 1
            )

            assert (
                result_severities[4] - baseline_severities[4]
                == 1
            )

            assert (
                result_severities[9] - baseline_severities[9]
                == 1
            )

            old_bucket = _find_bucket(
                result["buckets"],
                old_time_one,
            )

            recent_bucket = _find_bucket(
                result["buckets"],
                recent_time,
            )

            old_key = old_bucket["start"]
            recent_key = recent_bucket["start"]

            assert (
                old_bucket["event_count"]
                - baseline_buckets[old_key]["event_count"]
                == 2
            )

            assert (
                recent_bucket["event_count"]
                - baseline_buckets[recent_key]["event_count"]
                == 1
            )

            assert (
                old_bucket["active_agents"]
                - baseline_buckets[old_key]["active_agents"]
                == 1
            )

            assert (
                recent_bucket["active_agents"]
                - baseline_buckets[recent_key]["active_agents"]
                == 1
            )

            intermediate_time = old_time_one + timedelta(
                hours=1,
            )

            intermediate_bucket = _find_bucket(
                result["buckets"],
                intermediate_time,
            )

            intermediate_key = intermediate_bucket["start"]

            assert (
                intermediate_bucket["event_count"]
                - baseline_buckets[intermediate_key]["event_count"]
                == 0
            )

            assert (
                intermediate_bucket["active_agents"]
                - baseline_buckets[intermediate_key]["active_agents"]
                == 0
            )

            baseline_alerts_created = sum(
                bucket["alerts_created"]
                for bucket in baseline["buckets"]
            )

            result_alerts_created = sum(
                bucket["alerts_created"]
                for bucket in result["buckets"]
            )

            baseline_alerts_resolved = sum(
                bucket["alerts_resolved"]
                for bucket in baseline["buckets"]
            )

            result_alerts_resolved = sum(
                bucket["alerts_resolved"]
                for bucket in result["buckets"]
            )

            assert (
                result_alerts_created - baseline_alerts_created
                == 1
            )

            assert (
                result_alerts_resolved - baseline_alerts_resolved
                == 1
            )

        finally:
            _cleanup(
                agent_ids,
                asset_ids,
                alert_ids,
                user_ids,
            )


@pytest.mark.parametrize(
    (
        "period_hours",
        "expected_granularity",
        "expected_interval",
    ),
    [
        (24, "hour", 1),
        (120, "four_hours", 4),
        (720, "day", 24),
    ],
)
def test_mariadb_timeline_selects_granularity(
    period_hours,
    expected_granularity,
    expected_interval,
):
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        _assert_database()

        result = AnalyticsService.get_timeline(
            period_hours=period_hours,
        )

        assert result["granularity"] == expected_granularity
        assert result["bucket_interval_hours"] == expected_interval
        assert result["period"]["hours"] == period_hours
        assert result["buckets"]
