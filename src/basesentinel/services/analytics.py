
from datetime import datetime, timedelta

from sqlalchemy import (
    Integer,
    case,
    cast,
    extract,
    func,
    select,
)

from basesentinel import db
from basesentinel.models import (
    Agent,
    Alert,
    Asset,
    SecurityEvent,
)
from basesentinel.models.base import utcnow_naive


class AnalyticsService:
    DEFAULT_PERIOD_HOURS = 24
    MAX_PERIOD_HOURS = 720
    DEFAULT_TOP_AGENTS = 5
    MAX_TOP_AGENTS = 20

    @classmethod
    def _validate_period(cls, period_hours):
        if (
            type(period_hours) is not int
            or not 1 <= period_hours <= cls.MAX_PERIOD_HOURS
        ):
            raise ValueError("Invalid analytics period.")

    @classmethod
    def get_overview(
        cls,
        period_hours=DEFAULT_PERIOD_HOURS,
        top_agents_limit=DEFAULT_TOP_AGENTS,
    ):
        """Return aggregated dashboard metrics."""

        cls._validate_period(period_hours)

        if (
            type(top_agents_limit) is not int
            or not 1 <= top_agents_limit <= cls.MAX_TOP_AGENTS
        ):
            raise ValueError("Invalid top agents limit.")

        now = utcnow_naive()
        period_start = now - timedelta(hours=period_hours)

        # Event totals within the selected time period.
        event_total = db.session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(
                SecurityEvent.occurred_at >= period_start,
                SecurityEvent.occurred_at <= now,
            )
        )

        events_by_category = db.session.execute(
            select(
                SecurityEvent.category,
                func.count().label("count"),
            )
            .where(
                SecurityEvent.occurred_at >= period_start,
                SecurityEvent.occurred_at <= now,
            )
            .group_by(SecurityEvent.category)
            .order_by(SecurityEvent.category)
        ).all()

        events_by_severity = db.session.execute(
            select(
                SecurityEvent.severity,
                func.count().label("count"),
            )
            .where(
                SecurityEvent.occurred_at >= period_start,
                SecurityEvent.occurred_at <= now,
            )
            .group_by(SecurityEvent.severity)
            .order_by(SecurityEvent.severity)
        ).all()

        # Alert totals based on their most recent occurrence.
        alert_total = db.session.scalar(
            select(func.count())
            .select_from(Alert)
            .where(
                Alert.last_seen_at >= period_start,
                Alert.last_seen_at <= now,
            )
        )

        alerts_by_status = db.session.execute(
            select(
                Alert.status,
                func.count().label("count"),
            )
            .where(
                Alert.last_seen_at >= period_start,
                Alert.last_seen_at <= now,
            )
            .group_by(Alert.status)
            .order_by(Alert.status)
        ).all()

        alerts_by_severity = db.session.execute(
            select(
                Alert.severity,
                func.count().label("count"),
            )
            .where(
                Alert.last_seen_at >= period_start,
                Alert.last_seen_at <= now,
            )
            .group_by(Alert.severity)
            .order_by(Alert.severity)
        ).all()

        # Agent inventory.
        total_agents = db.session.scalar(
            select(func.count()).select_from(Agent)
        )

        active_agents = db.session.scalar(
            select(func.count())
            .select_from(Agent)
            .where(
                Agent.status == "active",
                Agent.revoked_at.is_(None),
                Agent.uninstalled_at.is_(None),
            )
        )

        # Rank agents by event count within the selected time period.
        top_agents = db.session.execute(
            select(
                Agent.id,
                Asset.hostname,
                Asset.display_name,
                func.count(SecurityEvent.id).label("event_count"),
            )
            .join(Asset, Asset.id == Agent.asset_id)
            .outerjoin(
                SecurityEvent,
                (
                    (SecurityEvent.agent_id == Agent.id)
                    & (SecurityEvent.occurred_at >= period_start)
                    & (SecurityEvent.occurred_at <= now)
                ),
            )
            .group_by(
                Agent.id,
                Asset.hostname,
                Asset.display_name,
            )
            .order_by(
                func.count(SecurityEvent.id).desc(),
                Agent.id,
            )
            .limit(top_agents_limit)
        ).all()

        return {
            "generated_at": now.isoformat() + "Z",
            "period": {
                "hours": period_hours,
                "from": period_start.isoformat() + "Z",
                "to": now.isoformat() + "Z",
            },
            "events": {
                "total": event_total,
                "by_category": [
                    {
                        "category": row.category,
                        "count": row.count,
                    }
                    for row in events_by_category
                ],
                "by_severity": [
                    {
                        "severity": row.severity,
                        "count": row.count,
                    }
                    for row in events_by_severity
                ],
            },
            "alerts": {
                "total": alert_total,
                "by_status": [
                    {
                        "status": row.status,
                        "count": row.count,
                    }
                    for row in alerts_by_status
                ],
                "by_severity": [
                    {
                        "severity": row.severity,
                        "count": row.count,
                    }
                    for row in alerts_by_severity
                ],
            },
            "agents": {
                "total": total_agents,
                "active": active_agents,
                "top_by_event_count": [
                    {
                        "agent_id": str(row.id),
                        "hostname": row.hostname,
                        "display_name": row.display_name,
                        "event_count": row.event_count,
                    }
                    for row in top_agents
                ],
            },
        }

    @staticmethod
    def _bucket_parts(timestamp_column, granularity):
        """Create database-compatible SQL expressions for time buckets."""

        parts = [
            cast(extract("year", timestamp_column), Integer).label(
                "bucket_year"
            ),
            cast(extract("month", timestamp_column), Integer).label(
                "bucket_month"
            ),
            cast(extract("day", timestamp_column), Integer).label(
                "bucket_day"
            ),
        ]

        if granularity == "hour":
            parts.append(
                cast(
                    extract("hour", timestamp_column),
                    Integer,
                ).label("bucket_hour")
            )

        elif granularity == "four_hours":
            hour = extract("hour", timestamp_column)

            bucket_hour = case(
                (hour < 4, 0),
                (hour < 8, 4),
                (hour < 12, 8),
                (hour < 16, 12),
                (hour < 20, 16),
                else_=20,
            )

            parts.append(
                cast(bucket_hour, Integer).label("bucket_hour")
            )

        return parts

    @staticmethod
    def _bucket_from_row(row, granularity):
        year = int(row[0])
        month = int(row[1])
        day = int(row[2])

        if granularity == "day":
            hour = 0
        else:
            hour = int(row[3])

        return datetime(
            year,
            month,
            day,
            hour,
        )

    @staticmethod
    def _floor_bucket(value, granularity):
        if granularity == "hour":
            hour = value.hour

        elif granularity == "four_hours":
            hour = (value.hour // 4) * 4

        else:
            hour = 0

        return value.replace(
            hour=hour,
            minute=0,
            second=0,
            microsecond=0,
        )

    @classmethod
    def _aggregate_timestamp_counts(
        cls,
        timestamp_column,
        period_start,
        now,
        granularity,
    ):
        """Count records grouped by a timestamp column."""

        parts = cls._bucket_parts(
            timestamp_column,
            granularity,
        )

        rows = db.session.execute(
            select(
                *parts,
                func.count().label("count"),
            )
            .where(
                timestamp_column >= period_start,
                timestamp_column <= now,
            )
            .group_by(*parts)
        ).all()

        result = {}

        for row in rows:
            bucket = cls._bucket_from_row(
                row,
                granularity,
            )

            result[bucket] = int(row[len(parts)])

        return result

    @classmethod
    def get_timeline(cls, period_hours=DEFAULT_PERIOD_HOURS):
        """Return time-bucketed event, alert and agent activity metrics."""

        cls._validate_period(period_hours)

        if period_hours <= 48:
            granularity = "hour"
            bucket_hours = 1
            bucket_step = timedelta(hours=1)

        elif period_hours <= 168:
            granularity = "four_hours"
            bucket_hours = 4
            bucket_step = timedelta(hours=4)

        else:
            granularity = "day"
            bucket_hours = 24
            bucket_step = timedelta(days=1)

        now = utcnow_naive()
        period_start = now - timedelta(hours=period_hours)

        # Event counts and distinct reporting agents per bucket.
        event_parts = cls._bucket_parts(
            SecurityEvent.occurred_at,
            granularity,
        )

        event_rows = db.session.execute(
            select(
                *event_parts,
                func.count(SecurityEvent.id).label("event_count"),
                func.count(
                    func.distinct(SecurityEvent.agent_id)
                ).label("active_agents"),
            )
            .where(
                SecurityEvent.occurred_at >= period_start,
                SecurityEvent.occurred_at <= now,
            )
            .group_by(*event_parts)
        ).all()

        event_counts = {}
        active_agent_counts = {}

        for row in event_rows:
            bucket = cls._bucket_from_row(
                row,
                granularity,
            )

            event_counts[bucket] = int(row[len(event_parts)])
            active_agent_counts[bucket] = int(
                row[len(event_parts) + 1]
            )

        # Event severity distribution per bucket.
        severity_rows = db.session.execute(
            select(
                *event_parts,
                SecurityEvent.severity,
                func.count(SecurityEvent.id).label("count"),
            )
            .where(
                SecurityEvent.occurred_at >= period_start,
                SecurityEvent.occurred_at <= now,
            )
            .group_by(
                *event_parts,
                SecurityEvent.severity,
            )
        ).all()

        severity_counts = {}

        for row in severity_rows:
            bucket = cls._bucket_from_row(
                row,
                granularity,
            )

            severity = int(row[len(event_parts)])
            count = int(row[len(event_parts) + 1])

            severity_counts.setdefault(bucket, {})[severity] = count

        # Alert creation and resolution are measured independently.
        alerts_created = cls._aggregate_timestamp_counts(
            Alert.created_at,
            period_start,
            now,
            granularity,
        )

        alerts_resolved = cls._aggregate_timestamp_counts(
            Alert.resolved_at,
            period_start,
            now,
            granularity,
        )

        # Generate every interval, including empty ones.
        current_bucket = cls._floor_bucket(
            period_start,
            granularity,
        )

        last_bucket = cls._floor_bucket(
            now,
            granularity,
        )

        buckets = []

        while current_bucket <= last_bucket:
            bucket_severities = severity_counts.get(
                current_bucket,
                {},
            )

            buckets.append({
                "start": current_bucket.isoformat() + "Z",
                "event_count": event_counts.get(current_bucket, 0),
                "severity_counts": [
                    {
                        "severity": severity,
                        "count": bucket_severities.get(severity, 0),
                    }
                    for severity in range(11)
                ],
                "alerts_created": alerts_created.get(
                    current_bucket,
                    0,
                ),
                "alerts_resolved": alerts_resolved.get(
                    current_bucket,
                    0,
                ),
                "active_agents": active_agent_counts.get(
                    current_bucket,
                    0,
                ),
            })

            current_bucket += bucket_step

        return {
            "generated_at": now.isoformat() + "Z",
            "period": {
                "hours": period_hours,
                "from": period_start.isoformat() + "Z",
                "to": now.isoformat() + "Z",
            },
            "granularity": granularity,
            "bucket_interval_hours": bucket_hours,
            "buckets": buckets,
        }
