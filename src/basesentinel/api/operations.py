import csv
import io
from datetime import timedelta
from uuid import UUID

from flask import Response, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from basesentinel.api import api
from basesentinel.api.decorators import require_user
from basesentinel import db
from basesentinel.models import Agent, Alert, Asset, SecurityEvent
from basesentinel.models.base import utcnow_naive


AGENT_ONLINE_WINDOW = timedelta(minutes=5)
AGENT_STALE_WINDOW = timedelta(minutes=15)


def _iso(value):
    return value.isoformat() + "Z" if value is not None else None


@api.get("/operations/agents")
@require_user
def agent_health():
    """Return agent connectivity and collection health based on server check-ins."""
    now = utcnow_naive()
    agents = db.session.scalars(
        select(Agent)
        .options(selectinload(Agent.asset))
        .order_by(Agent.last_checkin_at.desc(), Agent.id)
    ).all()

    items = []
    for agent in agents:
        last_event = db.session.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.agent_id == agent.id)
            .order_by(SecurityEvent.received_at.desc(), SecurityEvent.id.desc())
            .limit(1)
        )
        age = now - agent.last_checkin_at
        if agent.status != "active" or agent.revoked_at or agent.uninstalled_at:
            health = "inactive"
        elif age <= AGENT_ONLINE_WINDOW:
            health = "online"
        elif age <= AGENT_STALE_WINDOW:
            health = "stale"
        else:
            health = "disconnected"

        asset = agent.asset
        items.append({
            "agent_id": str(agent.id),
            "hostname": asset.hostname if asset else None,
            "display_name": asset.display_name if asset else None,
            "platform": agent.platform,
            "agent_version": agent.agent_version,
            "status": agent.status,
            "health": health,
            "last_checkin_at": _iso(agent.last_checkin_at),
            "last_event_at": _iso(last_event.received_at if last_event else None),
            "last_event_type": last_event.event_type if last_event else None,
            "last_event_severity": last_event.severity if last_event else None,
        })

    response = jsonify({
        "generated_at": _iso(now),
        "thresholds": {
            "online_seconds": int(AGENT_ONLINE_WINDOW.total_seconds()),
            "stale_seconds": int(AGENT_STALE_WINDOW.total_seconds()),
        },
        "agents": items,
        "counts": {
            state: sum(1 for item in items if item["health"] == state)
            for state in ("online", "stale", "disconnected", "inactive")
        },
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.get("/operations/alerts/<alert_id>/investigation")
@require_user
def alert_investigation(alert_id):
    """Return an alert with nearby events from the same agent for investigation."""
    try:
        parsed_id = UUID(alert_id)
    except (ValueError, TypeError, AttributeError):
        return jsonify({"error": {"code": "invalid_alert_id", "message": "Invalid alert ID."}}), 400

    alert = db.session.scalar(
        select(Alert)
        .options(selectinload(Alert.agent).selectinload(Agent.asset))
        .where(Alert.id == parsed_id)
    )
    if alert is None:
        return jsonify({"error": {"code": "alert_not_found", "message": "Alert not found."}}), 404

    window_start = alert.first_seen_at - timedelta(minutes=30)
    window_end = alert.last_seen_at + timedelta(minutes=30)
    events = db.session.scalars(
        select(SecurityEvent)
        .options(selectinload(SecurityEvent.agent).selectinload(Agent.asset))
        .where(
            SecurityEvent.agent_id == alert.agent_id,
            SecurityEvent.occurred_at >= window_start,
            SecurityEvent.occurred_at <= window_end,
        )
        .order_by(SecurityEvent.occurred_at.asc(), SecurityEvent.id.asc())
        .limit(500)
    ).all()

    asset = alert.agent.asset if alert.agent else None
    response = jsonify({
        "alert": {
            "id": str(alert.id),
            "rule_key": alert.rule_key,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "status": alert.status,
            "occurrence_count": alert.occurrence_count,
            "first_seen_at": _iso(alert.first_seen_at),
            "last_seen_at": _iso(alert.last_seen_at),
            "agent_id": str(alert.agent_id),
            "hostname": asset.hostname if asset else None,
            "source_event_id": str(alert.source_event_id) if alert.source_event_id else None,
        },
        "window": {"from": _iso(window_start), "to": _iso(window_end)},
        "related_events": [{
            "id": str(event.id),
            "event_type": event.event_type,
            "category": event.category,
            "severity": event.severity,
            "source": event.source,
            "event_code": event.event_code,
            "message": event.message,
            "occurred_at": _iso(event.occurred_at),
            "event_data": event.event_data,
        } for event in events],
        "related_event_count": len(events),
        "truncated": len(events) == 500,
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.get("/reports/security.csv")
@require_user
def export_security_report_csv():
    """Export bounded event and alert activity as a CSV report."""
    try:
        hours = int(request.args.get("hours", "24"))
    except (TypeError, ValueError):
        return jsonify({"error": {"code": "invalid_period", "message": "Hours must be an integer."}}), 400
    if not 1 <= hours <= 720:
        return jsonify({"error": {"code": "invalid_period", "message": "Hours must be between 1 and 720."}}), 400

    now = utcnow_naive()
    since = now - timedelta(hours=hours)
    rows = db.session.execute(
        select(
            SecurityEvent.occurred_at,
            SecurityEvent.received_at,
            Asset.hostname,
            SecurityEvent.category,
            SecurityEvent.event_type,
            SecurityEvent.severity,
            SecurityEvent.source,
            SecurityEvent.event_code,
            SecurityEvent.message,
        )
        .join(Agent, Agent.id == SecurityEvent.agent_id)
        .join(Asset, Asset.id == Agent.asset_id)
        .where(SecurityEvent.occurred_at >= since, SecurityEvent.occurred_at <= now)
        .order_by(SecurityEvent.occurred_at.asc(), SecurityEvent.id.asc())
        .limit(50000)
    ).all()

    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow([
        "occurred_at_utc", "received_at_utc", "hostname", "category",
        "event_type", "severity", "source", "event_code", "message",
    ])
    for row in rows:
        writer.writerow([
            _iso(row.occurred_at), _iso(row.received_at), row.hostname,
            row.category, row.event_type, row.severity, row.source,
            row.event_code, row.message,
        ])

    response = Response(stream.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="basesentinel-security-report.csv"'
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Report-Period-Hours"] = str(hours)
    response.headers["X-Report-Truncated"] = "true" if len(rows) == 50000 else "false"
    return response
