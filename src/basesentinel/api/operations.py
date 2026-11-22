import csv
import io
from datetime import datetime, timedelta
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



def _report_hours():
    try:
        hours = int(request.args.get("hours", "24"))
    except (TypeError, ValueError):
        return None
    return hours if 1 <= hours <= 720 else None


def _collect_security_report(hours: int) -> dict:
    now = utcnow_naive()
    since = now - timedelta(hours=hours)

    event_rows = db.session.execute(
        select(
            SecurityEvent.occurred_at,
            SecurityEvent.category,
            SecurityEvent.severity,
            Agent.id.label("agent_id"),
            Asset.hostname,
        )
        .join(Agent, Agent.id == SecurityEvent.agent_id)
        .join(Asset, Asset.id == Agent.asset_id)
        .where(SecurityEvent.occurred_at >= since, SecurityEvent.occurred_at <= now)
        .order_by(SecurityEvent.occurred_at.asc(), SecurityEvent.id.asc())
        .limit(50001)
    ).all()
    events_truncated = len(event_rows) > 50000
    event_rows = event_rows[:50000]

    alert_rows = db.session.execute(
        select(
            Alert.last_seen_at,
            Alert.severity,
            Alert.status,
            Alert.title,
            Agent.id.label("agent_id"),
            Asset.hostname,
        )
        .join(Agent, Agent.id == Alert.agent_id)
        .join(Asset, Asset.id == Agent.asset_id)
        .where(Alert.last_seen_at >= since, Alert.last_seen_at <= now)
        .order_by(Alert.last_seen_at.desc(), Alert.id)
        .limit(5001)
    ).all()
    alerts_truncated = len(alert_rows) > 5000
    alert_rows = alert_rows[:5000]

    severity_counts = {str(level): 0 for level in range(11)}
    category_counts = {}
    trend_counts = {}
    agent_counts = {}
    for row in event_rows:
        severity_counts[str(row.severity)] += 1
        category_counts[row.category] = category_counts.get(row.category, 0) + 1
        bucket = row.occurred_at.strftime("%Y-%m-%d %H:00") if hours <= 48 else row.occurred_at.strftime("%Y-%m-%d")
        trend_counts[bucket] = trend_counts.get(bucket, 0) + 1
        agent = agent_counts.setdefault(row.agent_id, {
            "agent_id": str(row.agent_id),
            "hostname": row.hostname,
            "event_count": 0,
            "high_severity_count": 0,
        })
        agent["event_count"] += 1
        if row.severity >= 7:
            agent["high_severity_count"] += 1

    alert_status_counts = {status: 0 for status in ("open", "acknowledged", "resolved")}
    alert_severity_counts = {str(level): 0 for level in range(11)}
    for row in alert_rows:
        if row.status in alert_status_counts:
            alert_status_counts[row.status] += 1
        alert_severity_counts[str(row.severity)] += 1

    return {
        "generated_at": _iso(now),
        "period": {"hours": hours, "from": _iso(since), "to": _iso(now)},
        "events": {
            "total": len(event_rows),
            "truncated": events_truncated,
            "by_severity": severity_counts,
            "by_category": dict(sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))),
            "trend": [{"bucket": key, "count": trend_counts[key]} for key in sorted(trend_counts)],
        },
        "alerts": {
            "total": len(alert_rows),
            "truncated": alerts_truncated,
            "by_status": alert_status_counts,
            "by_severity": alert_severity_counts,
        },
        "active_agent_count": len(agent_counts),
        "agent_activity": sorted(
            agent_counts.values(),
            key=lambda item: (-item["event_count"], item["hostname"] or ""),
        )[:20],
    }


@api.get("/reports/security/summary")
@require_user
def security_report_summary():
    hours = _report_hours()
    if hours is None:
        return jsonify({"error": {"code": "invalid_period", "message": "Hours must be an integer between 1 and 720."}}), 400
    response = jsonify(_collect_security_report(hours))
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.get("/reports/security.pdf")
@require_user
def export_security_report_pdf():
    hours = _report_hours()
    if hours is None:
        return jsonify({"error": {"code": "invalid_period", "message": "Hours must be an integer between 1 and 720."}}), 400

    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    report = _collect_security_report(hours)
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=landscape(A4),
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="BaseSentinel Security Report",
        author="BaseSentinel",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_LEFT,
        fontSize=20,
        leading=24,
        spaceAfter=5 * mm,
    ))
    styles.add(ParagraphStyle(
        name="ReportSection",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        spaceBefore=4 * mm,
        spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        name="ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
    ))

    story = [
        Paragraph("BaseSentinel Security Report", styles["ReportTitle"]),
        Paragraph(
            f"Period: {escape(report['period']['from'])} – {escape(report['period']['to'])} "
            f"({hours} hours) · Generated: {escape(report['generated_at'])}",
            styles["BodyText"],
        ),
        Spacer(1, 4 * mm),
        Paragraph("Executive summary", styles["ReportSection"]),
    ]

    summary_table = Table([
        ["Security events", "Alerts", "Open alerts", "Endpoints reporting"],
        [
            str(report["events"]["total"]),
            str(report["alerts"]["total"]),
            str(report["alerts"]["by_status"]["open"]),
            str(report["active_agent_count"]),
        ],
    ], colWidths=[55 * mm] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202a35")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#edf1f4")),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#17212b")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#9aa7b3")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c4cdd5")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([summary_table, Paragraph("Events by severity", styles["ReportSection"])])

    severity_table = Table(
        [["Severity", "Event count"]] + [
            [level, str(count)]
            for level, count in report["events"]["by_severity"].items()
        ],
        colWidths=[35 * mm, 35 * mm],
    )
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202a35")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#c4cdd5")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([severity_table, Paragraph("Event trend", styles["ReportSection"])])

    trend_data = [["UTC bucket", "Events"]] + [
        [item["bucket"], str(item["count"])]
        for item in report["events"]["trend"]
    ]
    if len(trend_data) == 1:
        trend_data.append(["No activity", "0"])
    trend_table = Table(trend_data, colWidths=[60 * mm, 35 * mm], repeatRows=1)
    trend_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202a35")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#c4cdd5")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
    ]))
    story.extend([trend_table, Paragraph("Events by category", styles["ReportSection"])])

    category_data = [["Category", "Event count"]] + [
        [Paragraph(escape(name), styles["ReportSmall"]), str(count)]
        for name, count in report["events"]["by_category"].items()
    ]
    if len(category_data) == 1:
        category_data.append(["No events", "0"])
    category_table = Table(category_data, colWidths=[60 * mm, 35 * mm])
    category_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202a35")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#c4cdd5")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 1), (1, -1), "RIGHT"),
    ]))
    story.extend([category_table, Paragraph("Endpoint activity", styles["ReportSection"])])

    agent_data = [["Hostname", "Events", "Severity 7–10"]] + [
        [
            Paragraph(escape(item["hostname"] or "Unknown"), styles["ReportSmall"]),
            str(item["event_count"]),
            str(item["high_severity_count"]),
        ]
        for item in report["agent_activity"]
    ]
    if len(agent_data) == 1:
        agent_data.append(["No activity", "0", "0"])
    agent_table = Table(agent_data, colWidths=[90 * mm, 35 * mm, 45 * mm], repeatRows=1)
    agent_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#202a35")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#c4cdd5")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
    ]))
    story.append(agent_table)

    if report["events"]["truncated"] or report["alerts"]["truncated"]:
        story.extend([
            Spacer(1, 3 * mm),
            Paragraph(
                "Note: report data was capped for performance "
                "(50,000 events and 5,000 alerts maximum).",
                styles["ReportSmall"],
            ),
        ])

    document.build(story)
    response = Response(output.getvalue(), mimetype="application/pdf")
    response.headers["Content-Disposition"] = 'attachment; filename="basesentinel-security-report.pdf"'
    response.headers["Cache-Control"] = "no-store"
    return response
