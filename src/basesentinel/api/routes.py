from datetime import datetime, timedelta, timezone
from basesentinel.services.analytics import AnalyticsService
from basesentinel.models import Alert

from basesentinel.services.alerts import (
    AlertService,
    AlertNotFoundError,
    AlertTransitionConflictError,
)

from basesentinel.models import SecurityEvent
from uuid import UUID

from flask import g, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from basesentinel import db
from basesentinel.api import api
from basesentinel.api.decorators import require_agent, require_user
from basesentinel.api.permissions import require_role
from basesentinel.models import Agent, AgentCredential, AgentInvitation
from basesentinel.services.credentials import (
    AgentCredentialService,
    AgentUnavailableError,
)
from basesentinel.services.sessions import UserSessionService
from basesentinel.services.users import UserService
from basesentinel.services.pairings import PairingService
from basesentinel.services.server_enrollment import ServerEnrollmentService, ServerAccessError
from basesentinel.services.agent_invitations import AgentInvitationService, InvalidInvitationError
from basesentinel.services.enrollment import (EnrollmentService, InvalidPairingCodeError, AssetAlreadyEnrolledError, EnrollmentError)
from werkzeug.exceptions import RequestEntityTooLarge

MAX_EVENT_REQUEST_BYTES = 32 * 1024


from basesentinel.services.events import (
    EventIngestionService,
    InvalidEventPayloadError,
    UnavailableAgentForIngestionError,
)


def _parse_event_datetime(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Invalid timestamp.")

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        raise ValueError("Invalid timestamp.") from None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timestamp must include a timezone.")

    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _event_summary_payload(event):
    return {
        "id": str(event.id),
        "agent_id": str(event.agent_id),
        "event_uid": str(event.event_uid),
        "category": event.category,
        "event_type": event.event_type,
        "severity": event.severity,
        "source": event.source,
        "event_code": event.event_code,
        "message": event.message,
        "occurred_at": _serialize_datetime(event.occurred_at),
        "received_at": _serialize_datetime(event.received_at),
    }


def _event_detail_payload(event):
    return {
        **_event_summary_payload(event),
        "schema_version": event.schema_version,
        "event_data": event.event_data,
    }


def _error_response(code, message, status):
    response = jsonify({
        "error": {
            "code": code,
            "message": message,
        }
    })
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def _invalid_request_response():
    return _error_response(
        "invalid_request",
        "A valid JSON object is required.",
        400,
    )


def _parse_uuid(value):
    try:
        return UUID(value)
    except (ValueError, TypeError, AttributeError):
        return None


def _parse_pagination():
    try:
        limit = int(request.args.get("limit", "50"))
        offset = int(request.args.get("offset", "0"))
    except ValueError:
        return None

    if not 1 <= limit <= 100 or offset < 0:
        return None

    return limit, offset


def _serialize_datetime(value):
    if value is None:
        return None

    return value.isoformat() + "Z"


def _agent_payload(agent):
    asset = agent.asset

    return {
        "id": str(agent.id),
        "asset": {
            "id": str(asset.id),
            "display_name": asset.display_name,
            "hostname": asset.hostname,
            "asset_type": asset.asset_type,
        },
        "platform": agent.platform,
        "platform_version": agent.platform_version,
        "architecture": agent.architecture,
        "agent_version": agent.agent_version,
        "status": agent.status,
        "enrolled_at": _serialize_datetime(agent.enrolled_at),
        "last_checkin_at": _serialize_datetime(agent.last_checkin_at),
        "revoked_at": _serialize_datetime(agent.revoked_at),
        "uninstalled_at": _serialize_datetime(agent.uninstalled_at),
        "created_at": _serialize_datetime(agent.created_at),
        "updated_at": _serialize_datetime(agent.updated_at),
    }


def _credential_payload(credential):
    return {
        "id": str(credential.id),
        "agent_id": str(credential.agent_id),
        "created_at": _serialize_datetime(credential.created_at),
        "expires_at": _serialize_datetime(credential.expires_at),
        "revoked_at": _serialize_datetime(credential.revoked_at),
        "last_used_at": _serialize_datetime(credential.last_used_at),
    }


@api.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "basesentinel-core",
        "version": "0.1.0",
    }), 200


# ---------------------------------------------------------------------
# Agent authentication
# ---------------------------------------------------------------------

@api.get("/agents/me")
@require_agent
def agent_identity():
    agent = g.current_agent

    response = jsonify({
        "agent_id": str(agent.id),
        "asset_id": str(agent.asset_id),
        "platform": agent.platform,
        "agent_version": agent.agent_version,
        "status": agent.status,
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


# ---------------------------------------------------------------------
# User authentication
# ---------------------------------------------------------------------

@api.post("/auth/login")
def user_login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return _invalid_request_response()

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return _invalid_request_response()

    user = UserService.authenticate(username, password)

    if user is None:
        return _error_response(
            "invalid_credentials",
            "Invalid username or password.",
            401,
        ), {"WWW-Authenticate": "Bearer"}

    token, session = UserSessionService.create_session(user.id)

    response = jsonify({
        "token": token,
        "token_type": "Bearer",
        "expires_at": _serialize_datetime(session.expires_at),
        "user": {
            "id": str(user.id),
            "username": user.username,
            "role": user.role,
        },
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.post("/auth/logout")
@require_user
def user_logout():
    token = request.headers["Authorization"].split()[1]

    UserSessionService.revoke_session(token)

    response = jsonify({
        "status": "ok",
        "message": "Session revoked.",
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.get("/auth/me")
@require_user
def user_identity():
    user = g.current_user

    response = jsonify({
        "user_id": str(user.id),
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


# ---------------------------------------------------------------------
# Agent inventory
# ---------------------------------------------------------------------

@api.get("/agents")
@require_user
def list_agents():
    pagination = _parse_pagination()

    if pagination is None:
        return _error_response(
            "invalid_pagination",
            "Limit must be between 1 and 100 and offset cannot be negative.",
            400,
        )

    limit, offset = pagination

    total = db.session.scalar(
        select(func.count()).select_from(Agent)
    )

    agents = db.session.scalars(
        select(Agent)
        .options(selectinload(Agent.asset))
        .order_by(Agent.created_at.desc(), Agent.id)
        .limit(limit)
        .offset(offset)
    ).all()

    response = jsonify({
        "items": [_agent_payload(agent) for agent in agents],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.get("/agents/<agent_id>")
@require_user
def get_agent(agent_id):
    parsed_id = _parse_uuid(agent_id)

    if parsed_id is None:
        return _error_response(
            "invalid_agent_id",
            "Invalid agent ID.",
            400,
        )

    agent = db.session.scalar(
        select(Agent)
        .options(selectinload(Agent.asset))
        .where(Agent.id == parsed_id)
    )

    if agent is None:
        return _error_response(
            "agent_not_found",
            "Agent not found.",
            404,
        )

    response = jsonify(_agent_payload(agent))
    response.headers["Cache-Control"] = "no-store"

    return response, 200


# ---------------------------------------------------------------------
# Agent enrollment
# ---------------------------------------------------------------------

@api.post("/pairing-codes")
@require_user
@require_role("admin")
def create_pairing_code():
    data = request.get_json(silent=True) if request.data else {}
    if not isinstance(data, dict):
        return _invalid_request_response()

    ttl_minutes = data.get("ttl_minutes", 10)
    target_asset_id = data.get("target_asset_id")
    if type(ttl_minutes) is not int or not 1 <= ttl_minutes <= 30:
        return _error_response("invalid_pairing_code_lifetime", "Pairing code lifetime must be between 1 and 30 minutes.", 400)
    if target_asset_id is not None:
        target_asset_id = _parse_uuid(target_asset_id)
        if target_asset_id is None:
            return _error_response("invalid_asset_id", "Invalid target asset ID.", 400)
    try:
        record, code = PairingService.create_code(g.current_user.id, target_asset_id, timedelta(minutes=ttl_minutes))
    except ValueError as exc:
        return _error_response("invalid_pairing_code_request", str(exc), 400)
    except PermissionError:
        return _error_response("forbidden", "Administrator access is required.", 403)
    response = jsonify({
        "id": str(record.id),
        "code": code,
        "created_at": _serialize_datetime(record.created_at),
        "expires_at": _serialize_datetime(record.expires_at),
        "target_asset_id": str(record.target_asset_id) if record.target_asset_id else None,
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 201


@api.post("/agents/enroll")
def enroll_agent():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _invalid_request_response()
    allowed = {"pairing_code", "hostname", "platform", "agent_version", "platform_version", "architecture"}
    if set(data) - allowed:
        return _error_response("invalid_enrollment_request", "Enrollment request contains unsupported fields.", 400)
    try:
        result = EnrollmentService.enroll(
            pairing_code=data.get("pairing_code"),
            hostname=data.get("hostname"),
            platform=data.get("platform"),
            agent_version=data.get("agent_version"),
            platform_version=data.get("platform_version"),
            architecture=data.get("architecture"),
        )
    except InvalidPairingCodeError:
        return _error_response("invalid_pairing_code", "Pairing code is invalid or unavailable.", 401)
    except AssetAlreadyEnrolledError:
        return _error_response("asset_already_enrolled", "Target asset already has an active agent.", 409)
    except EnrollmentError as exc:
        return _error_response("enrollment_unavailable", str(exc), 409)
    except ValueError as exc:
        return _error_response("invalid_enrollment_request", str(exc), 400)
    except RuntimeError:
        return _error_response("enrollment_not_configured", "Agent enrollment is not configured.", 503)
    response = jsonify({
        "agent_id": str(result.agent.id),
        "asset_id": str(result.asset.id),
        "token": result.token,
        "token_type": "Bearer",
        "expires_at": _serialize_datetime(result.credential.expires_at),
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 201

# ---------------------------------------------------------------------
# Agent administration
# ---------------------------------------------------------------------

@api.post("/agents/<agent_id>/revoke")
@require_user
@require_role("admin")
def revoke_agent(agent_id):
    parsed_id = _parse_uuid(agent_id)

    if parsed_id is None:
        return _error_response(
            "invalid_agent_id",
            "Invalid agent ID.",
            400,
        )

    agent = db.session.get(Agent, parsed_id)

    if agent is None:
        return _error_response(
            "agent_not_found",
            "Agent not found.",
            404,
        )

    try:
        changed = AgentCredentialService.revoke_agent(
            parsed_id,
            g.current_user.id,
        )
    except PermissionError:
        return _error_response(
            "forbidden",
            "Administrator access is required.",
            403,
        )

    return jsonify({
        "agent_id": str(parsed_id),
        "status": "revoked",
        "changed": changed,
    }), 200


@api.get("/agents/<agent_id>/credentials")
@require_user
@require_role("admin")
def list_agent_credentials(agent_id):
    parsed_id = _parse_uuid(agent_id)

    if parsed_id is None:
        return _error_response(
            "invalid_agent_id",
            "Invalid agent ID.",
            400,
        )

    agent = db.session.get(Agent, parsed_id)

    if agent is None:
        return _error_response(
            "agent_not_found",
            "Agent not found.",
            404,
        )

    pagination = _parse_pagination()

    if pagination is None:
        return _error_response(
            "invalid_pagination",
            "Limit must be between 1 and 100 and offset cannot be negative.",
            400,
        )

    limit, offset = pagination

    total = db.session.scalar(
        select(func.count())
        .select_from(AgentCredential)
        .where(AgentCredential.agent_id == parsed_id)
    )

    credentials = db.session.scalars(
        select(AgentCredential)
        .where(AgentCredential.agent_id == parsed_id)
        .order_by(AgentCredential.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    response = jsonify({
        "items": [
            _credential_payload(credential)
            for credential in credentials
        ],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.post("/agents/<agent_id>/credentials/rotate")
@require_user
@require_role("admin")
def rotate_agent_credentials(agent_id):
    parsed_id = _parse_uuid(agent_id)

    if parsed_id is None:
        return _error_response(
            "invalid_agent_id",
            "Invalid agent ID.",
            400,
        )

    if request.data:
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return _invalid_request_response()
    else:
        data = {}

    ttl_days = data.get("ttl_days", 90)

    if type(ttl_days) is not int or not 1 <= ttl_days <= 365:
        return _error_response(
            "invalid_credential_lifetime",
            "Credential lifetime must be between 1 and 365 days.",
            400,
        )

    from datetime import timedelta

    try:
        result = AgentCredentialService.rotate_agent_credential(
            parsed_id,
            g.current_user.id,
            ttl=timedelta(days=ttl_days),
        )
    except AgentUnavailableError:
        return _error_response(
            "agent_unavailable",
            "Agent is not active.",
            409,
        )
    except PermissionError:
        return _error_response(
            "forbidden",
            "Administrator access is required.",
            403,
        )

    if result is None:
        return _error_response(
            "agent_not_found",
            "Agent not found.",
            404,
        )

    response = jsonify({
        "agent_id": str(parsed_id),
        "credential": {
            "id": str(result.credential.id),
            "created_at": _serialize_datetime(
                result.credential.created_at
            ),
            "expires_at": _serialize_datetime(
                result.credential.expires_at
            ),
        },
        "token": result.token,
        "token_type": "Bearer",
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.post("/events")
@require_agent
def ingest_event():
    # Enforce a maximum request size before parsing JSON.
    request.max_content_length = MAX_EVENT_REQUEST_BYTES

    if (
        request.content_length is not None
        and request.content_length > MAX_EVENT_REQUEST_BYTES
    ):
        return _error_response(
            "payload_too_large",
            "Event payload exceeds the maximum request size.",
            413,
        )

    try:
        payload = request.get_json(silent=True)
    except RequestEntityTooLarge:
        return _error_response(
            "payload_too_large",
            "Event payload exceeds the maximum request size.",
            413,
        )

    if not isinstance(payload, dict):
        return _error_response(
            "invalid_request",
            "A valid JSON object is required.",
            400,
        )

    try:
        result = EventIngestionService.ingest(
            g.current_agent.id,
            payload,
        )

    except InvalidEventPayloadError as exc:
        return _error_response(
            "invalid_event",
            str(exc),
            400,
        )

    except UnavailableAgentForIngestionError:
        return _error_response(
            "agent_unavailable",
            "Agent is not available for event ingestion.",
            409,
        )

    event = result.event

    response = jsonify({
        "event_id": str(event.id),
        "event_uid": str(event.event_uid),
        "received_at": _serialize_datetime(event.received_at),
        "duplicate": result.duplicate,
    })

    response.headers["Cache-Control"] = "no-store"

    return response, 200 if result.duplicate else 201


@api.get("/events")
@require_user
def list_security_events():
    from sqlalchemy import select

    pagination = _parse_pagination()

    if pagination is None:
        return _error_response(
            "invalid_pagination",
            "Limit must be between 1 and 100 and offset cannot be negative.",
            400,
        )

    limit, offset = pagination
    conditions = []

    agent_id = request.args.get("agent_id")

    if agent_id is not None:
        parsed_agent_id = _parse_uuid(agent_id)

        if parsed_agent_id is None:
            return _error_response(
                "invalid_agent_id",
                "Invalid agent ID.",
                400,
            )

        conditions.append(
            SecurityEvent.agent_id == parsed_agent_id
        )

    category = request.args.get("category")

    if category is not None:
        category = category.strip().lower()

        if (
            not category
            or len(category) > 32
            or category not in EventIngestionService.ALLOWED_CATEGORIES
        ):
            return _error_response(
                "invalid_category",
                "Invalid event category.",
                400,
            )

        conditions.append(SecurityEvent.category == category)

    event_type = request.args.get("event_type")

    if event_type is not None:
        event_type = event_type.strip().lower()

        import re

        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", event_type):
            return _error_response(
                "invalid_event_type",
                "Invalid event type.",
                400,
            )

        conditions.append(SecurityEvent.event_type == event_type)

    severity_min = request.args.get("severity_min")
    severity_max = request.args.get("severity_max")

    try:
        if severity_min is not None:
            severity_min = int(severity_min)

            if not 0 <= severity_min <= 10:
                raise ValueError

        if severity_max is not None:
            severity_max = int(severity_max)

            if not 0 <= severity_max <= 10:
                raise ValueError

    except ValueError:
        return _error_response(
            "invalid_severity",
            "Severity filters must be integers between 0 and 10.",
            400,
        )

    if (
        severity_min is not None
        and severity_max is not None
        and severity_min > severity_max
    ):
        return _error_response(
            "invalid_severity_range",
            "Minimum severity cannot exceed maximum severity.",
            400,
        )

    if severity_min is not None:
        conditions.append(
            SecurityEvent.severity >= severity_min
        )

    if severity_max is not None:
        conditions.append(
            SecurityEvent.severity <= severity_max
        )

    start_time = request.args.get("from")
    end_time = request.args.get("to")

    try:
        if start_time is not None:
            start_time = _parse_event_datetime(start_time)
            conditions.append(
                SecurityEvent.occurred_at >= start_time
            )

        if end_time is not None:
            end_time = _parse_event_datetime(end_time)
            conditions.append(
                SecurityEvent.occurred_at <= end_time
            )

    except ValueError:
        return _error_response(
            "invalid_time_range",
            "Timestamps must be valid ISO 8601 values with a timezone.",
            400,
        )

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        return _error_response(
            "invalid_time_range",
            "Start time cannot be later than end time.",
            400,
        )

    total = db.session.scalar(
        select(func.count())
        .select_from(SecurityEvent)
        .where(*conditions)
    )

    events = db.session.scalars(
        select(SecurityEvent)
        .where(*conditions)
        .order_by(
            SecurityEvent.occurred_at.desc(),
            SecurityEvent.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    ).all()

    response = jsonify({
        "items": [
            _event_summary_payload(event)
            for event in events
        ],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    })

    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.get("/events/<event_id>")
@require_user
def get_security_event(event_id):
    parsed_id = _parse_uuid(event_id)

    if parsed_id is None:
        return _error_response(
            "invalid_event_id",
            "Invalid event ID.",
            400,
        )

    event = db.session.get(SecurityEvent, parsed_id)

    if event is None:
        return _error_response(
            "event_not_found",
            "Event not found.",
            404,
        )

    response = jsonify(_event_detail_payload(event))
    response.headers["Cache-Control"] = "no-store"

    return response, 200


def _alert_payload(alert):
    return {
        "id": str(alert.id),
        "rule_key": alert.rule_key,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "agent_id": str(alert.agent_id),
        "source_event_id": str(alert.source_event_id),
        "occurrence_count": alert.occurrence_count,
        "first_seen_at": _serialize_datetime(alert.first_seen_at),
        "last_seen_at": _serialize_datetime(alert.last_seen_at),
        "acknowledged_by_user_id": (
            str(alert.acknowledged_by_user_id)
            if alert.acknowledged_by_user_id is not None
            else None
        ),
        "acknowledged_at": _serialize_datetime(alert.acknowledged_at),
        "resolved_at": _serialize_datetime(alert.resolved_at),
        "created_at": _serialize_datetime(alert.created_at),
        "updated_at": _serialize_datetime(alert.updated_at),
    }


@api.get("/alerts")
@require_user
def list_alerts():
    import re

    pagination = _parse_pagination()

    if pagination is None:
        return _error_response(
            "invalid_pagination",
            "Limit must be between 1 and 100 and offset cannot be negative.",
            400,
        )

    limit, offset = pagination
    conditions = []

    status = request.args.get("status")

    if status is not None:
        if status not in {"open", "acknowledged", "resolved"}:
            return _error_response(
                "invalid_status",
                "Invalid alert status.",
                400,
            )

        conditions.append(Alert.status == status)

    agent_id = request.args.get("agent_id")

    if agent_id is not None:
        parsed_agent_id = _parse_uuid(agent_id)

        if parsed_agent_id is None:
            return _error_response(
                "invalid_agent_id",
                "Invalid agent ID.",
                400,
            )

        conditions.append(Alert.agent_id == parsed_agent_id)

    rule_key = request.args.get("rule_key")

    if rule_key is not None:
        rule_key = rule_key.strip()

        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", rule_key):
            return _error_response(
                "invalid_rule_key",
                "Invalid detection rule key.",
                400,
            )

        conditions.append(Alert.rule_key == rule_key)

    severity_min = request.args.get("severity_min")
    severity_max = request.args.get("severity_max")

    try:
        if severity_min is not None:
            severity_min = int(severity_min)

            if not 0 <= severity_min <= 10:
                raise ValueError

        if severity_max is not None:
            severity_max = int(severity_max)

            if not 0 <= severity_max <= 10:
                raise ValueError

    except ValueError:
        return _error_response(
            "invalid_severity",
            "Severity filters must be integers between 0 and 10.",
            400,
        )

    if (
        severity_min is not None
        and severity_max is not None
        and severity_min > severity_max
    ):
        return _error_response(
            "invalid_severity_range",
            "Minimum severity cannot exceed maximum severity.",
            400,
        )

    if severity_min is not None:
        conditions.append(Alert.severity >= severity_min)

    if severity_max is not None:
        conditions.append(Alert.severity <= severity_max)

    start_time = request.args.get("from")
    end_time = request.args.get("to")

    try:
        if start_time is not None:
            start_time = _parse_event_datetime(start_time)
            conditions.append(Alert.last_seen_at >= start_time)

        if end_time is not None:
            end_time = _parse_event_datetime(end_time)
            conditions.append(Alert.last_seen_at <= end_time)

    except ValueError:
        return _error_response(
            "invalid_time_range",
            "Timestamps must be valid ISO 8601 values with a timezone.",
            400,
        )

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        return _error_response(
            "invalid_time_range",
            "Start time cannot be later than end time.",
            400,
        )

    total = db.session.scalar(
        select(func.count())
        .select_from(Alert)
        .where(*conditions)
    )

    alerts = db.session.scalars(
        select(Alert)
        .where(*conditions)
        .order_by(
            Alert.last_seen_at.desc(),
            Alert.id.desc(),
        )
        .limit(limit)
        .offset(offset)
    ).all()

    response = jsonify({
        "items": [_alert_payload(alert) for alert in alerts],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "total": total,
        },
    })

    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.get("/alerts/<alert_id>")
@require_user
def get_alert(alert_id):
    parsed_id = _parse_uuid(alert_id)

    if parsed_id is None:
        return _error_response(
            "invalid_alert_id",
            "Invalid alert ID.",
            400,
        )

    alert = db.session.get(Alert, parsed_id)

    if alert is None:
        return _error_response(
            "alert_not_found",
            "Alert not found.",
            404,
        )

    response = jsonify(_alert_payload(alert))
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.post("/alerts/<alert_id>/acknowledge")
@require_user
@require_role("admin", "analyst")
def acknowledge_alert(alert_id):
    parsed_id = _parse_uuid(alert_id)

    if parsed_id is None:
        return _error_response(
            "invalid_alert_id",
            "Invalid alert ID.",
            400,
        )

    try:
        result = AlertService.acknowledge(
            parsed_id,
            g.current_user.id,
        )

    except AlertNotFoundError:
        return _error_response(
            "alert_not_found",
            "Alert not found.",
            404,
        )

    except AlertTransitionConflictError as exc:
        return _error_response(
            "invalid_alert_transition",
            str(exc),
            409,
        )

    except PermissionError:
        return _error_response(
            "forbidden",
            "Administrator or analyst access is required.",
            403,
        )

    response = jsonify({
        "alert": _alert_payload(result.alert),
        "changed": result.changed,
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.post("/alerts/<alert_id>/resolve")
@require_user
@require_role("admin", "analyst")
def resolve_alert(alert_id):
    parsed_id = _parse_uuid(alert_id)

    if parsed_id is None:
        return _error_response(
            "invalid_alert_id",
            "Invalid alert ID.",
            400,
        )

    try:
        result = AlertService.resolve(
            parsed_id,
            g.current_user.id,
        )

    except AlertNotFoundError:
        return _error_response(
            "alert_not_found",
            "Alert not found.",
            404,
        )

    except PermissionError:
        return _error_response(
            "forbidden",
            "Administrator or analyst access is required.",
            403,
        )

    response = jsonify({
        "alert": _alert_payload(result.alert),
        "changed": result.changed,
    })
    response.headers["Cache-Control"] = "no-store"

    return response, 200

@api.get("/dashboard/overview")
@require_user
def dashboard_overview():
    try:
        period_hours = int(
            request.args.get(
                "period_hours",
                str(AnalyticsService.DEFAULT_PERIOD_HOURS),
            )
        )

        top_agents_limit = int(
            request.args.get(
                "top_agents_limit",
                str(AnalyticsService.DEFAULT_TOP_AGENTS),
            )
        )

        result = AnalyticsService.get_overview(
            period_hours=period_hours,
            top_agents_limit=top_agents_limit,
        )

    except ValueError:
        return _error_response(
            "invalid_analytics_parameters",
            "Invalid dashboard analytics parameters.",
            400,
        )

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"

    return response, 200


@api.get("/dashboard/timeline")
@require_user
def dashboard_timeline():
    try:
        period_hours = int(
            request.args.get(
                "period_hours",
                str(AnalyticsService.DEFAULT_PERIOD_HOURS),
            )
        )

        result = AnalyticsService.get_timeline(
            period_hours=period_hours,
        )

    except ValueError:
        return _error_response(
            "invalid_analytics_parameters",
            "Invalid dashboard timeline parameters.",
            400,
        )

    response = jsonify(result)
    response.headers["Cache-Control"] = "no-store"

    return response, 200


# ---------------------------------------------------------------------
# Persistent server enrollment access
# ---------------------------------------------------------------------

@api.get("/server/enrollment")
@require_user
@require_role("admin")
def get_server_enrollment_settings():
    settings, initial_secret = ServerEnrollmentService.get_or_create_settings()
    response = jsonify({
        "server_id": settings.server_id,
        "enrollment_mode": settings.enrollment_mode,
        "connection_password_required": settings.connection_password_hash is not None,
        "initial_server_secret": initial_secret,
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.put("/server/enrollment")
@require_user
@require_role("admin")
def update_server_enrollment_settings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - {"enrollment_mode", "connection_password"}:
        return _invalid_request_response()
    mode = data.get("enrollment_mode", "automatic")
    password = data.get("connection_password")
    try:
        settings = ServerEnrollmentService.update_settings(mode, password)
    except ValueError as exc:
        return _error_response("invalid_server_settings", str(exc), 400)
    response = jsonify({
        "server_id": settings.server_id,
        "enrollment_mode": settings.enrollment_mode,
        "connection_password_required": settings.connection_password_hash is not None,
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.post("/server/enrollment/rotate-secret")
@require_user
@require_role("admin")
def rotate_server_enrollment_secret():
    settings, secret = ServerEnrollmentService.rotate_secret()
    response = jsonify({"server_id": settings.server_id, "server_secret": secret})
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.post("/agents/enroll-server")
def enroll_agent_with_server_access():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _invalid_request_response()
    allowed = {
        "server_id", "server_secret", "connection_password", "hostname",
        "platform", "agent_version", "platform_version", "architecture",
    }
    if set(data) - allowed:
        return _error_response("invalid_enrollment_request", "Enrollment request contains unsupported fields.", 400)
    try:
        result = ServerEnrollmentService.enroll(
            server_id=data.get("server_id"),
            server_secret=data.get("server_secret"),
            connection_password=data.get("connection_password"),
            hostname=data.get("hostname"),
            platform=data.get("platform"),
            agent_version=data.get("agent_version"),
            platform_version=data.get("platform_version"),
            architecture=data.get("architecture"),
        )
    except ServerAccessError:
        return _error_response("invalid_server_access", "Server access details are invalid or enrollment is disabled.", 401)
    except AssetAlreadyEnrolledError:
        return _error_response("asset_already_enrolled", "Target asset already has an active agent.", 409)
    except EnrollmentError as exc:
        return _error_response("enrollment_unavailable", str(exc), 409)
    except ValueError as exc:
        return _error_response("invalid_enrollment_request", str(exc), 400)
    except RuntimeError:
        return _error_response("enrollment_not_configured", "Server enrollment is not configured.", 503)
    response = jsonify({
        "agent_id": str(result.agent.id),
        "asset_id": str(result.asset.id),
        "token": result.token,
        "token_type": "Bearer",
        "expires_at": _serialize_datetime(result.credential.expires_at),
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 201


# ---------------------------------------------------------------------
# Temporary agent invitations
# ---------------------------------------------------------------------

@api.get("/server/enrollment/invitations")
@require_user
@require_role("admin")
def list_agent_invitations():
    now = datetime.utcnow()
    records = AgentInvitationService.list_recent()
    response = jsonify({
        "items": [{
            "id": str(item.id),
            "created_at": _serialize_datetime(item.created_at),
            "expires_at": _serialize_datetime(item.expires_at),
            "consumed_at": _serialize_datetime(item.consumed_at),
            "revoked_at": _serialize_datetime(item.revoked_at),
            "status": (
                "used" if item.consumed_at is not None
                else "revoked" if item.revoked_at is not None
                else "expired" if item.expires_at <= now
                else "active"
            ),
        } for item in records],
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.post("/server/enrollment/invitations")
@require_user
@require_role("admin")
def create_agent_invitation():
    data = request.get_json(silent=True) if request.data else {}
    if not isinstance(data, dict) or set(data) - {"ttl_minutes"}:
        return _invalid_request_response()
    ttl_minutes = data.get("ttl_minutes", 60)
    if type(ttl_minutes) is not int or not 5 <= ttl_minutes <= 1440:
        return _error_response(
            "invalid_invitation_lifetime",
            "Invitation lifetime must be between 5 minutes and 24 hours.",
            400,
        )
    try:
        record, token, invitation_code = AgentInvitationService.create(
            g.current_user.id,
            timedelta(minutes=ttl_minutes),
        )
    except PermissionError:
        return _error_response("forbidden", "Administrator access is required.", 403)
    except RuntimeError as exc:
        return _error_response("enrollment_disabled", str(exc), 409)
    response = jsonify({
        "id": str(record.id),
        "invitation_token": token,
        "invitation_code": invitation_code,
        "created_at": _serialize_datetime(record.created_at),
        "expires_at": _serialize_datetime(record.expires_at),
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 201


@api.post("/server/enrollment/invitations/<invitation_id>/revoke")
@require_user
@require_role("admin")
def revoke_agent_invitation(invitation_id):
    parsed_id = _parse_uuid(invitation_id)
    if parsed_id is None:
        return _error_response("invalid_invitation_id", "Invalid invitation ID.", 400)
    result = AgentInvitationService.revoke(parsed_id)
    if result is None:
        return _error_response("invitation_not_found", "Invitation not found.", 404)
    return jsonify({"id": str(parsed_id), "revoked": bool(result)}), 200


@api.post("/agents/enroll-invitation")
def enroll_agent_with_invitation():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _invalid_request_response()
    allowed = {
        "invitation_token", "invitation_code", "hostname", "platform", "agent_version",
        "platform_version", "architecture",
    }
    if set(data) - allowed:
        return _error_response(
            "invalid_enrollment_request",
            "Enrollment request contains unsupported fields.",
            400,
        )
    try:
        result = AgentInvitationService.enroll(
            token=data.get("invitation_token"),
            invitation_code=data.get("invitation_code"),
            hostname=data.get("hostname"),
            platform=data.get("platform"),
            agent_version=data.get("agent_version"),
            platform_version=data.get("platform_version"),
            architecture=data.get("architecture"),
        )
    except InvalidInvitationError:
        return _error_response(
            "invalid_invitation",
            "Invitation is invalid, expired, already used, revoked, or enrollment is disabled.",
            401,
        )
    except AssetAlreadyEnrolledError:
        return _error_response(
            "asset_already_enrolled",
            "Target asset already has an active agent.",
            409,
        )
    except EnrollmentError as exc:
        return _error_response("enrollment_unavailable", str(exc), 409)
    except ValueError as exc:
        return _error_response("invalid_enrollment_request", str(exc), 400)
    except RuntimeError:
        return _error_response("enrollment_not_configured", "Agent enrollment is not configured.", 503)

    response = jsonify({
        "agent_id": str(result.agent.id),
        "asset_id": str(result.asset.id),
        "token": result.token,
        "token_type": "Bearer",
        "expires_at": _serialize_datetime(result.credential.expires_at),
    })
    response.headers["Cache-Control"] = "no-store"
    return response, 201
