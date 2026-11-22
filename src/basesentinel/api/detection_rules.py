import math
import re
from uuid import UUID

from flask import g, jsonify, request
from sqlalchemy import select

from basesentinel import db
from basesentinel.api import api
from basesentinel.api.decorators import require_user
from basesentinel.api.permissions import require_role
from basesentinel.models import DetectionRule
from basesentinel.models.base import utcnow_naive


RULE_FIELDS = {
    "name", "description", "category", "event_type", "source",
    "event_code", "min_event_severity", "conditions", "threshold",
    "window_seconds", "severity", "enabled",
}


def _error(code, message, status):
    response = jsonify({"error": {"code": code, "message": message}})
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def _timestamp(value):
    return value.isoformat() + "Z" if value is not None else None


def _rule_payload(rule):
    return {
        "id": str(rule.id),
        "name": rule.name,
        "description": rule.description,
        "category": rule.category,
        "event_type": rule.event_type,
        "source": rule.source,
        "event_code": rule.event_code,
        "min_event_severity": rule.min_event_severity,
        "conditions": rule.conditions,
        "threshold": rule.threshold,
        "window_seconds": rule.window_seconds,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "created_at": _timestamp(rule.created_at),
        "updated_at": _timestamp(rule.updated_at),
    }


def _validate_rule(data):
    if not isinstance(data, dict):
        return None, "A JSON object is required."
    unknown = set(data) - RULE_FIELDS
    if unknown:
        return None, "Unsupported rule fields were supplied."

    result = {}
    for field, maximum in (
        ("name", 120), ("description", 1000), ("category", 32),
        ("event_type", 80), ("source", 80), ("event_code", 64),
    ):
        value = data.get(field)
        if field in ("category", "event_type", "source", "event_code") and value is None:
            result[field] = None
            continue
        if field == "description" and value is None:
            value = ""
        if field == "name" and value is None:
            return None, "Name is required."
        if value is not None:
            if not isinstance(value, str):
                return None, f"{field} must be text."
            value = value.strip()
            if field == "name" and not value:
                return None, "Name is required."
            if len(value) > maximum:
                return None, f"{field} is too long."
        result[field] = value

    if result.get("event_type") and not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", result["event_type"].lower()):
        return None, "event_type has an invalid format."
    if result.get("category"):
        result["category"] = result["category"].lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", result["category"]):
            return None, "category has an invalid format."
    if result.get("event_type"):
        result["event_type"] = result["event_type"].lower()

    for field, minimum, maximum, optional in (
        ("min_event_severity", 0, 10, True),
        ("threshold", 1, 100, False),
        ("window_seconds", 1, 86400, False),
        ("severity", 0, 10, False),
    ):
        defaults = {"threshold": 1, "window_seconds": 300, "severity": 7}
        value = data.get(field, defaults.get(field))
        if value is None and optional:
            result[field] = None
            continue
        if type(value) is not int or not minimum <= value <= maximum:
            return None, f"{field} must be an integer between {minimum} and {maximum}."
        result[field] = value

    conditions = data.get("conditions", {})
    if not isinstance(conditions, dict) or len(conditions) > 20:
        return None, "conditions must be an object with at most 20 entries."
    normalized_conditions = {}
    for key, value in conditions.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", key):
            return None, "Condition keys must be simple event-data field names."
        if not (value is None or type(value) in (str, int, bool) or (type(value) is float and math.isfinite(value))):
            return None, "Condition values must be finite JSON scalar values."
        if isinstance(value, str) and len(value) > 256:
            return None, "Condition text values cannot exceed 256 characters."
        normalized_conditions[key] = value
    result["conditions"] = normalized_conditions

    enabled = data.get("enabled", True)
    if type(enabled) is not bool:
        return None, "enabled must be a boolean."
    result["enabled"] = enabled
    return result, None


@api.get("/detection-rules")
@require_user
def list_detection_rules():
    rules = db.session.scalars(
        select(DetectionRule).order_by(DetectionRule.created_at.desc(), DetectionRule.id)
    ).all()
    response = jsonify({"items": [_rule_payload(rule) for rule in rules]})
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.post("/detection-rules")
@require_user
@require_role("admin")
def create_detection_rule():
    data = request.get_json(silent=True)
    values, error = _validate_rule(data)
    if error:
        return _error("invalid_detection_rule", error, 400)

    rule = DetectionRule(
        **values,
        created_by_user_id=g.current_user.id,
        created_at=utcnow_naive(),
        updated_at=utcnow_naive(),
    )
    db.session.add(rule)
    db.session.commit()
    response = jsonify(_rule_payload(rule))
    response.headers["Cache-Control"] = "no-store"
    return response, 201


@api.patch("/detection-rules/<rule_id>")
@require_user
@require_role("admin")
def update_detection_rule(rule_id):
    try:
        parsed_id = UUID(rule_id)
    except (ValueError, TypeError, AttributeError):
        return _error("invalid_detection_rule_id", "Invalid detection rule ID.", 400)

    rule = db.session.get(DetectionRule, parsed_id)
    if rule is None:
        return _error("detection_rule_not_found", "Detection rule not found.", 404)

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("invalid_detection_rule", "A JSON object is required.", 400)
    current = {
        field: getattr(rule, field)
        for field in RULE_FIELDS
    }
    current.update(data)
    values, error = _validate_rule(current)
    if error:
        return _error("invalid_detection_rule", error, 400)

    for field, value in values.items():
        setattr(rule, field, value)
    rule.updated_at = utcnow_naive()
    db.session.commit()
    response = jsonify(_rule_payload(rule))
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@api.delete("/detection-rules/<rule_id>")
@require_user
@require_role("admin")
def delete_detection_rule(rule_id):
    try:
        parsed_id = UUID(rule_id)
    except (ValueError, TypeError, AttributeError):
        return _error("invalid_detection_rule_id", "Invalid detection rule ID.", 400)

    rule = db.session.get(DetectionRule, parsed_id)
    if rule is None:
        return _error("detection_rule_not_found", "Detection rule not found.", 404)

    db.session.delete(rule)
    db.session.commit()
    response = jsonify({"id": str(parsed_id), "deleted": True})
    response.headers["Cache-Control"] = "no-store"
    return response, 200
