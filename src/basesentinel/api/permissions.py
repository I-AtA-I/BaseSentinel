
from functools import wraps

from flask import g, jsonify


def require_role(*allowed_roles):
    """Require an authenticated user with one of the specified roles."""

    if not allowed_roles:
        raise ValueError("At least one role must be specified.")

    valid_roles = {"admin", "analyst", "viewer"}

    if not set(allowed_roles).issubset(valid_roles):
        raise ValueError("Invalid role specified.")

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = getattr(g, "current_user", None)

            if user is None:
                response = jsonify({
                    "error": {
                        "code": "unauthorized",
                        "message": "Authentication required.",
                    }
                })
                response.status_code = 401
                response.headers["WWW-Authenticate"] = "Bearer"
                response.headers["Cache-Control"] = "no-store"
                return response

            if user.role not in allowed_roles:
                response = jsonify({
                    "error": {
                        "code": "forbidden",
                        "message": "Insufficient permissions.",
                    }
                })
                response.status_code = 403
                response.headers["Cache-Control"] = "no-store"
                return response

            return view(*args, **kwargs)

        return wrapped

    return decorator
