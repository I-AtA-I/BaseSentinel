
from functools import wraps

from flask import g, jsonify, request

from basesentinel.services.authentication import (
    AgentAuthenticationService,
)
from basesentinel.services.sessions import UserSessionService


def _unauthorized_response():
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


def _get_bearer_token():
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()

    if (
        len(parts) != 2
        or parts[0].lower() != "bearer"
        or len(parts[1]) < 32
        or len(parts[1]) > 256
    ):
        return None

    return parts[1]


def require_agent(view):
    """Require a valid agent bearer token."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _get_bearer_token()

        if token is None:
            return _unauthorized_response()

        authentication = AgentAuthenticationService.authenticate(token)

        if authentication is None:
            return _unauthorized_response()

        g.current_agent = authentication.agent
        g.current_agent_credential = authentication.credential

        return view(*args, **kwargs)

    return wrapped


def require_user(view):
    """Require a valid user session bearer token."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _get_bearer_token()

        if token is None:
            return _unauthorized_response()

        authentication = UserSessionService.authenticate(token)

        if authentication is None:
            return _unauthorized_response()

        g.current_user = authentication.user
        g.current_user_session = authentication.session

        return view(*args, **kwargs)

    return wrapped
