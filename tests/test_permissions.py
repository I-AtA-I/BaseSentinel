
import pytest

from flask import Flask, g, jsonify

from basesentinel.api.permissions import require_role


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.get("/admin")
    @require_role("admin")
    def admin_route():
        return jsonify({"access": "granted"}), 200

    @app.get("/analyst")
    @require_role("admin", "analyst")
    def analyst_route():
        return jsonify({"access": "granted"}), 200

    @app.get("/inventory")
    @require_role("admin", "analyst", "viewer")
    def inventory_route():
        return jsonify({"access": "granted"}), 200

    @app.get("/unprotected")
    def unprotected_route():
        return jsonify({"access": "public"}), 200

    return app


@pytest.fixture
def client(app):
    return app.test_client()


def set_user_role(app, role):
    @app.before_request
    def inject_user():
        g.current_user = type(
            "TestUser",
            (),
            {"role": role},
        )()


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_admin_route_requires_admin(app, client, role):
    set_user_role(app, role)

    response = client.get("/admin")

    if role == "admin":
        assert response.status_code == 200
    else:
        assert response.status_code == 403


@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_analyst_route_allows_admin_and_analyst(app, client, role):
    set_user_role(app, role)

    response = client.get("/analyst")

    assert response.status_code == 200


def test_analyst_route_rejects_viewer(app, client):
    set_user_role(app, "viewer")

    response = client.get("/analyst")

    assert response.status_code == 403


@pytest.mark.parametrize("role", ["admin", "analyst", "viewer"])
def test_inventory_allows_all_roles(app, client, role):
    set_user_role(app, role)

    response = client.get("/inventory")

    assert response.status_code == 200


def test_protected_route_rejects_missing_user(client):
    response = client.get("/admin")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_forbidden_response_has_no_store_header(app, client):
    set_user_role(app, "viewer")

    response = client.get("/admin")

    assert response.status_code == 403
    assert response.headers["Cache-Control"] == "no-store"


def test_invalid_role_is_rejected():
    with pytest.raises(ValueError):
        require_role("superuser")


def test_empty_role_list_is_rejected():
    with pytest.raises(ValueError):
        require_role()
