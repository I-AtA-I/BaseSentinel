
import pytest

from basesentinel import db
from basesentinel.models import User
from basesentinel.services.users import UserService


class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "test-secret"


@pytest.fixture
def app():
    from basesentinel import create_app

    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(app):
    with app.app_context():
        created = UserService.create_user(
            username="apiadmin",
            password="correct-password-123",
            role="admin",
        )
        return created.id


def login(client):
    return client.post(
        "/api/v1/auth/login",
        json={
            "username": "apiadmin",
            "password": "correct-password-123",
        },
    )


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_success(client, user):
    response = login(client)

    assert response.status_code == 200

    data = response.get_json()

    assert data["token"]
    assert data["token_type"] == "Bearer"
    assert data["user"]["username"] == "apiadmin"
    assert data["user"]["role"] == "admin"
    assert "expires_at" in data
    assert response.headers["Cache-Control"] == "no-store"


def test_login_invalid_password(client, user):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "apiadmin",
            "password": "wrong-password-123",
        },
    )

    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "invalid_credentials"


def test_login_unknown_user(client):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "unknown",
            "password": "correct-password-123",
        },
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"username": "apiadmin"},
        {"password": "correct-password-123"},
        {"username": 123, "password": "correct-password-123"},
        {"username": "apiadmin", "password": 123},
    ],
)
def test_login_invalid_payload(client, payload):
    response = client.post(
        "/api/v1/auth/login",
        json=payload,
    )

    assert response.status_code == 400


def test_me_requires_authentication(client):
    response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_me_with_valid_session(client, user):
    login_response = login(client)
    token = login_response.get_json()["token"]

    response = client.get(
        "/api/v1/auth/me",
        headers=auth_headers(token),
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["user_id"] == str(user)
    assert data["username"] == "apiadmin"
    assert data["role"] == "admin"
    assert data["is_active"] is True


def test_me_rejects_invalid_token(client):
    response = client.get(
        "/api/v1/auth/me",
        headers=auth_headers("x" * 43),
    )

    assert response.status_code == 401


def test_logout_revokes_session(client, user):
    login_response = login(client)
    token = login_response.get_json()["token"]
    headers = auth_headers(token)

    logout_response = client.post(
        "/api/v1/auth/logout",
        headers=headers,
    )

    assert logout_response.status_code == 200

    me_response = client.get(
        "/api/v1/auth/me",
        headers=headers,
    )

    assert me_response.status_code == 401


def test_logout_requires_authentication(client):
    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 401


def test_inactive_user_cannot_login(client, app, user):
    with app.app_context():
        account = db.session.get(User, user)
        account.is_active = False
        db.session.commit()

    response = login(client)

    assert response.status_code == 401
