
import uuid
from datetime import timedelta

import pytest

from basesentinel import db
from basesentinel.models import User, UserSession
from basesentinel.models.base import utcnow_naive
from basesentinel.services import UserSessionService
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
def active_user(app):
    with app.app_context():
        user = UserService.create_user(
            username="sessionuser",
            password="correct-password-123",
            role="admin",
        )
        return user.id


def test_create_session_returns_token_and_stores_only_hash(app, active_user):
    with app.app_context():
        token, user_session = UserSessionService.create_session(active_user)

        assert isinstance(token, str)
        assert len(token) >= 32
        assert user_session.user_id == active_user
        assert user_session.token_hash != token
        assert len(user_session.token_hash) == 64

        stored = db.session.get(UserSession, user_session.id)
        assert stored.token_hash != token


def test_authenticate_valid_session(app, active_user):
    with app.app_context():
        token, _ = UserSessionService.create_session(active_user)

        result = UserSessionService.authenticate(token)

        assert result is not None
        assert result.user.id == active_user
        assert result.user.is_active is True


@pytest.mark.parametrize("token", ["", "short", None, 123])
def test_authenticate_rejects_invalid_token(app, token):
    with app.app_context():
        assert UserSessionService.authenticate(token) is None


def test_authenticate_rejects_expired_session(app, active_user):
    with app.app_context():
        token, user_session = UserSessionService.create_session(active_user)

        user_session.expires_at = utcnow_naive() - timedelta(seconds=1)
        db.session.commit()

        assert UserSessionService.authenticate(token) is None


def test_authenticate_rejects_revoked_session(app, active_user):
    with app.app_context():
        token, user_session = UserSessionService.create_session(active_user)

        user_session.revoked_at = utcnow_naive()
        db.session.commit()

        assert UserSessionService.authenticate(token) is None


def test_authenticate_rejects_inactive_user(app, active_user):
    with app.app_context():
        token, _ = UserSessionService.create_session(active_user)

        user = db.session.get(User, active_user)
        user.is_active = False
        db.session.commit()

        assert UserSessionService.authenticate(token) is None


def test_revoke_session(app, active_user):
    with app.app_context():
        token, user_session = UserSessionService.create_session(active_user)

        assert UserSessionService.revoke_session(token) is True
        assert UserSessionService.authenticate(token) is None

        stored = db.session.get(UserSession, user_session.id)
        assert stored.revoked_at is not None


def test_revoke_session_is_idempotent(app, active_user):
    with app.app_context():
        token, _ = UserSessionService.create_session(active_user)

        assert UserSessionService.revoke_session(token) is True
        assert UserSessionService.revoke_session(token) is False


def test_revoke_unknown_session(app):
    with app.app_context():
        assert UserSessionService.revoke_session(
            "a" * 43
        ) is False


def test_session_ttl_validation(app, active_user):
    with app.app_context():
        with pytest.raises(ValueError):
            UserSessionService.create_session(
                active_user,
                ttl=timedelta(days=91),
            )

        with pytest.raises(ValueError):
            UserSessionService.create_session(
                active_user,
                ttl=timedelta(seconds=0),
            )


def test_last_used_at_is_updated(app, active_user):
    with app.app_context():
        token, user_session = UserSessionService.create_session(active_user)

        assert user_session.last_used_at is None

        result = UserSessionService.authenticate(token)

        assert result is not None
        assert result.session.last_used_at is not None


def test_session_creation_rejects_inactive_user(app, active_user):
    with app.app_context():
        user = db.session.get(User, active_user)
        user.is_active = False
        db.session.commit()

        with pytest.raises(PermissionError):
            UserSessionService.create_session(active_user)
