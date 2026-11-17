
import pytest

from basesentinel import create_app, db
from basesentinel.core.security import verify_password
from basesentinel.models import User
from basesentinel.services import (
    UserService,
    UserAlreadyExistsError,
)


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


@pytest.fixture
def app():
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()

        yield app

        db.session.remove()
        db.drop_all()


def test_create_user(app):
    user = UserService.create_user(
        username="Admin",
        password="a-long-test-password",
        role="admin",
    )

    assert user.username == "admin"
    assert user.role == "admin"
    assert user.is_active is True
    assert user.password_hash != "a-long-test-password"

    assert verify_password(
        "a-long-test-password",
        user.password_hash,
    )


def test_username_is_normalized(app):
    user = UserService.create_user(
        username="  TestUser  ",
        password="a-long-test-password",
    )

    assert user.username == "testuser"


def test_duplicate_username_is_rejected(app):
    UserService.create_user(
        username="admin",
        password="a-long-test-password",
    )

    with pytest.raises(UserAlreadyExistsError):
        UserService.create_user(
            username="ADMIN",
            password="another-test-password",
        )


def test_invalid_username_is_rejected(app):
    with pytest.raises(ValueError):
        UserService.create_user(
            username="ab",
            password="a-long-test-password",
        )


def test_short_password_is_rejected(app):
    with pytest.raises(ValueError):
        UserService.create_user(
            username="testuser",
            password="short",
        )


def test_invalid_role_is_rejected(app):
    with pytest.raises(ValueError):
        UserService.create_user(
            username="testuser",
            password="a-long-test-password",
            role="superadmin",
        )


def test_authentication_success(app):
    UserService.create_user(
        username="admin",
        password="a-long-test-password",
        role="admin",
    )

    user = UserService.authenticate(
        "ADMIN",
        "a-long-test-password",
    )

    assert user is not None
    assert user.username == "admin"
    assert user.last_login_at is not None


def test_authentication_rejects_wrong_password(app):
    UserService.create_user(
        username="admin",
        password="a-long-test-password",
    )

    user = UserService.authenticate(
        "admin",
        "incorrect-password",
    )

    assert user is None


def test_authentication_rejects_inactive_user(app):
    user = UserService.create_user(
        username="admin",
        password="a-long-test-password",
    )

    user.is_active = False
    db.session.commit()

    result = UserService.authenticate(
        "admin",
        "a-long-test-password",
    )

    assert result is None
