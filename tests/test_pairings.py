
from datetime import timedelta
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.core.security import verify_pairing_code
from basesentinel.models import PairingCode
from basesentinel.models.base import utcnow_naive
from basesentinel.services import PairingService, UserService


TEST_PEPPER = "test-pepper-for-basesentinel-32bytes"


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    PAIRING_CODE_PEPPER = TEST_PEPPER
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


def create_admin():
    return UserService.create_user(
        username="admin",
        password="a-long-test-password",
        role="admin",
    )


def test_create_pairing_code(app):
    admin = create_admin()

    record, raw_code = PairingService.create_code(admin.id)

    assert len(raw_code) == 14
    assert record.code_hash != raw_code
    assert verify_pairing_code(
        raw_code,
        record.code_hash,
        TEST_PEPPER,
    )
    assert record.created_by_user_id == admin.id
    assert record.consumed_at is None
    assert record.revoked_at is None


def test_create_pairing_code_with_custom_ttl(app):
    admin = create_admin()

    ttl = timedelta(minutes=5)
    before_creation = utcnow_naive()

    record, _ = PairingService.create_code(
        admin.id,
        ttl=ttl,
    )

    assert before_creation + ttl <= record.expires_at


def test_pairing_code_requires_admin(app):
    viewer = UserService.create_user(
        username="viewer",
        password="a-long-test-password",
        role="viewer",
    )

    with pytest.raises(PermissionError):
        PairingService.create_code(viewer.id)


def test_pairing_code_rejects_invalid_ttl(app):
    admin = create_admin()

    with pytest.raises(ValueError):
        PairingService.create_code(
            admin.id,
            ttl=timedelta(hours=1),
        )


def test_pairing_code_rejects_unknown_target_asset(app):
    admin = create_admin()

    with pytest.raises(ValueError):
        PairingService.create_code(
            admin.id,
            target_asset_id=uuid.uuid4(),
        )


def test_revoke_pairing_code(app):
    admin = create_admin()

    record, _ = PairingService.create_code(admin.id)

    result = PairingService.revoke_code(
        record.id,
        admin.id,
    )

    assert result is True

    stored_record = db.session.get(PairingCode, record.id)

    assert stored_record.revoked_at is not None

    assert PairingService.revoke_code(
        record.id,
        admin.id,
    ) is False


def test_expired_pairing_code_cannot_be_revoked(app):
    admin = create_admin()

    record, _ = PairingService.create_code(admin.id)

    record.expires_at = utcnow_naive() - timedelta(minutes=1)
    db.session.commit()

    result = PairingService.revoke_code(
        record.id,
        admin.id,
    )

    assert result is False
