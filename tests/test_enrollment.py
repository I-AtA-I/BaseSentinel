
from datetime import timedelta

import pytest

from basesentinel import create_app, db
from basesentinel.core.security import verify_agent_token
from basesentinel.models import Asset, Agent, AgentCredential, PairingCode
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    UserService,
    PairingService,
    EnrollmentService,
    InvalidPairingCodeError,
    AssetAlreadyEnrolledError,
)


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


def create_pairing_code(admin, target_asset_id=None):
    return PairingService.create_code(
        created_by_user_id=admin.id,
        target_asset_id=target_asset_id,
    )


def test_successful_enrollment_creates_asset_and_agent(app):
    admin = create_admin()
    _, code = create_pairing_code(admin)

    result = EnrollmentService.enroll(
        pairing_code=code,
        hostname="test-workstation",
        platform="windows",
        platform_version="11",
        architecture="x64",
        agent_version="0.1.0",
    )

    assert Asset.query.count() == 1
    assert Agent.query.count() == 1
    assert AgentCredential.query.count() == 1

    assert result.asset.hostname == "test-workstation"
    assert result.agent.platform == "windows"
    assert result.agent.status == "active"

    assert result.credential.agent_id == result.agent.id
    assert verify_agent_token(
        result.token,
        result.credential.secret_hash,
    )


def test_enrollment_consumes_pairing_code(app):
    admin = create_admin()
    record, code = create_pairing_code(admin)

    result = EnrollmentService.enroll(
        pairing_code=code,
        hostname="test-linux",
        platform="linux",
        agent_version="0.1.0",
    )

    db.session.refresh(record)

    assert record.consumed_at is not None
    assert record.consumed_by_agent_id == result.agent.id


def test_pairing_code_cannot_be_used_twice(app):
    admin = create_admin()
    _, code = create_pairing_code(admin)

    EnrollmentService.enroll(
        pairing_code=code,
        hostname="test-pc",
        platform="windows",
        agent_version="0.1.0",
    )

    with pytest.raises(InvalidPairingCodeError):
        EnrollmentService.enroll(
            pairing_code=code,
            hostname="another-pc",
            platform="windows",
            agent_version="0.1.0",
        )

    assert Agent.query.count() == 1
    assert Asset.query.count() == 1


def test_expired_pairing_code_is_rejected(app):
    admin = create_admin()
    record, code = create_pairing_code(admin)

    record.expires_at = utcnow_naive() - timedelta(minutes=1)
    db.session.commit()

    with pytest.raises(InvalidPairingCodeError):
        EnrollmentService.enroll(
            pairing_code=code,
            hostname="test-pc",
            platform="windows",
            agent_version="0.1.0",
        )

    assert Agent.query.count() == 0
    assert Asset.query.count() == 0


def test_target_asset_is_reused(app):
    admin = create_admin()

    asset = Asset(
        display_name="Existing Workstation",
        hostname="old-hostname",
        asset_type="workstation",
    )

    db.session.add(asset)
    db.session.commit()

    _, code = create_pairing_code(admin, asset.id)

    result = EnrollmentService.enroll(
        pairing_code=code,
        hostname="new-hostname",
        platform="windows",
        agent_version="0.1.0",
    )

    assert result.asset.id == asset.id
    assert result.asset.hostname == "new-hostname"
    assert Asset.query.count() == 1


def test_second_active_agent_for_same_asset_is_rejected(app):
    admin = create_admin()

    asset = Asset(
        display_name="Managed Workstation",
        hostname="managed-pc",
        asset_type="workstation",
    )

    db.session.add(asset)
    db.session.commit()

    _, first_code = create_pairing_code(admin, asset.id)

    EnrollmentService.enroll(
        pairing_code=first_code,
        hostname="managed-pc",
        platform="windows",
        agent_version="0.1.0",
    )

    second_record, second_code = create_pairing_code(admin, asset.id)

    with pytest.raises(AssetAlreadyEnrolledError):
        EnrollmentService.enroll(
            pairing_code=second_code,
            hostname="managed-pc",
            platform="windows",
            agent_version="0.1.0",
        )

    db.session.refresh(second_record)

    assert Agent.query.count() == 1
    assert second_record.consumed_at is None
