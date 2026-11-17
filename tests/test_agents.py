from datetime import timedelta

from basesentinel import create_app, db
from basesentinel.models import (
    Asset,
    Agent,
    AgentCredential,
    PairingCode,
    User,
)
from basesentinel.models.base import utcnow_naive


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def test_agent_management_relationships():
    app = create_app(TestConfig)

    with app.app_context():
        db.create_all()

        try:
            user = User(
                username="admin",
                password_hash="test-password-hash",
                role="admin",
            )

            asset = Asset(
                display_name="Test Workstation",
                hostname="test-pc",
                asset_type="workstation",
            )

            agent = Agent(
                platform="windows",
                platform_version="11",
                architecture="x64",
                agent_version="0.1.0",
            )

            credential = AgentCredential(
                secret_hash="a" * 64,
                expires_at=utcnow_naive() + timedelta(days=90),
            )

            pairing_code = PairingCode(
                code_hash="b" * 64,
                expires_at=utcnow_naive() + timedelta(minutes=10),
            )

            agent.asset = asset
            agent.credentials.append(credential)

            pairing_code.created_by = user
            pairing_code.target_asset = asset
            pairing_code.consumed_by_agent = agent

            db.session.add_all([user, asset, agent, pairing_code])
            db.session.commit()

            assert User.query.count() == 1
            assert Agent.query.count() == 1
            assert AgentCredential.query.count() == 1
            assert PairingCode.query.count() == 1

            assert agent.asset_id == asset.id
            assert credential.agent_id == agent.id
            assert pairing_code.created_by_user_id == user.id
            assert pairing_code.target_asset_id == asset.id
            assert pairing_code.consumed_by_agent_id == agent.id

        finally:
            db.session.rollback()
            db.session.remove()
            db.drop_all()


def test_agent_management_tables_registered():
    app = create_app(TestConfig)

    with app.app_context():
        expected_tables = {
            "users",
            "agents",
            "agent_credentials",
            "pairing_codes",
        }

        assert expected_tables.issubset(db.metadata.tables.keys())