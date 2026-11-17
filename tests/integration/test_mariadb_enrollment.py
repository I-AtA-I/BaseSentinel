
import os
import uuid

import pytest
from sqlalchemy import delete, inspect, select

from basesentinel import create_app, db
from basesentinel.config import Config
from basesentinel.core.security import verify_agent_token
from basesentinel.models import (
    Agent,
    AgentCredential,
    Asset,
    PairingCode,
    User,
)
from basesentinel.services import (
    UserService,
    PairingService,
    EnrollmentService,
    InvalidPairingCodeError,
)


pytestmark = pytest.mark.skipif(
    os.getenv("BASESENTINEL_MARIADB_INTEGRATION") != "1",
    reason="MariaDB integration tests are opt-in.",
)


class MariaDBTestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = (
        Config.SQLALCHEMY_DATABASE_URI.set(
            database="basesentinel_test"
        )
    )


def test_mariadb_agent_enrollment():
    app = create_app(MariaDBTestConfig)

    with app.app_context():
        assert db.engine.dialect.name == "mysql"
        assert db.engine.url.database == "basesentinel_test"

        required_tables = {
            "assets",
            "agents",
            "agent_credentials",
            "pairing_codes",
            "users",
        }

        existing_tables = set(inspect(db.engine).get_table_names())

        assert required_tables.issubset(existing_tables)

        user_id = None
        asset_id = None
        agent_id = None

        unique_id = uuid.uuid4().hex[:16]

        try:
            user = UserService.create_user(
                username=f"it_{unique_id}",
                password="Integration-Test-Password-123",
                role="admin",
            )

            user_id = user.id

            pairing_record, pairing_code = (
                PairingService.create_code(user.id)
            )

            result = EnrollmentService.enroll(
                pairing_code=pairing_code,
                hostname=f"it-host-{unique_id}",
                platform="windows",
                platform_version="11",
                architecture="x64",
                agent_version="0.1.0",
            )

            asset_id = result.asset.id
            agent_id = result.agent.id

            # Verify the agent and its credential.
            assert result.agent.status == "active"

            assert verify_agent_token(
                result.token,
                result.credential.secret_hash,
            )

            assert result.credential.agent_id == result.agent.id

            # Verify that the pairing code was consumed.
            db.session.refresh(pairing_record)

            assert pairing_record.consumed_at is not None
            assert pairing_record.consumed_by_agent_id == result.agent.id

            # A consumed pairing code must not work again.
            with pytest.raises(InvalidPairingCodeError):
                EnrollmentService.enroll(
                    pairing_code=pairing_code,
                    hostname="second-attempt",
                    platform="windows",
                    agent_version="0.1.0",
                )

            assert db.session.scalar(
                select(Agent.id).where(
                    Agent.id == result.agent.id
                )
            ) is not None

        finally:
            # Remove test records in foreign-key dependency order.
            db.session.rollback()

            if user_id is not None:
                db.session.execute(
                    delete(PairingCode).where(
                        PairingCode.created_by_user_id == user_id
                    )
                )

            if agent_id is not None:
                db.session.execute(
                    delete(AgentCredential).where(
                        AgentCredential.agent_id == agent_id
                    )
                )

                db.session.execute(
                    delete(Agent).where(
                        Agent.id == agent_id
                    )
                )

            if asset_id is not None:
                db.session.execute(
                    delete(Asset).where(
                        Asset.id == asset_id
                    )
                )

            if user_id is not None:
                db.session.execute(
                    delete(User).where(
                        User.id == user_id
                    )
                )

            db.session.commit()
