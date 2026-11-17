
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

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
    SQLALCHEMY_DATABASE_URI = Config.SQLALCHEMY_DATABASE_URI.set(
        database="basesentinel_test"
    )


def test_concurrent_enrollment_with_same_pairing_code():
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

        unique_id = uuid.uuid4().hex[:16]

        user_id = None
        pairing_id = None
        agent_id = None
        asset_id = None

        try:
            user = UserService.create_user(
                username=f"race_{unique_id}",
                password="Integration-Test-Password-123",
                role="admin",
            )

            user_id = user.id

            pairing_record, pairing_code = PairingService.create_code(
                created_by_user_id=user.id,
            )

            pairing_id = pairing_record.id

            barrier = Barrier(2)

            def attempt_enrollment():
                with app.app_context():
                    barrier.wait(timeout=15)

                    try:
                        result = EnrollmentService.enroll(
                            pairing_code=pairing_code,
                            hostname=f"race-host-{unique_id}",
                            platform="windows",
                            platform_version="11",
                            architecture="x64",
                            agent_version="0.1.0",
                        )

                        assert verify_agent_token(
                            result.token,
                            result.credential.secret_hash,
                        )

                        return (
                            "enrolled",
                            result.agent.id,
                            result.asset.id,
                        )

                    except InvalidPairingCodeError:
                        return ("rejected", None, None)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(attempt_enrollment)
                    for _ in range(2)
                ]

                results = [
                    future.result(timeout=30)
                    for future in futures
                ]

            statuses = sorted(result[0] for result in results)

            assert statuses == ["enrolled", "rejected"]

            successful_result = next(
                result for result in results
                if result[0] == "enrolled"
            )

            _, agent_id, asset_id = successful_result

            # End the parent transaction to obtain a fresh DB snapshot.
            db.session.rollback()

            stored_pairing = db.session.get(
                PairingCode,
                pairing_id,
            )

            assert stored_pairing is not None
            assert stored_pairing.consumed_at is not None
            assert stored_pairing.consumed_by_agent_id == agent_id

            # Exactly one active agent must exist.
            assert Agent.query.filter_by(
                asset_id=asset_id,
                status="active",
            ).count() == 1

            # Exactly one credential must exist.
            assert AgentCredential.query.filter_by(
                agent_id=agent_id,
            ).count() == 1

            assert Asset.query.filter_by(
                id=asset_id,
            ).count() == 1

        finally:
            # End any remaining transaction before cleanup.
            db.session.rollback()

            # Recover IDs from the database if an assertion failed
            # before the successful worker result was processed.
            if pairing_id is not None:
                stored_pairing = db.session.get(
                    PairingCode,
                    pairing_id,
                )

                if stored_pairing is not None:
                    agent_id = (
                        stored_pairing.consumed_by_agent_id
                        or agent_id
                    )

            if agent_id is not None:
                stored_agent = db.session.get(
                    Agent,
                    agent_id,
                )

                if stored_agent is not None:
                    asset_id = stored_agent.asset_id

            # Delete in foreign-key dependency order.
            if pairing_id is not None:
                db.session.execute(
                    delete(PairingCode).where(
                        PairingCode.id == pairing_id
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
