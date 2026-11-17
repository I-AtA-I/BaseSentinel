from basesentinel.services.credentials import AgentUnavailableError
from datetime import timedelta
import uuid

import pytest

from basesentinel import create_app, db
from basesentinel.core.security import (
    generate_agent_token,
    hash_agent_token,
)
from basesentinel.models import (
    Agent,
    AgentCredential,
    Asset,
    User,
)
from basesentinel.models.base import utcnow_naive
from basesentinel.services import (
    UserService,
    AgentAuthenticationService,
    AgentCredentialService,
    InvalidAgentCredentialError,
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


def create_admin():
    return UserService.create_user(
        username="admin",
        password="test-password-123",
        role="admin",
    )


def create_agent_with_token():
    now = utcnow_naive()

    asset = Asset(
        display_name="Credential Test",
        hostname="credential-test",
        asset_type="workstation",
    )

    agent = Agent(
        asset=asset,
        platform="windows",
        platform_version="11",
        architecture="x64",
        agent_version="0.1.0",
        status="active",
    )

    token = generate_agent_token()

    credential = AgentCredential(
        agent=agent,
        secret_hash=hash_agent_token(token),
        created_at=now,
        expires_at=now + timedelta(days=90),
    )

    db.session.add_all([asset, agent, credential])
    db.session.commit()

    return token, agent, credential


def test_credential_rotation_invalidates_old_token(app):
    old_token, agent, old_credential = create_agent_with_token()

    result = AgentCredentialService.rotate_credential(old_token)

    assert result.token != old_token
    assert result.credential.agent_id == agent.id
    assert result.credential.secret_hash != result.token
    assert old_credential.revoked_at is not None

    assert AgentAuthenticationService.authenticate(old_token) is None

    authenticated = AgentAuthenticationService.authenticate(result.token)

    assert authenticated is not None
    assert authenticated.agent.id == agent.id


def test_rotation_creates_only_one_new_credential(app):
    old_token, agent, _ = create_agent_with_token()

    result = AgentCredentialService.rotate_credential(old_token)

    credentials = AgentCredential.query.filter_by(
        agent_id=agent.id
    ).all()

    assert len(credentials) == 2
    assert result.credential in credentials


def test_expired_credential_cannot_be_rotated(app):
    token, _, credential = create_agent_with_token()

    credential.expires_at = utcnow_naive() - timedelta(seconds=1)
    db.session.commit()

    with pytest.raises(InvalidAgentCredentialError):
        AgentCredentialService.rotate_credential(token)


def test_revoked_credential_cannot_be_rotated(app):
    token, _, credential = create_agent_with_token()

    credential.revoked_at = utcnow_naive()
    db.session.commit()

    with pytest.raises(InvalidAgentCredentialError):
        AgentCredentialService.rotate_credential(token)


def test_rotation_rejects_excessive_lifetime(app):
    token, _, _ = create_agent_with_token()

    with pytest.raises(ValueError):
        AgentCredentialService.rotate_credential(
            token,
            ttl=timedelta(days=400),
        )


def test_administrator_can_revoke_one_credential(app):
    admin = create_admin()
    token, agent, credential = create_agent_with_token()

    result = AgentCredentialService.revoke_credential(
        credential.id,
        admin.id,
    )

    assert result is True
    assert credential.revoked_at is not None

    assert AgentAuthenticationService.authenticate(token) is None

    db.session.refresh(agent)
    assert agent.status == "active"


def test_viewer_cannot_revoke_credentials(app):
    viewer = UserService.create_user(
        username="viewer",
        password="test-password-123",
        role="viewer",
    )

    _, _, credential = create_agent_with_token()

    with pytest.raises(PermissionError):
        AgentCredentialService.revoke_credential(
            credential.id,
            viewer.id,
        )

    db.session.refresh(credential)
    assert credential.revoked_at is None


def test_administrator_can_revoke_entire_agent(app):
    admin = create_admin()
    token, agent, first_credential = create_agent_with_token()

    second_token = generate_agent_token()

    second_credential = AgentCredential(
        agent_id=agent.id,
        secret_hash=hash_agent_token(second_token),
        created_at=utcnow_naive(),
        expires_at=utcnow_naive() + timedelta(days=90),
    )

    db.session.add(second_credential)
    db.session.commit()

    result = AgentCredentialService.revoke_agent(
        agent.id,
        admin.id,
    )

    assert result is True

    db.session.refresh(agent)
    db.session.refresh(first_credential)
    db.session.refresh(second_credential)

    assert agent.status == "revoked"
    assert agent.revoked_at is not None
    assert first_credential.revoked_at is not None
    assert second_credential.revoked_at is not None

    assert AgentAuthenticationService.authenticate(token) is None
    assert AgentAuthenticationService.authenticate(second_token) is None


def test_unknown_credential_or_agent_returns_false(app):
    admin = create_admin()
    unknown_id = uuid.uuid4()

    assert AgentCredentialService.revoke_credential(
        unknown_id,
        admin.id,
    ) is False

    assert AgentCredentialService.revoke_agent(
        unknown_id,
        admin.id,
    ) is False


def test_nonexistent_agent_token_cannot_be_rotated(app):
    with pytest.raises(InvalidAgentCredentialError):
        AgentCredentialService.rotate_credential(
            generate_agent_token()
        )


def test_admin_can_rotate_all_agent_credentials(app):
    admin = create_admin()
    old_token, agent, old_credential = create_agent_with_token()

    second_token = generate_agent_token()
    second_credential = AgentCredential(
        agent_id=agent.id,
        secret_hash=hash_agent_token(second_token),
        created_at=utcnow_naive(),
        expires_at=utcnow_naive() + timedelta(days=90),
    )

    db.session.add(second_credential)
    db.session.commit()

    result = AgentCredentialService.rotate_agent_credential(
        agent.id,
        admin.id,
    )

    assert result is not None
    assert result.token != old_token
    assert result.token != second_token
    assert result.credential.agent_id == agent.id
    assert result.credential.secret_hash == hash_agent_token(result.token)
    assert result.credential.secret_hash != result.token

    db.session.refresh(old_credential)
    db.session.refresh(second_credential)

    assert old_credential.revoked_at is not None
    assert second_credential.revoked_at is not None

    credentials = AgentCredential.query.filter_by(
        agent_id=agent.id
    ).all()

    active_credentials = [
        credential
        for credential in credentials
        if credential.revoked_at is None
    ]

    assert len(active_credentials) == 1
    assert active_credentials[0].id == result.credential.id

    assert AgentAuthenticationService.authenticate(old_token) is None
    assert AgentAuthenticationService.authenticate(second_token) is None

    authenticated = AgentAuthenticationService.authenticate(result.token)
    assert authenticated is not None
    assert authenticated.agent.id == agent.id


def test_viewer_cannot_rotate_agent_credentials(app):
    viewer = UserService.create_user(
        username="rotationviewer",
        password="test-password-123",
        role="viewer",
    )

    token, agent, credential = create_agent_with_token()

    with pytest.raises(PermissionError):
        AgentCredentialService.rotate_agent_credential(
            agent.id,
            viewer.id,
        )

    db.session.refresh(credential)

    assert credential.revoked_at is None
    assert AgentCredential.query.filter_by(
        agent_id=agent.id
    ).count() == 1

    assert AgentAuthenticationService.authenticate(token) is not None


def test_unknown_agent_returns_none_on_admin_rotation(app):
    admin = create_admin()

    result = AgentCredentialService.rotate_agent_credential(
        uuid.uuid4(),
        admin.id,
    )

    assert result is None


def test_revoked_agent_cannot_receive_new_credential(app):
    admin = create_admin()
    _, agent, credential = create_agent_with_token()

    agent.status = "revoked"
    agent.revoked_at = utcnow_naive()
    db.session.commit()

    with pytest.raises(AgentUnavailableError):
        AgentCredentialService.rotate_agent_credential(
            agent.id,
            admin.id,
        )

    assert AgentCredential.query.filter_by(
        agent_id=agent.id
    ).count() == 1

    db.session.refresh(credential)
    assert credential.revoked_at is None


def test_uninstalled_agent_cannot_receive_new_credential(app):
    admin = create_admin()
    _, agent, _ = create_agent_with_token()

    agent.uninstalled_at = utcnow_naive()
    db.session.commit()

    with pytest.raises(AgentUnavailableError):
        AgentCredentialService.rotate_agent_credential(
            agent.id,
            admin.id,
        )

    assert AgentCredential.query.filter_by(
        agent_id=agent.id
    ).count() == 1


def test_admin_rotation_rejects_excessive_lifetime(app):
    admin = create_admin()
    _, agent, _ = create_agent_with_token()

    with pytest.raises(ValueError):
        AgentCredentialService.rotate_agent_credential(
            agent.id,
            admin.id,
            ttl=timedelta(days=400),
        )


def test_admin_rotation_supports_custom_lifetime(app):
    admin = create_admin()
    _, agent, _ = create_agent_with_token()

    result = AgentCredentialService.rotate_agent_credential(
        agent.id,
        admin.id,
        ttl=timedelta(days=30),
    )

    assert result is not None
    assert result.credential.expires_at - result.credential.created_at == timedelta(days=30)
