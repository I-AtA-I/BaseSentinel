from basesentinel import create_app, db
from basesentinel.models import Agent, Asset
from basesentinel.services.users import UserService


TEST_PEPPER = "test-pepper-for-basesentinel-32bytes"


class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    PAIRING_CODE_PEPPER = TEST_PEPPER
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def setup_app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        UserService.create_user("enroll_admin", "test-password-123", "admin")
        UserService.create_user("enroll_viewer", "test-password-123", "viewer")
    return app


def login(client, username):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": "test-password-123"},
    )
    assert response.status_code == 200
    return response.json["token"]


def test_admin_can_create_one_time_pairing_code():
    app = setup_app()
    client = app.test_client()
    token = login(client, "enroll_admin")

    response = client.post(
        "/api/v1/pairing-codes",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_minutes": 5},
    )

    assert response.status_code == 201
    assert len(response.json["code"]) == 14
    assert response.json["expires_at"]
    assert response.headers["Cache-Control"] == "no-store"

    with app.app_context():
        from basesentinel.models import PairingCode
        record = db.session.get(PairingCode, response.json["id"])
        assert record is not None
        assert record.code_hash != response.json["code"]


def test_viewer_cannot_create_pairing_code():
    app = setup_app()
    client = app.test_client()
    token = login(client, "enroll_viewer")

    response = client.post(
        "/api/v1/pairing-codes",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )

    assert response.status_code == 403


def test_pairing_code_lifetime_is_validated():
    app = setup_app()
    client = app.test_client()
    token = login(client, "enroll_admin")

    response = client.post(
        "/api/v1/pairing-codes",
        headers={"Authorization": f"Bearer {token}"},
        json={"ttl_minutes": 31},
    )

    assert response.status_code == 400


def test_agent_can_enroll_with_pairing_code():
    app = setup_app()
    client = app.test_client()
    admin_token = login(client, "enroll_admin")

    pairing = client.post(
        "/api/v1/pairing-codes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={},
    )
    assert pairing.status_code == 201

    response = client.post(
        "/api/v1/agents/enroll",
        json={
            "pairing_code": pairing.json["code"],
            "hostname": "test-endpoint",
            "platform": "windows",
            "platform_version": "11",
            "architecture": "x64",
            "agent_version": "0.1.0",
        },
    )

    assert response.status_code == 201
    assert response.json["agent_id"]
    assert response.json["asset_id"]
    assert response.json["token"]
    assert response.json["token_type"] == "Bearer"
    assert response.headers["Cache-Control"] == "no-store"

    with app.app_context():
        agent = db.session.get(Agent, response.json["agent_id"])
        asset = db.session.get(Asset, response.json["asset_id"])
        assert agent is not None
        assert agent.status == "active"
        assert asset.hostname == "test-endpoint"


def test_pairing_code_cannot_be_reused():
    app = setup_app()
    client = app.test_client()
    admin_token = login(client, "enroll_admin")

    pairing = client.post(
        "/api/v1/pairing-codes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={},
    )
    payload = {
        "pairing_code": pairing.json["code"],
        "hostname": "test-endpoint",
        "platform": "linux",
        "agent_version": "0.1.0",
    }

    first = client.post("/api/v1/agents/enroll", json=payload)
    second = client.post("/api/v1/agents/enroll", json=payload)

    assert first.status_code == 201
    assert second.status_code == 401


def test_enrollment_rejects_unsupported_platform():
    app = setup_app()
    client = app.test_client()
    admin_token = login(client, "enroll_admin")

    pairing = client.post(
        "/api/v1/pairing-codes",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={},
    )

    response = client.post(
        "/api/v1/agents/enroll",
        json={
            "pairing_code": pairing.json["code"],
            "hostname": "unsupported-host",
            "platform": "freebsd",
            "agent_version": "0.1.0",
        },
    )

    assert response.status_code == 400
