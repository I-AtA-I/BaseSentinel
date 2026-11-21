import json
import subprocess
import uuid

import pytest

from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.queue import EventQueue


def _event():
    return {
        "event_uid": str(uuid.uuid4()),
        "schema_version": 1,
        "category": "authentication",
        "event_type": "login.failed",
        "severity": 7,
        "source": "Windows Security",
        "event_code": "4625",
        "message": "A failed sign-in was recorded.",
        "event_data": {"TargetUserName": "test-user"},
        "occurred_at": "2026-11-17T10:00:00Z",
    }


def test_client_sends_authenticated_event_payload(monkeypatch):
    from basesentinel_agent import client as client_module

    payload = _event()
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"event_id":"stored-event","duplicate":false}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.method
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(client_module, "urlopen", fake_urlopen)

    client = BaseSentinelClient(
        "https://siem.example.test",
        token="test-agent-token",
    )
    response = client.send_event(payload)

    assert captured["url"] == "https://siem.example.test/api/v1/events"
    assert captured["method"] == "POST"
    assert captured["authorization"] == "Bearer test-agent-token"
    assert captured["payload"] == payload
    assert captured["timeout"] == 10.0
    assert response["event_id"] == "stored-event"


def test_collection_pipeline_queues_sends_and_acknowledges(monkeypatch, tmp_path):
    from basesentinel_agent import cli

    payload = _event()
    queue = EventQueue(tmp_path / "events.sqlite3")
    delivered = []

    class FakeClient:
        def send_event(self, event):
            delivered.append(event)
            return {"event_id": "stored-event", "duplicate": False}

    monkeypatch.setattr(
        cli,
        "collect_security_events",
        lambda checkpoint: ([payload], 1234),
    )

    result = cli._collect_and_send(FakeClient(), queue, batch_size=50)

    assert result == (1, 1, 0, 1234)
    assert delivered == [payload]
    assert queue.pending() == []
    assert queue.security_checkpoint() == 1234


@pytest.mark.parametrize(
    ("event_type", "legacy_category", "expected_category"),
    [
        ("audit.policy_changed", "security", "audit"),
        ("security_log.cleared", "security", "audit"),
        ("device.usb_storage_recognized", "device", "system"),
    ],
)
def test_delivery_normalizes_legacy_windows_event_categories(
    tmp_path, event_type, legacy_category, expected_category
):
    from basesentinel_agent import cli

    payload = _event()
    payload["event_type"] = event_type
    payload["category"] = legacy_category
    queue = EventQueue(tmp_path / "events.sqlite3")
    queue.add(payload)
    delivered = []

    class FakeClient:
        def send_event(self, event):
            delivered.append(event)
            return {"event_uid": event["event_uid"]}

    sent, pending = cli._deliver_pending(FakeClient(), queue, batch_size=10)

    assert sent == 1
    assert pending == 0
    assert delivered[0]["category"] == expected_category
    assert queue.pending() == []


def test_failed_delivery_stays_in_local_queue(monkeypatch, tmp_path, capsys):
    from basesentinel_agent import cli

    payload = _event()
    queue = EventQueue(tmp_path / "events.sqlite3")

    class UnavailableClient:
        def send_event(self, _event):
            raise AgentApiError(503, "Ingestion service unavailable.")

    monkeypatch.setattr(
        cli,
        "collect_security_events",
        lambda checkpoint: ([payload], 2345),
    )

    result = cli._collect_and_send(UnavailableClient(), queue, batch_size=50)

    assert result == (1, 0, 1, 2345)
    assert queue.pending() == [payload]
    assert queue.security_checkpoint() == 2345
    assert "HTTP 503" in capsys.readouterr().out


def test_security_log_permission_error_is_not_reported_as_empty(monkeypatch):
    from basesentinel_agent import windows_eventlog

    def denied(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=2,
            stdout="",
            stderr="Access is denied.",
        )

    monkeypatch.setattr(windows_eventlog.subprocess, "run", denied)

    with pytest.raises(RuntimeError, match="permission to read the Security log"):
        windows_eventlog.collect_security_events()


def test_client_to_server_event_delivery_round_trip(monkeypatch):
    import io
    from datetime import timedelta
    from urllib.error import HTTPError

    from basesentinel import create_app, db
    from basesentinel.core.security import generate_agent_token, hash_agent_token
    from basesentinel.models import Agent, AgentCredential, Asset, SecurityEvent
    from basesentinel.models.base import utcnow_naive
    from basesentinel_agent import client as client_module

    class TestConfig:
        TESTING = True
        SECRET_KEY = "test-secret"
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        SQLALCHEMY_TRACK_MODIFICATIONS = False

    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        now = utcnow_naive()
        asset = Asset(
            display_name="Delivery Test",
            hostname="delivery-test",
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

        flask_client = app.test_client()
        payload = _event()

        class FakeResponse:
            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.body

        def route_request(request, timeout):
            assert timeout == 10.0
            response = flask_client.open(
                "/api/v1/events",
                method=request.method,
                data=request.data,
                headers={
                    "Authorization": request.get_header("Authorization"),
                    "Content-Type": request.get_header("Content-type"),
                    "Accept": request.get_header("Accept"),
                },
            )
            if response.status_code >= 400:
                raise HTTPError(
                    request.full_url,
                    response.status_code,
                    "API request failed",
                    response.headers,
                    io.BytesIO(response.get_data()),
                )
            return FakeResponse(response.get_data())

        monkeypatch.setattr(client_module, "urlopen", route_request)

        agent_client = BaseSentinelClient(
            "http://127.0.0.1:5000",
            token=token,
        )
        result = agent_client.send_event(payload)

        assert result["duplicate"] is False
        assert result["event_uid"] == payload["event_uid"]
        stored = db.session.query(SecurityEvent).one()
        assert str(stored.agent_id) == str(agent.id)
        assert str(stored.event_uid) == payload["event_uid"]

        db.session.remove()
        db.drop_all()
