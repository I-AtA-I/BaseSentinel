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
