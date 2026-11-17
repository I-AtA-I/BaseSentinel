import json
import uuid

import pytest

from basesentinel_agent.client import BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.windows_eventlog import _event_data


def test_client_requires_https_outside_localhost():
    with pytest.raises(ValueError):
        BaseSentinelClient("http://siem.example.com")


def test_client_allows_local_development_http():
    client = BaseSentinelClient("http://127.0.0.1:5000")
    assert client.base_url == "http://127.0.0.1:5000"


def test_client_rejects_url_credentials():
    with pytest.raises(ValueError):
        BaseSentinelClient("https://user:password@siem.example.com")


def test_queue_keeps_events_until_acknowledged(tmp_path):
    queue = EventQueue(tmp_path / "queue.sqlite3")
    event = {"event_uid": str(uuid.uuid4()), "event_type": "login.failed"}
    queue.add(event)
    queue.add(event)

    assert len(queue) == 1
    assert queue.pending() == [event]

    queue.acknowledge(event["event_uid"])
    assert len(queue) == 0


def test_queue_rejects_events_without_stable_id(tmp_path):
    queue = EventQueue(tmp_path / "queue.sqlite3")
    with pytest.raises(ValueError):
        queue.add({"event_type": "login.failed"})


def test_event_data_parser_extracts_named_fields():
    xml = """<Event><EventData><Data Name="TargetUserName">sample</Data><Data Name="IpAddress">192.0.2.10</Data></EventData></Event>"""
    assert _event_data(xml) == {
        "TargetUserName": "sample",
        "IpAddress": "192.0.2.10",
    }


def test_security_event_collector_normalizes_windows_events(monkeypatch):
    import subprocess
    from basesentinel_agent import windows_eventlog

    xml = """<Event><EventData><Data Name="TargetUserName">sample</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="IgnoredField">not-collected</Data></EventData></Event>"""
    output = {
        "LatestRecordId": 91,
        "Events": [{
            "Id": 4625,
            "RecordId": 91,
            "TimeCreated": "2026-11-17T10:00:00.0000000Z",
            "MachineName": "WORKSTATION",
            "Message": "A sign-in attempt failed.",
            "Xml": xml,
        }],
    }

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, json.dumps(output), "")

    monkeypatch.setattr(windows_eventlog.subprocess, "run", fake_run)
    events, checkpoint = windows_eventlog.collect_security_events()

    assert checkpoint == 91
    assert len(events) == 1
    event = events[0]
    assert event["category"] == "authentication"
    assert event["event_type"] == "login.failed"
    assert event["severity"] == 7
    assert event["event_code"] == "4625"
    assert event["event_data"]["TargetUserName"] == "sample"
    assert "IgnoredField" not in event["event_data"]
    assert event["event_uid"] == str(uuid.uuid5(
        uuid.NAMESPACE_URL, "windows-security:WORKSTATION:91:4625:2026-11-17T10:00:00.0000000Z"
    ))


def test_security_event_collector_handles_empty_log(monkeypatch):
    import subprocess
    from basesentinel_agent import windows_eventlog

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, json.dumps({
            "LatestRecordId": 250,
            "Events": [],
        }), "")

    monkeypatch.setattr(windows_eventlog.subprocess, "run", fake_run)
    assert windows_eventlog.collect_security_events() == ([], 250)


def test_queue_persists_events_and_checkpoint_atomically(tmp_path):
    queue = EventQueue(tmp_path / "queue.sqlite3")
    event = {"event_uid": str(uuid.uuid4()), "event_type": "login.failed"}

    queue.add_batch_and_checkpoint([event], 125)
    assert queue.pending() == [event]
    assert queue.security_checkpoint() == 125

    with pytest.raises(ValueError):
        queue.add_batch_and_checkpoint(
            [{"event_type": "invalid"}],
            130,
        )

    assert queue.security_checkpoint() == 125
    assert queue.pending() == [event]


def test_queue_rejects_checkpoint_rollback(tmp_path):
    queue = EventQueue(tmp_path / "queue.sqlite3")
    queue.add_batch_and_checkpoint([], 200)

    with pytest.raises(ValueError):
        queue.add_batch_and_checkpoint([], 100)

    assert queue.security_checkpoint() == 200


def test_security_event_collector_uses_record_checkpoint(monkeypatch):
    import subprocess
    from basesentinel_agent import windows_eventlog

    xml = """<Event><EventData><Data Name="TargetUserName">sample</Data></EventData></Event>"""
    output = {
        "LatestRecordId": 100,
        "Events": [{
            "Id": 4625,
            "RecordId": 91,
            "TimeCreated": "2026-11-17T10:00:00.0000000Z",
            "MachineName": "WORKSTATION",
            "Message": "A sign-in attempt failed.",
            "Xml": xml,
        }],
    }
    captured = {}

    def fake_run(args, **kwargs):
        captured["script"] = args[-1]
        return subprocess.CompletedProcess(args, 0, json.dumps(output), "")

    monkeypatch.setattr(windows_eventlog.subprocess, "run", fake_run)
    events, checkpoint = windows_eventlog.collect_security_events(80)

    assert "EventRecordID > 80" in captured["script"]
    assert checkpoint == 100
    assert len(events) == 1
    assert events[0]["event_type"] == "login.failed"
    assert events[0]["event_data"]["record_id"] == 91


def test_security_event_collector_keeps_checkpoint_when_batch_is_full(monkeypatch):
    import subprocess
    from basesentinel_agent import windows_eventlog

    xml = """<Event><EventData><Data Name="TargetUserName">sample</Data></EventData></Event>"""
    output = {
        "LatestRecordId": 5000,
        "Events": [{
            "Id": 4625,
            "RecordId": 1000,
            "TimeCreated": "2026-11-17T10:00:00Z",
            "MachineName": "WORKSTATION",
            "Message": "A sign-in attempt failed.",
            "Xml": xml,
        }] * windows_eventlog._MAX_BATCH,
    }

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, json.dumps(output), "")

    monkeypatch.setattr(windows_eventlog.subprocess, "run", fake_run)
    events, checkpoint = windows_eventlog.collect_security_events(50)

    assert len(events) == windows_eventlog._MAX_BATCH
    assert checkpoint == 1000
