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

    assert "$checkpoint = 80" in captured["script"]
    assert "EventRecordID > $checkpoint" in captured["script"]
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


def test_run_command_defaults_to_sixty_second_interval():
    from basesentinel_agent.cli import build_parser

    args = build_parser().parse_args(["run"])
    assert args.interval == 60.0
    assert args.batch_size == 500

    collect_args = build_parser().parse_args(["collect"])
    assert collect_args.batch_size == 500

    drain_args = build_parser().parse_args(["drain"])
    assert drain_args.batch_size == 500


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "not-a-number"])
def test_run_command_rejects_invalid_intervals(value):
    from basesentinel_agent.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["run", "--interval", value])


def test_run_cycle_sends_heartbeat_before_collecting(monkeypatch):
    from basesentinel_agent import cli

    calls = []

    class FakeClient:
        def identity(self):
            calls.append("heartbeat")

    class FakeQueue:
        pass

    def fake_collect_and_send(client, queue, batch_size):
        calls.append(("collect", batch_size))
        return 2, 2, 0, 150

    monkeypatch.setattr(cli, "_collect_and_send", fake_collect_and_send)
    result = cli._run_cycle(FakeClient(), FakeQueue(), 25)

    assert result == (2, 2, 0, 150)
    assert calls == ["heartbeat", ("collect", 25)]


def test_run_stops_cleanly_on_keyboard_interrupt(monkeypatch, capsys):
    from argparse import Namespace
    from basesentinel_agent import cli

    class FakeClient:
        pass

    class FakeQueue:
        pass

    class InteractiveInput:
        @staticmethod
        def isatty():
            return True

    class FakeStopEvent:
        @staticmethod
        def is_set():
            return False

        @staticmethod
        def wait(interval):
            assert interval == 30
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_client_from_config", lambda: FakeClient())
    monkeypatch.setattr(cli, "_queue", lambda: FakeQueue())
    monkeypatch.setattr(cli, "_run_cycle", lambda *args, **kwargs: (0, 0, 0, 0))
    monkeypatch.setattr(cli.sys, "stdin", InteractiveInput())
    monkeypatch.setattr(cli.threading, "Event", FakeStopEvent)

    assert cli.run(Namespace(interval=30, batch_size=500)) == 0
    assert "agent stopped" in capsys.readouterr().out


def test_run_stops_when_gui_closes_stdin_pipe(monkeypatch, capsys):
    import io
    from argparse import Namespace
    from basesentinel_agent import cli

    class FakeClient:
        pass

    class FakeQueue:
        pass

    monkeypatch.setattr(cli, "_client_from_config", lambda: FakeClient())
    monkeypatch.setattr(cli, "_queue", lambda: FakeQueue())
    monkeypatch.setattr(cli, "_run_cycle", lambda *args, **kwargs: (0, 0, 0, 0))
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("\\n"))

    assert cli.run(Namespace(interval=30, batch_size=500)) == 0
    assert "agent stopped" in capsys.readouterr().out


@pytest.mark.parametrize("value", ["0", "501", "-1", "not-a-number"])
def test_cli_rejects_invalid_batch_size(value):
    from basesentinel_agent.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["collect", "--batch-size", value])


def test_collection_pipeline_keeps_events_queued_when_stop_is_requested(
    monkeypatch,
    tmp_path,
):
    import threading
    from basesentinel_agent import cli

    queue = EventQueue(tmp_path / "events.sqlite3")
    event = {"event_uid": str(uuid.uuid4()), "event_type": "login.failed"}
    stop_event = threading.Event()
    stop_event.set()

    class FakeClient:
        def send_event(self, _event):
            raise AssertionError("No event should be sent after stop is requested.")

    monkeypatch.setattr(
        cli,
        "collect_security_events",
        lambda checkpoint: ([event], 300),
    )

    result = cli._collect_and_send(
        FakeClient(),
        queue,
        batch_size=500,
        stop_event=stop_event,
    )

    assert result == (1, 0, 1, 300)
    assert queue.pending() == [event]


def test_drain_sends_existing_queue_without_collecting_new_events(
    monkeypatch,
    tmp_path,
    capsys,
):
    from argparse import Namespace
    from basesentinel_agent import cli

    queue = EventQueue(tmp_path / "events.sqlite3")
    event = {"event_uid": str(uuid.uuid4()), "event_type": "login.failed"}
    queue.add(event)
    delivered = []

    class FakeClient:
        def send_event(self, queued_event):
            delivered.append(queued_event)
            return {"event_uid": queued_event["event_uid"]}

    monkeypatch.setattr(cli, "_client_from_config", lambda: FakeClient())
    monkeypatch.setattr(cli, "_queue", lambda: queue)
    monkeypatch.setattr(
        cli,
        "collect_security_events",
        lambda *_args: pytest.fail("Drain must not read the Windows event log."),
    )

    assert cli.drain(Namespace(batch_size=500)) == 0
    assert delivered == [event]
    assert queue.pending() == []
    assert "Delivered 1 queued event(s); pending 0." in capsys.readouterr().out



def test_successful_logon_is_informational_level_zero(monkeypatch):
    import subprocess
    from basesentinel_agent import windows_eventlog

    output = {
        "LatestRecordId": 120,
        "Events": [{
            "Id": 4624,
            "RecordId": 120,
            "TimeCreated": "2026-11-19T10:00:00Z",
            "MachineName": "WORKSTATION",
            "Message": "An account was successfully logged on.",
            "Xml": "<Event><EventData><Data Name=\"TargetUserName\">sample</Data></EventData></Event>",
        }],
    }

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, json.dumps(output), "")

    monkeypatch.setattr(windows_eventlog.subprocess, "run", fake_run)
    events, checkpoint = windows_eventlog.collect_security_events()

    assert checkpoint == 120
    assert len(events) == 1
    assert events[0]["event_type"] == "login.success"
    assert events[0]["severity"] == 0
