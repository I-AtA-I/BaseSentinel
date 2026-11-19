import os
from argparse import Namespace

import pytest

from basesentinel_agent import background


def test_worker_lock_is_exclusive_and_released(tmp_path):
    first = background.try_acquire_worker_lock(tmp_path)
    assert first is not None

    second = background.try_acquire_worker_lock(tmp_path)
    assert second is None

    background.release_worker_lock(first)

    third = background.try_acquire_worker_lock(tmp_path)
    assert third is not None
    background.release_worker_lock(third)


def test_background_status_reports_running_pid(tmp_path):
    lock = background.try_acquire_worker_lock(tmp_path)
    assert lock is not None
    (tmp_path / "agent.pid").write_text("43210", encoding="ascii")

    state = background.background_status(tmp_path)
    assert state == {
        "running": True,
        "pid": 43210,
        "log_path": str(tmp_path / "agent.log"),
    }

    background.release_worker_lock(lock)
    assert background.background_status(tmp_path)["running"] is False


def test_stop_request_signals_worker_and_waits_for_lock_release(
    monkeypatch,
    tmp_path,
):
    lock = background.try_acquire_worker_lock(tmp_path)
    assert lock is not None
    (tmp_path / "agent.pid").write_text("1234", encoding="ascii")

    released = False

    def release_during_wait(_seconds):
        nonlocal released
        if not released:
            released = True
            background.release_worker_lock(lock)

    monkeypatch.setattr(background.time, "sleep", release_during_wait)

    assert background.request_background_stop(tmp_path, timeout=1) is True
    assert (tmp_path / "agent.stop").exists()


def test_start_worker_launches_detached_process_and_waits_for_lock(
    monkeypatch,
    tmp_path,
):
    captured = {}
    acquired = {}

    class FakeProcess:
        pid = 9876

        @staticmethod
        def poll():
            return None

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        acquired["lock"] = background.try_acquire_worker_lock(tmp_path)
        (tmp_path / "agent.pid").write_text("9876", encoding="ascii")
        return FakeProcess()

    monkeypatch.setattr(background.subprocess, "Popen", fake_popen)

    pid = background.start_background_worker(
        batch_size=250,
        interval=30,
        data_dir=tmp_path,
        python_executable="python-test",
    )

    assert pid == 9876
    assert captured["command"][:4] == [
        "python-test",
        "-u",
        "-m",
        "basesentinel_agent.cli",
    ]
    assert "_background-worker" in captured["command"]
    assert "--batch-size" in captured["command"]
    assert "250" in captured["command"]
    assert captured["kwargs"]["stdin"] == background.subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] == background.subprocess.STDOUT
    assert captured["kwargs"]["close_fds"] is True
    assert captured["kwargs"]["stdout"].name.endswith("agent.log")
    if os.name == "nt":
        assert captured["kwargs"]["creationflags"] & background.subprocess.CREATE_NO_WINDOW
        assert captured["kwargs"]["creationflags"] & background.subprocess.DETACHED_PROCESS
    else:
        assert captured["kwargs"]["start_new_session"] is True

    assert background.background_status(tmp_path)["running"] is True
    background.release_worker_lock(acquired["lock"])


def test_start_worker_rejects_second_instance(monkeypatch, tmp_path):
    lock = background.try_acquire_worker_lock(tmp_path)
    assert lock is not None
    (tmp_path / "agent.pid").write_text("54321", encoding="ascii")

    monkeypatch.setattr(
        background.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("A second worker must not be spawned."),
    )

    with pytest.raises(RuntimeError, match="already running"):
        background.start_background_worker(data_dir=tmp_path)

    background.release_worker_lock(lock)


def test_background_worker_releases_lock_and_pid_file(monkeypatch, tmp_path):
    from basesentinel_agent import cli

    monkeypatch.setattr(cli, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(
        cli,
        "_run_loop",
        lambda _args, stop_event, mode: (
            stop_event.is_set() is False and mode == "running in background" and 0
        ),
    )

    result = cli.background_worker(Namespace(interval=60, batch_size=500))

    assert result == 0
    assert not (tmp_path / "agent.pid").exists()
    assert background.background_status(tmp_path)["running"] is False


def test_background_commands_are_available_and_have_safe_defaults():
    from basesentinel_agent.cli import build_parser

    parser = build_parser()
    start = parser.parse_args(["start"])
    stop = parser.parse_args(["stop"])
    status = parser.parse_args(["background-status"])
    worker = parser.parse_args(["_background-worker"])

    assert start.interval == 60.0
    assert start.batch_size == 500
    assert stop.timeout == 60.0
    assert status.handler.__name__ == "background_status_command"
    assert worker.handler.__name__ == "background_worker"
