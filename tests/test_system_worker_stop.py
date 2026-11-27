from __future__ import annotations

import pytest

from basesentinel_agent import background, system_install
from basesentinel_windows import startup


@pytest.fixture
def worker(monkeypatch, tmp_path):
    """Fake a system-wide worker: state['running'] is the single-instance lock."""
    state = {
        "running": True,
        "pid": 4321,
        "task_running": True,
        "ended": 0,
        "killed": [],
        "graceful_works": False,
        "kill_works": True,
    }
    monkeypatch.setattr(system_install, "machine_data_dir", lambda: tmp_path)

    def request_stop(data_dir, timeout=20.0):
        assert data_dir == tmp_path
        if not state["running"]:
            return False
        if state["graceful_works"]:
            state["running"] = False
            state["task_running"] = False
            return True
        raise TimeoutError("did not stop")

    def end_task(name):
        state["ended"] += 1
        state["task_running"] = False
        return True

    def terminate(pid):
        state["killed"].append(pid)
        if state["kill_works"]:
            state["running"] = False

    monkeypatch.setattr(background, "request_background_stop", request_stop)
    monkeypatch.setattr(
        background,
        "background_status",
        lambda data_dir=None: {
            "running": state["running"],
            "pid": state["pid"] if state["running"] else None,
            "log_path": "",
        },
    )
    monkeypatch.setattr(startup, "task_exists", lambda name: True)
    monkeypatch.setattr(startup, "is_task_running", lambda name: state["task_running"])
    monkeypatch.setattr(startup, "end_task", end_task)
    monkeypatch.setattr(startup, "terminate_process_tree", terminate)
    return state


def test_graceful_stop_needs_no_kill(worker):
    worker["graceful_works"] = True

    assert system_install.stop_system_worker() is True
    assert worker["ended"] == 0
    assert worker["killed"] == []


def test_orphaned_child_is_killed_after_task_end(worker):
    # schtasks /End ends the task, but the PyInstaller child keeps the lock.
    assert system_install.stop_system_worker(kill_timeout=1) is True
    assert worker["ended"] == 1
    assert worker["killed"] == [4321]
    assert worker["running"] is False


def test_nothing_running_does_nothing(worker):
    worker["running"] = False
    worker["task_running"] = False

    assert system_install.stop_system_worker() is False
    assert worker["ended"] == 0
    assert worker["killed"] == []


def test_failure_to_stop_is_reported(worker):
    worker["kill_works"] = False

    with pytest.raises(RuntimeError, match="did not stop"):
        system_install.stop_system_worker(kill_timeout=0.3)


def test_terminate_process_tree_accepts_already_exited_process(monkeypatch):
    import subprocess

    monkeypatch.setattr(startup, "_require_windows", lambda: None)
    captured = {}

    def fake_run(arguments, **kwargs):
        captured["arguments"] = arguments
        return subprocess.CompletedProcess(arguments, 128, stdout="", stderr="not found")

    monkeypatch.setattr(startup.subprocess, "run", fake_run)

    startup.terminate_process_tree(4321)

    assert captured["arguments"][1:] == ["/PID", "4321", "/T", "/F"]


def test_terminate_process_tree_reports_real_failures(monkeypatch):
    import subprocess

    monkeypatch.setattr(startup, "_require_windows", lambda: None)
    monkeypatch.setattr(
        startup.subprocess,
        "run",
        lambda arguments, **kwargs: subprocess.CompletedProcess(
            arguments, 1, stdout="", stderr="Access is denied"
        ),
    )

    with pytest.raises(RuntimeError, match="Access is denied"):
        startup.terminate_process_tree(4321)
