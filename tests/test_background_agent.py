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
    def fake_run_loop(_args, stop_event, mode):
        assert stop_event.is_set() is False
        assert mode == "running in background"
        return 0

    monkeypatch.setattr(cli, "_run_loop", fake_run_loop)

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


def test_run_cycle_skips_collection_when_stop_arrives_after_heartbeat(monkeypatch):
    import threading
    from basesentinel_agent import cli

    stop_event = threading.Event()

    class FakeClient:
        def identity(self):
            stop_event.set()

    class FakeQueue:
        def __len__(self):
            return 7

        @staticmethod
        def security_checkpoint():
            return 123

    monkeypatch.setattr(
        cli,
        "_collect_and_send",
        lambda *_args, **_kwargs: pytest.fail("Collection must not start after stop."),
    )

    result = cli._run_cycle(FakeClient(), FakeQueue(), 500, stop_event=stop_event)
    assert result == (0, 0, 7, 123)


def test_console_python_executable_prefers_python_exe_for_pythonw(monkeypatch, tmp_path):
    pythonw = tmp_path / "pythonw.exe"
    python = tmp_path / "python.exe"
    pythonw.touch()
    python.touch()
    from types import SimpleNamespace
    monkeypatch.setattr(background, "os", SimpleNamespace(name="nt"))

    assert background.console_python_executable(str(pythonw)) == str(python)


def test_windowed_gui_entrypoint_is_registered_and_module_compiles():
    import tomllib
    from pathlib import Path

    repository_root = Path(__file__).resolve().parents[1]
    project = tomllib.loads(
        (repository_root / "pyproject.toml").read_text(encoding="utf-8")
    )
    gui_script = project["project"]["gui-scripts"]["basesentinel-agent-gui"]
    assert gui_script == "basesentinel_agent.gui:main"

    gui_source = (
        repository_root / "src" / "basesentinel_agent" / "gui.py"
    ).read_text(encoding="utf-8")
    compile(gui_source, "basesentinel_agent/gui.py", "exec")



def test_status_checks_use_shared_locks_and_do_not_contend_with_each_other(tmp_path):
    first_reader = background._try_acquire_status_lock(tmp_path)
    second_reader = background._try_acquire_status_lock(tmp_path)
    assert first_reader is not None
    assert second_reader is not None

    # Another status probe must also be able to read while existing probes run.
    assert background.background_status(tmp_path)["running"] is False

    # A real worker's exclusive lock must exclude status probes.
    background.release_worker_lock(first_reader)
    background.release_worker_lock(second_reader)
    worker = background.try_acquire_worker_lock(tmp_path)
    assert worker is not None
    assert background._try_acquire_status_lock(tmp_path) is None
    assert background.background_status(tmp_path)["running"] is True
    background.release_worker_lock(worker)
