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
        assert captured["kwargs"]["creationflags"] & getattr(
            background.subprocess,
            "CREATE_BREAKAWAY_FROM_JOB",
            0x01000000,
        )
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



def test_windows_lock_modes_use_shared_status_and_exclusive_worker_locks(
    monkeypatch,
    tmp_path,
):
    import os as real_os
    from types import SimpleNamespace

    held = []
    requested_modes = []

    def fake_windows_lock(handle, *, shared):
        requested_modes.append(shared)
        if any(not existing_shared for existing_shared, _ in held):
            handle.close()
            return None
        if not shared and held:
            handle.close()
            return None
        held.append((shared, handle))
        return handle

    def fake_release(handle):
        held[:] = [(shared, current) for shared, current in held if current is not handle]
        handle.close()

    monkeypatch.setattr(
        background,
        "os",
        SimpleNamespace(name="nt", SEEK_END=real_os.SEEK_END),
    )
    monkeypatch.setattr(background, "_try_acquire_windows_file_lock", fake_windows_lock)
    monkeypatch.setattr(background, "release_worker_lock", fake_release)

    first_reader = background._try_acquire_status_lock(tmp_path)
    second_reader = background._try_acquire_status_lock(tmp_path)
    assert first_reader is not None
    assert second_reader is not None

    # A third status check must not mistake the other readers for a worker.
    status_probe = background._try_acquire_status_lock(tmp_path)
    assert status_probe is not None
    fake_release(status_probe)

    # The exclusive worker lock must still conflict with all status readers.
    assert background.try_acquire_worker_lock(tmp_path) is None
    fake_release(first_reader)
    fake_release(second_reader)

    worker = background.try_acquire_worker_lock(tmp_path)
    assert worker is not None
    assert background._try_acquire_status_lock(tmp_path) is None
    fake_release(worker)

    assert requested_modes == [True, True, True, False, False, True, False]

def test_event_workspace_sidebar_items_are_interactive():
    from pathlib import Path

    source_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "basesentinel_agent"
        / "gui.py"
    )
    source = source_path.read_text(encoding="utf-8")
    compile(source, str(source_path), "exec")

    assert 'self._side_item("⌁", "Event collection", target="collection")' in source
    assert 'self._side_item("▤", "Local event queue", target="queue")' in source
    assert "command=lambda: self._navigate_to(target)" in source
    assert "ttk.Treeview(" in source
    assert "command=self.drain_backlog" in source
    assert source.count("self._build_activity_card(body)") == 1



def test_start_worker_accepts_windows_venv_redirector_child(
    monkeypatch,
    tmp_path,
):
    from types import SimpleNamespace

    import os as real_os

    held = []

    def fake_windows_lock(handle, *, shared):
        if held:
            handle.close()
            return None
        held.append(handle)
        return handle

    def fake_release(handle):
        held.remove(handle)
        handle.close()

    class FakeProcess:
        pid = 27412

        @staticmethod
        def poll():
            return None

    def fake_popen(_command, **_kwargs):
        lock = background.try_acquire_worker_lock(tmp_path)
        assert lock is not None
        (tmp_path / "agent.pid").write_text("28872", encoding="ascii")
        return FakeProcess()

    monkeypatch.setattr(
        background,
        "os",
        SimpleNamespace(name="nt", SEEK_END=real_os.SEEK_END),
    )
    monkeypatch.setattr(background, "_try_acquire_windows_file_lock", fake_windows_lock)
    monkeypatch.setattr(background, "release_worker_lock", fake_release)
    monkeypatch.setattr(
        background,
        "_is_windows_process_descendant",
        lambda ancestor_pid, process_pid: (
            ancestor_pid == 27412 and process_pid == 28872
        ),
    )
    monkeypatch.setattr(background.subprocess, "Popen", fake_popen)

    try:
        pid = background.start_background_worker(data_dir=tmp_path)
        assert pid == 28872
    finally:
        if held:
            held.pop().close()


def test_start_worker_rejects_unrelated_windows_worker_pid(
    monkeypatch,
    tmp_path,
):
    from types import SimpleNamespace

    import os as real_os

    held = []

    def fake_windows_lock(handle, *, shared):
        if held:
            handle.close()
            return None
        held.append(handle)
        return handle

    def fake_release(handle):
        held.remove(handle)
        handle.close()

    class FakeProcess:
        pid = 27412

        @staticmethod
        def poll():
            return None

    def fake_popen(_command, **_kwargs):
        lock = background.try_acquire_worker_lock(tmp_path)
        assert lock is not None
        (tmp_path / "agent.pid").write_text("99999", encoding="ascii")
        return FakeProcess()

    monkeypatch.setattr(
        background,
        "os",
        SimpleNamespace(name="nt", SEEK_END=real_os.SEEK_END),
    )
    monkeypatch.setattr(background, "_try_acquire_windows_file_lock", fake_windows_lock)
    monkeypatch.setattr(background, "release_worker_lock", fake_release)
    monkeypatch.setattr(
        background,
        "_is_windows_process_descendant",
        lambda _ancestor_pid, _process_pid: False,
    )
    monkeypatch.setattr(background.subprocess, "Popen", fake_popen)

    try:
        with pytest.raises(RuntimeError, match="started at the same time"):
            background.start_background_worker(data_dir=tmp_path)
    finally:
        if held:
            held.pop().close()
