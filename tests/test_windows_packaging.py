from __future__ import annotations

import queue
import subprocess

from basesentinel_agent import background, cli, system_install


def test_packaged_background_worker_uses_agent_cli_executable(tmp_path, monkeypatch):
    agent_executable = tmp_path / "BaseSentinelAgent.exe"
    agent_executable.write_bytes(b"placeholder")
    monkeypatch.setattr(background.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        background.sys,
        "executable",
        str(tmp_path / "BaseSentinelEndpoint.exe"),
    )

    command = background._background_worker_command(
        interval=60,
        batch_size=500,
    )

    assert command == [
        str(agent_executable),
        "_background-worker",
        "--interval",
        "60",
        "--batch-size",
        "500",
    ]


def test_packaged_gui_cli_command_uses_bundled_agent_executable(tmp_path, monkeypatch):
    agent_executable = tmp_path / "BaseSentinelAgent.exe"
    agent_executable.write_bytes(b"placeholder")
    monkeypatch.setattr(background.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        background.sys,
        "executable",
        str(tmp_path / "BaseSentinelEndpoint.exe"),
    )

    assert background.agent_cli_command("diagnostics") == [
        str(agent_executable),
        "diagnostics",
    ]


def test_source_gui_cli_command_uses_python_module(monkeypatch):
    monkeypatch.setattr(background.sys, "frozen", False, raising=False)
    monkeypatch.setattr(background.sys, "executable", r"C:\Python\python.exe")

    assert background.agent_cli_command("diagnostics") == [
        r"C:\Python\python.exe",
        "-u",
        "-m",
        "basesentinel_agent.cli",
        "diagnostics",
    ]


def test_packaged_cli_elevation_relaunches_executable_directly(monkeypatch):
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "executable", r"C:\Program Files\BaseSentinel\BaseSentinelAgent.exe")

    assert cli._cli_command("startup-remove-admin") == [
        r"C:\Program Files\BaseSentinel\BaseSentinelAgent.exe",
        "startup-remove-admin",
    ]


def test_source_cli_elevation_uses_python_module(monkeypatch):
    monkeypatch.setattr(cli.sys, "frozen", False, raising=False)
    monkeypatch.setattr(cli.sys, "executable", r"C:\Python\python.exe")

    assert cli._cli_command("startup-remove-admin") == [
        r"C:\Python\python.exe",
        "-m",
        "basesentinel_agent.cli",
        "startup-remove-admin",
    ]


def test_packaged_system_install_copies_worker_executable(tmp_path, monkeypatch):
    install_directory = tmp_path / "Program Files" / "BaseSentinel"
    install_directory.mkdir(parents=True)
    worker_source = install_directory / "BaseSentinelAgentWorker.exe"
    worker_source.write_bytes(b"worker-placeholder")
    monkeypatch.setattr(system_install.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        system_install.sys,
        "executable",
        str(install_directory / "BaseSentinelAgent.exe"),
    )
    destination = tmp_path / "Runtime"
    destination.mkdir()

    system_install._copy_runtime(destination)

    copied_worker = destination / "BaseSentinelAgentWorker.exe"
    assert copied_worker.read_bytes() == b"worker-placeholder"



def test_gui_runtime_status_refresh_dispatches_work_to_a_background_thread(monkeypatch):
    from basesentinel_agent import gui

    calls = {}

    class FakeThread:
        def __init__(self, *, target, name, daemon):
            calls["target"] = target
            calls["name"] = name
            calls["daemon"] = daemon

        def start(self):
            calls["started"] = True

    app = gui.AgentWindow.__new__(gui.AgentWindow)
    app.closing = False
    app.runtime_check_running = False
    monkeypatch.setattr(gui.threading, "Thread", FakeThread)

    app._refresh_runtime_state()

    assert app.runtime_check_running is True
    assert calls["started"] is True
    assert calls["name"] == "BaseSentinelRuntimeStatus"
    assert calls["daemon"] is True
    assert calls["target"].__self__ is app


def test_gui_runtime_status_worker_returns_status_without_touching_tk(monkeypatch, tmp_path):
    from basesentinel_agent import gui

    class FakeQueue:
        def __len__(self):
            return 7

    app = gui.AgentWindow.__new__(gui.AgentWindow)
    app.messages = queue.Queue()
    monkeypatch.setattr(gui, "is_system_boot_task", lambda _name: False)
    monkeypatch.setattr(
        gui,
        "background_status",
        lambda: {"running": True, "pid": 1234},
    )
    monkeypatch.setattr(gui, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(gui, "EventQueue", lambda _path: FakeQueue())

    app._runtime_state_worker()

    kind, payload = app.messages.get_nowait()
    assert kind == "runtime_state"
    assert payload == {
        "system_wide": False,
        "running": True,
        "pid": 1234,
        "pending": 7,
    }


def test_task_scheduler_command_times_out_instead_of_waiting_forever(monkeypatch):
    from basesentinel_windows import startup

    monkeypatch.setattr(
        startup,
        "windows_system_executable",
        lambda _name: "C:/Windows/System32/schtasks.exe",
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        raise subprocess.TimeoutExpired(command, timeout=5)

    monkeypatch.setattr(startup.subprocess, "run", fake_run)

    try:
        startup._run_schtasks(["/Query", "/TN", "BaseSentinel Agent"])
    except RuntimeError as exc:
        assert "within 5 seconds" in str(exc)
    else:
        raise AssertionError("A Task Scheduler timeout must be reported.")

    assert calls[0][1]["timeout"] == 5
