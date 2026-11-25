from __future__ import annotations

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
