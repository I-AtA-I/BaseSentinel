from argparse import Namespace

from basesentinel_agent import cli


def test_agent_startup_commands_are_available_with_safe_defaults():
    parser = cli.build_parser()

    install = parser.parse_args(["startup-install"])
    remove = parser.parse_args(["startup-remove"])
    status = parser.parse_args(["startup-status"])

    assert install.interval == 60.0
    assert install.batch_size == 500
    assert install.handler is cli.install_startup
    assert remove.handler is cli.remove_startup
    assert status.handler is cli.startup_status


def test_install_startup_registers_logon_task_and_starts_collector(monkeypatch, tmp_path):
    captured = {}

    monkeypatch.setattr(cli.AgentConfigStore, "load", lambda self: {"agent_id": "agent-1"})
    monkeypatch.setattr(cli, "windowless_python_executable", lambda: r"C:\venv\Scripts\pythonw.exe")
    monkeypatch.setattr(cli, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(cli, "background_status", lambda: {"running": False, "pid": None})
    monkeypatch.setattr(
        cli,
        "register_logon_task",
        lambda name, command, **kwargs: captured.update(
            name=name,
            command=command,
            options=kwargs,
        ),
    )
    monkeypatch.setattr(
        cli,
        "start_background_worker",
        lambda **kwargs: captured.update(start_options=kwargs) or 3210,
    )

    result = cli.install_startup(Namespace(interval=30.0, batch_size=250))

    assert result == 0
    assert captured["name"] == "BaseSentinel Agent"
    assert captured["command"] == [
        r"C:\venv\Scripts\pythonw.exe",
        "-m",
        "basesentinel_agent.cli",
        "start",
        "--interval",
        "30.0",
        "--batch-size",
        "250",
    ]
    assert captured["options"]["working_directory"] == tmp_path
    assert captured["start_options"] == {"batch_size": 250, "interval": 30.0}


def test_remove_agent_startup_does_not_stop_running_worker(monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr(cli, "remove_logon_task", lambda name: captured.setdefault("name", name) or True)

    result = cli.remove_startup(Namespace())

    assert result == 0
    assert captured["name"] == "BaseSentinel Agent"
    assert "not stopped" in capsys.readouterr().out
