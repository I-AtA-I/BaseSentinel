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
    silent_start = parser.parse_args(["startup-run"])
    assert silent_start.handler is cli.startup_launch
    service_start = parser.parse_args(["startup-service-run"])
    assert service_start.handler is cli.startup_service_run
    assert parser.parse_args(["startup-install-admin", "--bootstrap-file", "handoff.json"]).handler is cli.install_startup_admin
    assert parser.parse_args(["startup-remove-admin"]).handler is cli.remove_startup_admin
    assert parser.parse_args(["startup-stop-admin"]).handler is not None


def test_install_startup_requests_system_wide_install(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        cli.AgentConfigStore,
        "load",
        lambda self: {
            "server_url": "https://siem.example.com",
            "agent_id": "agent-1",
            "token": "token",
        },
    )
    monkeypatch.setattr(cli, "background_status", lambda: {"running": False, "pid": None})
    monkeypatch.setattr(cli, "is_admin", lambda: True)
    monkeypatch.setattr(
        cli,
        "_finish_system_install",
        lambda config, args: captured.update(config=config, args=args) or 0,
    )

    args = Namespace(interval=30.0, batch_size=250)
    result = cli.install_startup(args)

    assert result == 0
    assert captured["config"]["agent_id"] == "agent-1"
    assert captured["args"] is args


def test_remove_agent_startup_removes_system_task_and_retains_data(monkeypatch, capsys):
    from basesentinel_agent import system_install

    monkeypatch.setattr(cli, "is_admin", lambda: True)
    monkeypatch.setattr(system_install, "remove_system_agent_startup", lambda: True)

    result = cli.remove_startup(Namespace())

    assert result == 0
    output = capsys.readouterr().out
    assert "automatic startup has been removed" in output
    assert "data were retained" in output


def test_scheduled_agent_start_is_silent_and_skips_an_existing_worker(monkeypatch):
    started = []
    monkeypatch.setattr(cli.AgentConfigStore, "load", lambda self: {"agent_id": "agent-1"})
    monkeypatch.setattr(cli, "background_status", lambda: {"running": True, "pid": 42})
    monkeypatch.setattr(
        cli,
        "start_background_worker",
        lambda **kwargs: started.append(kwargs),
    )

    result = cli.startup_launch(Namespace(interval=60.0, batch_size=500))

    assert result == 0
    assert started == []


def test_scheduled_agent_start_logs_launch_errors_without_console_output(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(cli.AgentConfigStore, "load", lambda self: {"agent_id": "agent-1"})
    monkeypatch.setattr(cli, "default_data_dir", lambda: tmp_path)
    monkeypatch.setattr(cli, "background_status", lambda: {"running": False})
    monkeypatch.setattr(
        cli,
        "start_background_worker",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("worker failed")),
    )

    result = cli.startup_launch(Namespace(interval=60.0, batch_size=500))

    assert result == 1
    assert "Automatic startup failed: worker failed" in (tmp_path / "agent.log").read_text()
