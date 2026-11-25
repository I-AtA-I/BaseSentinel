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
    admin_install = parser.parse_args(["startup-install-admin", "--bootstrap-file", "handoff.json"])
    assert admin_install.handler is cli.install_startup_admin
    assert admin_install.result_file is None
    assert parser.parse_args(["startup-remove-admin"]).handler is cli.remove_startup_admin
    assert parser.parse_args(["startup-stop-admin"]).handler is not None


def test_install_startup_requests_system_wide_install(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
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


def test_scheduled_agent_start_is_silent_and_skips_an_existing_worker(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
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
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
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


def test_unprivileged_startup_install_requests_visible_uac_approval(
    monkeypatch,
    tmp_path,
    capsys,
):
    from basesentinel_agent import system_install

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    bootstrap = tmp_path / "bootstrap.json"
    bootstrap.write_text("temporary", encoding="utf-8")
    captured = {}

    monkeypatch.setattr(
        cli.AgentConfigStore,
        "load",
        lambda self: {
            "server_url": "https://siem.example.com",
            "agent_id": "agent-123",
            "token": "token",
        },
    )
    monkeypatch.setattr(cli, "background_status", lambda: {"running": False, "pid": None})
    monkeypatch.setattr(cli, "is_admin", lambda: False)
    result_file = tmp_path / "bootstrap.result.log"
    monkeypatch.setattr(system_install, "create_admin_bootstrap", lambda config: bootstrap)
    monkeypatch.setattr(
        system_install,
        "create_admin_result_file",
        lambda _bootstrap: result_file,
    )
    monkeypatch.setattr(cli, "run_elevated", lambda command: captured.update(command=command))

    result = cli.install_startup(Namespace(interval=45.0, batch_size=300))

    assert result == 0
    assert captured["command"][0] == cli.sys.executable
    assert "startup-install-admin" in captured["command"]
    assert "--bootstrap-file" in captured["command"]
    assert str(bootstrap) in captured["command"]
    assert "--result-file" in captured["command"]
    assert str(result_file) in captured["command"]
    assert "BASESENTINEL_INSTALL_RESULT_FILE=" + str(result_file) in capsys.readouterr().out
    assert "--interval" in captured["command"]
    assert "45.0" in captured["command"]
    assert "--batch-size" in captured["command"]
    assert "300" in captured["command"]
    assert bootstrap.exists()
    bootstrap.unlink()



def test_elevated_system_install_writes_result_log_and_removes_bootstrap(
    monkeypatch,
    tmp_path,
):
    from basesentinel_agent import system_install

    bootstrap = tmp_path / "bootstrap.json"
    bootstrap.write_text("temporary", encoding="utf-8")
    result_file = tmp_path / "bootstrap.result.log"
    monkeypatch.setattr(
        system_install,
        "read_admin_bootstrap",
        lambda _path: {
            "server_url": "https://siem.example.com",
            "agent_id": "agent-123",
            "token": "token",
        },
    )
    monkeypatch.setattr(cli, "is_admin", lambda: True)
    monkeypatch.setattr(
        cli,
        "_finish_system_install",
        lambda config, args: print("SYSTEM installation completed") or 0,
    )

    result = cli.install_startup_admin(
        Namespace(
            bootstrap_file=str(bootstrap),
            result_file=str(result_file),
            interval=60.0,
            batch_size=500,
        )
    )

    output = result_file.read_text(encoding="utf-8")
    assert result == 0
    assert "SYSTEM installation completed" in output
    assert "BASESENTINEL_INSTALL_EXIT_CODE=0" in output
    assert not bootstrap.exists()



def test_restore_user_worker_skips_when_system_task_exists(monkeypatch, capsys):
    monkeypatch.setattr(cli, "is_system_boot_task", lambda _name: True)
    started = []
    monkeypatch.setattr(
        cli,
        "start_background_worker",
        lambda **kwargs: started.append(kwargs),
    )

    result = cli.restore_user_worker(
        Namespace(interval=30.0, batch_size=250)
    )

    assert result == 0
    assert started == []
    assert "system-wide collector is registered" in capsys.readouterr().out


def test_restore_user_worker_starts_previous_collector_when_system_task_is_absent(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(cli, "is_system_boot_task", lambda _name: False)
    monkeypatch.setattr(
        cli.AgentConfigStore,
        "load",
        lambda self: {"server_url": "https://siem.example.com"},
    )
    monkeypatch.setattr(
        cli,
        "background_status",
        lambda: {"running": False, "pid": None},
    )
    started = []
    monkeypatch.setattr(
        cli,
        "start_background_worker",
        lambda **kwargs: started.append(kwargs) or 1234,
    )

    result = cli.restore_user_worker(
        Namespace(interval=30.0, batch_size=250)
    )

    assert result == 0
    assert started == [{"batch_size": 250, "interval": 30.0}]
    assert "restored (PID 1234)" in capsys.readouterr().out
