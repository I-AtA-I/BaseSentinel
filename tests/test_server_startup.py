from argparse import Namespace

from basesentinel import server


def test_server_parser_has_foreground_and_startup_commands():
    parser = server.build_parser()

    run_args = parser.parse_args(["run"])
    install_args = parser.parse_args(["startup-install", "--host", "127.0.0.1", "--port", "5055"])
    remove_args = parser.parse_args(["startup-remove"])
    status_args = parser.parse_args(["startup-status"])

    assert run_args.host == "127.0.0.1"
    assert run_args.port == 5000
    assert run_args.threads == 8
    assert run_args.handler is server.run_server
    assert install_args.host == "127.0.0.1"
    assert install_args.port == 5055
    assert install_args.handler is server.install_startup
    assert remove_args.handler is server.remove_startup
    assert status_args.handler is server.startup_status


def test_server_options_are_validated():
    server._validate_server_options("127.0.0.1", 5050, 8)

    for host, port, threads, message in [
        ("", 5050, 8, "host"),
        ("127.0.0.1", 0, 8, "port"),
        ("127.0.0.1", 5050, 0, "thread"),
    ]:
        try:
            server._validate_server_options(host, port, threads)
        except ValueError as exc:
            assert message in str(exc)
        else:
            raise AssertionError("Invalid server options must be rejected.")


def test_server_startup_registers_background_task(monkeypatch, tmp_path):
    captured = []

    monkeypatch.setattr(server, "_windowless_interpreter", lambda: r"C:\venv\Scripts\pythonw.exe")
    monkeypatch.setattr(server, "_log_path", lambda: tmp_path / "server.log")
    monkeypatch.setattr(server, "_port_is_listening", lambda _host, _port: False)
    monkeypatch.setattr(
        server,
        "register_logon_task",
        lambda name, command, **kwargs: captured.append((name, command, kwargs)),
    )
    monkeypatch.setattr(server, "run_task", lambda name: captured.append(("run", name)))

    result = server.install_startup(Namespace(host="127.0.0.1", port=5050, threads=4))

    assert result == 0
    name, command, options = captured[0]
    assert name == "BaseSentinel Server"
    assert command == [
        r"C:\venv\Scripts\pythonw.exe",
        "-m",
        "basesentinel.server",
        "run",
        "--host",
        "127.0.0.1",
        "--port",
        "5050",
        "--threads",
        "4",
    ]
    assert options["working_directory"]
    assert options["restart_on_failure"] is True
    assert captured[1] == ("run", "BaseSentinel Server")


def test_server_startup_status_reports_task_and_listener(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(server, "task_exists", lambda _name: True)
    monkeypatch.setattr(server, "_port_is_listening", lambda _host, _port: True)
    monkeypatch.setattr(server, "_log_path", lambda: tmp_path / "server.log")

    result = server.startup_status(Namespace(host="127.0.0.1", port=5050))

    assert result == 0
    output = capsys.readouterr().out
    assert "installed" in output
    assert "accepting connections" in output
