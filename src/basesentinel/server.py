from __future__ import annotations

import argparse
import logging
import os
import platform
import socket
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from basesentinel_windows.startup import (
    task_exists,
    register_logon_task,
    remove_task,
    run_task,
)


_TASK_NAME = "BaseSentinel Server"


def _windowless_interpreter() -> str:
    executable = Path(sys.executable)
    if os.name == "nt" and executable.name.lower() == "python.exe":
        candidate = executable.with_name("pythonw.exe")
        if candidate.is_file():
            return str(candidate)
    return str(executable)


def _log_path() -> Path:
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("PROGRAMDATA")
    if not root:
        raise RuntimeError("LOCALAPPDATA and PROGRAMDATA are not available for the BaseSentinel server log.")
    directory = Path(root) / "BaseSentinel" / "Logs"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "server.log"


def _configure_logging() -> logging.Logger:
    handler = RotatingFileHandler(
        _log_path(),
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[handler],
        force=True,
    )
    return logging.getLogger("basesentinel.server")


def _validate_server_options(host: str, port: int, threads: int) -> None:
    if not host.strip():
        raise ValueError("Server host must not be empty.")
    if not 1 <= port <= 65535:
        raise ValueError("Server port must be between 1 and 65535.")
    if not 1 <= threads <= 128:
        raise ValueError("Server thread count must be between 1 and 128.")


def run_server(args) -> int:
    _validate_server_options(args.host, args.port, args.threads)
    logger = _configure_logging()
    try:
        from basesentinel import create_app
        from waitress import serve

        app = create_app()
        logger.info(
            "Starting BaseSentinel server on %s:%s with %s worker thread(s).",
            args.host,
            args.port,
            args.threads,
        )
        serve(
            app,
            host=args.host,
            port=args.port,
            threads=args.threads,
            expose_tracebacks=False,
        )
    except KeyboardInterrupt:
        logger.info("BaseSentinel server stopped by the console.")
        return 0
    except Exception:
        logger.exception("BaseSentinel server terminated unexpectedly.")
        return 1
    return 0


def _port_is_listening(host: str, port: int) -> bool:
    probe_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    try:
        with socket.create_connection((probe_host, port), timeout=0.5):
            return True
    except OSError:
        return False


def install_startup(args) -> int:
    try:
        _validate_server_options(args.host, args.port, args.threads)
        executable = _windowless_interpreter()
        register_logon_task(
            _TASK_NAME,
            [
                executable,
                "-m",
                "basesentinel.server",
                "run",
                "--host",
                args.host,
                "--port",
                str(args.port),
                "--threads",
                str(args.threads),
            ],
            working_directory=Path.cwd(),
            description="Start the BaseSentinel server after the current user signs in.",
            restart_on_failure=True,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Could not install BaseSentinel server automatic startup: {exc}")
        return 1

    print("BaseSentinel server automatic startup is installed for the current Windows user.")
    print(f"Server address: {args.host}:{args.port}")
    print(f"Server log: {_log_path()}")
    if _port_is_listening(args.host, args.port):
        print("The configured port is already accepting connections; the server was not started twice.")
    else:
        try:
            run_task(_TASK_NAME)
            print("Windows Task Scheduler was asked to start the server now.")
        except RuntimeError as exc:
            print(f"The startup task is installed, but could not be started now: {exc}")
            print("It will still run at the next Windows sign-in.")
    return 0


def remove_startup(args) -> int:
    try:
        removed = remove_task(_TASK_NAME)
    except RuntimeError as exc:
        print(f"Could not remove BaseSentinel server automatic startup: {exc}")
        return 1

    if removed:
        print("BaseSentinel server automatic startup has been removed.")
        print("An already running server process is not stopped.")
    else:
        print("BaseSentinel server automatic startup was not installed.")
    return 0


def startup_status(args) -> int:
    try:
        installed = task_exists(_TASK_NAME)
    except RuntimeError as exc:
        print(f"Could not read BaseSentinel server startup status: {exc}")
        return 1

    print(f"Automatic startup: {'installed' if installed else 'not installed'}")
    if _port_is_listening(args.host, args.port):
        print(f"TCP port {args.port}: accepting connections")
    else:
        print(f"TCP port {args.port}: not accepting connections")
    print(f"Server log: {_log_path()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="basesentinel-server")
    commands = parser.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser(
        "run",
        help="Run the BaseSentinel web/API server with Waitress.",
    )
    run_parser.add_argument(
        "--host",
        default=os.getenv("BASESENTINEL_SERVER_HOST", "127.0.0.1"),
    )
    run_parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("BASESENTINEL_SERVER_PORT", "5000")),
    )
    run_parser.add_argument("--threads", type=int, default=8)
    run_parser.set_defaults(handler=run_server)

    install_parser = commands.add_parser(
        "startup-install",
        help="Start the BaseSentinel server automatically when Windows boots.",
    )
    install_parser.add_argument(
        "--host",
        default=os.getenv("BASESENTINEL_SERVER_HOST", "127.0.0.1"),
    )
    install_parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("BASESENTINEL_SERVER_PORT", "5000")),
    )
    install_parser.add_argument("--threads", type=int, default=8)
    install_parser.set_defaults(handler=install_startup)

    remove_parser = commands.add_parser(
        "startup-remove",
        help="Remove the server's automatic Windows startup task.",
    )
    remove_parser.set_defaults(handler=remove_startup)

    status_parser = commands.add_parser(
        "startup-status",
        help="Show server automatic startup and TCP port status.",
    )
    status_parser.add_argument(
        "--host",
        default=os.getenv("BASESENTINEL_SERVER_HOST", "127.0.0.1"),
    )
    status_parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("BASESENTINEL_SERVER_PORT", "5000")),
    )
    status_parser.set_defaults(handler=startup_status)
    return parser


def main() -> int:
    if platform.system() != "Windows":
        raise SystemExit("The BaseSentinel Windows server launcher currently supports Windows only.")
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
