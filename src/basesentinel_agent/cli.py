from __future__ import annotations

import argparse
import math
import os
import platform
import socket
import sys
import threading
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout

from basesentinel_agent.background import (
    background_status,
    release_worker_lock,
    request_background_stop,
    start_background_worker,
    try_acquire_worker_lock,
    windowless_python_executable,
)
from basesentinel_windows.startup import (
    end_task,
    is_admin,
    is_system_boot_task,
    register_logon_task,
    remove_task,
    run_elevated,
    task_exists,
)
from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.storage import AgentConfigStore, default_data_dir
from basesentinel_agent.windows_eventlog import (
    collect_defender_events,
    collect_security_events,
    ensure_pnp_audit_activity,
)


def _queue() -> EventQueue:
    return EventQueue(default_data_dir() / "events.sqlite3")


def _client_from_config() -> BaseSentinelClient:
    config = AgentConfigStore().load()
    return BaseSentinelClient(config["server_url"], config["token"])


def enroll(args) -> int:
    store = AgentConfigStore()
    client = BaseSentinelClient(args.server)
    result = client.enroll(
        args.pairing_code,
        socket.gethostname(),
        platform.platform()[:80],
        platform.machine()[:32],
    )
    store.save(args.server, result["token"], result["agent_id"])
    print(f"Enrolled successfully. Agent ID: {result['agent_id']}")
    print("The credential is protected with Windows DPAPI for the current user.")
    return 0


_LEGACY_EVENT_CATEGORIES = {
    "audit.policy_changed": ("security", "audit"),
    "security_log.cleared": ("security", "audit"),
    "device.usb_storage_recognized": ("device", "system"),
}


def _normalize_legacy_event_category(event: dict) -> dict:
    """Normalize category aliases stored by older agent versions before delivery."""
    expected = _LEGACY_EVENT_CATEGORIES.get(event.get("event_type"))
    if expected is None or event.get("category") != expected[0]:
        return event
    normalized = dict(event)
    normalized["category"] = expected[1]
    return normalized


def _deliver_pending(
    client: BaseSentinelClient,
    queue: EventQueue,
    batch_size: int,
    stop_event: threading.Event | None = None,
) -> tuple[int, int]:
    """Send a bounded number of queued events and acknowledge successful deliveries."""
    sent = 0
    for event in queue.pending(limit=batch_size):
        if stop_event is not None and stop_event.is_set():
            break
        try:
            client.send_event(_normalize_legacy_event_category(event))
        except AgentApiError as exc:
            if exc.status in (401, 403):
                raise
            print(f"Could not deliver event {event['event_uid']}: HTTP {exc.status}: {exc}")
            continue
        queue.acknowledge(event["event_uid"])
        sent += 1
        if sent % 50 == 0:
            print(f"Delivery progress: acknowledged {sent} event(s) in this batch.")

    return sent, len(queue)


def _collect_and_send(
    client: BaseSentinelClient,
    queue: EventQueue,
    batch_size: int,
    stop_event: threading.Event | None = None,
) -> tuple[int, int, int, int]:
    checkpoint = queue.security_checkpoint()
    discovered: list[dict] = []
    next_checkpoint = checkpoint
    try:
        discovered, next_checkpoint = collect_security_events(checkpoint)
        queue.add_batch_and_checkpoint(discovered, next_checkpoint, channel="security")
    except RuntimeError as exc:
        # Security log access is optional for a standard user account. Keep the
        # checkpoint unchanged so the agent retries if permissions are granted later.
        print(f"Windows Security telemetry unavailable: {exc}")

    defender_discovered = 0
    try:
        defender_checkpoint = queue.defender_checkpoint()
        defender_events, next_defender_checkpoint = collect_defender_events(defender_checkpoint)
        queue.add_batch_and_checkpoint(
            defender_events,
            next_defender_checkpoint,
            channel="defender",
        )
        defender_discovered = len(defender_events)
    except RuntimeError as exc:
        print(f"Microsoft Defender telemetry unavailable: {exc}")

    sent, pending = _deliver_pending(
        client,
        queue,
        batch_size,
        stop_event=stop_event,
    )
    return len(discovered) + defender_discovered, sent, pending, next_checkpoint


def collect(args) -> int:
    try:
        audit_state = ensure_pnp_audit_activity()
        if audit_state == "enabled":
            print("Windows Plug and Play success auditing enabled.")
        elif audit_state == "requires-admin":
            print(
                "USB detection setup skipped: successful Plug and Play auditing "
                "is disabled and requires an administrator to enable."
            )
    except RuntimeError as exc:
        print(f"USB detection setup warning: {exc}")

    client = _client_from_config()
    queue = _queue()
    discovered, sent, pending, checkpoint = _collect_and_send(
        client,
        queue,
        args.batch_size,
    )
    print(
        f"Collected {discovered} event(s); delivered {sent}; "
        f"pending {pending}; Security log checkpoint {checkpoint}."
    )
    return 0


def drain(args) -> int:
    """Deliver already queued events without reading the Windows event log."""
    client = _client_from_config()
    queue = _queue()
    sent, pending = _deliver_pending(
        client,
        queue,
        args.batch_size,
    )
    print(f"Delivered {sent} queued event(s); pending {pending}.")
    return 0


def diagnostics(args) -> int:
    """Check authenticated server access, local queue and Security log access."""
    errors = []

    try:
        client = _client_from_config()
        identity = client.identity()
        print(f"Server connection: OK (authenticated)")
        print(f"Agent identity: {identity['agent_id']} ({identity['status']})")
    except AgentApiError as exc:
        print(f"Server connection: FAILED (HTTP {exc.status}): {exc}")
        errors.append("server")
    except (ConnectionError, RuntimeError, ValueError, OSError) as exc:
        print(f"Server connection: FAILED: {exc}")
        errors.append("server")

    try:
        queue = _queue()
        checkpoint = queue.security_checkpoint()
        pending = len(queue)
        print(f"Local event queue: {pending} pending event(s)")
        print(f"Security log checkpoint: {checkpoint}")

        available, latest_checkpoint = collect_security_events(checkpoint)
        print(
            "Windows Security log: READABLE; "
            f"{len(available)} matching event(s) newer than the checkpoint."
        )
        print(f"Current Security log record: {latest_checkpoint}")
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Windows Security log: FAILED: {exc}")
        errors.append("security-log")

    print("Diagnostics do not upload events or advance the local checkpoint.")
    return 1 if errors else 0


def _run_cycle(
    client: BaseSentinelClient,
    queue: EventQueue,
    batch_size: int,
    stop_event: threading.Event | None = None,
) -> tuple[int, int, int, int]:
    # The authenticated identity request also refreshes the server-side agent heartbeat.
    client.identity()
    if stop_event is not None and stop_event.is_set():
        return 0, 0, len(queue), queue.security_checkpoint()
    if stop_event is None:
        return _collect_and_send(client, queue, batch_size)
    return _collect_and_send(client, queue, batch_size, stop_event=stop_event)


def _positive_interval(value: str) -> float:
    try:
        interval = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "interval must be a number of seconds"
        ) from None
    if not math.isfinite(interval) or interval <= 0:
        raise argparse.ArgumentTypeError(
            "interval must be a finite number greater than zero"
        )
    return interval


def _batch_size(value: str) -> int:
    try:
        batch_size = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "batch size must be an integer between 1 and 500"
        ) from None
    if not 1 <= batch_size <= 500:
        raise argparse.ArgumentTypeError(
            "batch size must be an integer between 1 and 500"
        )
    return batch_size


def _watch_for_stop_request(stream, stop_event: threading.Event) -> None:
    """Stop a foreground run when its parent closes the stdin control pipe."""
    try:
        stream.readline()
    except (OSError, ValueError):
        pass
    finally:
        stop_event.set()


def _run_loop(args, stop_event: threading.Event, mode: str) -> int:
    client = _client_from_config()
    queue = _queue()
    try:
        audit_state = ensure_pnp_audit_activity()
        if audit_state == "enabled":
            print("Windows Plug and Play success auditing enabled.")
        elif audit_state == "requires-admin":
            print(
                "USB detection setup skipped: successful Plug and Play auditing "
                "is disabled and requires an administrator to enable."
            )
    except RuntimeError as exc:
        print(f"USB detection setup warning: {exc}")

    print(
        f"BaseSentinel agent {mode}. Collection interval: "
        f"{args.interval:g}s. Delivery limit: {args.batch_size} event(s) per cycle."
    )

    try:
        while not stop_event.is_set():
            try:
                discovered, sent, pending, checkpoint = _run_cycle(
                    client,
                    queue,
                    args.batch_size,
                    stop_event=stop_event,
                )
                print(
                    f"Heartbeat OK; collected {discovered}; delivered {sent}; "
                    f"pending {pending}; Security log checkpoint {checkpoint}."
                )
            except ConnectionError as exc:
                print(
                    f"Server unavailable: {exc} "
                    "Pending events remain in the local queue."
                )
            except AgentApiError as exc:
                if exc.status in (401, 403):
                    print(
                        f"Agent authentication failed (HTTP {exc.status}). "
                        "Re-enroll before running again."
                    )
                    return 1
                print(f"BaseSentinel API error (HTTP {exc.status}): {exc}")
            except Exception as exc:
                print(f"Collection cycle failed: {exc}")

            if stop_event.wait(args.interval):
                break
    except KeyboardInterrupt:
        pass

    print("\\nBaseSentinel agent stopped.")
    return 0


def run(args) -> int:
    stop_event = threading.Event()
    input_stream = sys.stdin
    is_interactive = getattr(input_stream, "isatty", lambda: True)()
    if not is_interactive:
        threading.Thread(
            target=_watch_for_stop_request,
            args=(input_stream, stop_event),
            daemon=True,
        ).start()
    return _run_loop(args, stop_event, "running in foreground")


def background_worker(args) -> int:
    """Run the explicitly started, detached worker without opening a console window."""
    data_dir = default_data_dir()
    lock = try_acquire_worker_lock(data_dir)
    if lock is None:
        print("A BaseSentinel background worker is already running.")
        return 1

    pid_path = data_dir / "agent.pid"
    stop_path = data_dir / "agent.stop"
    worker_pid = str(os.getpid())
    try:
        pid_path.write_text(worker_pid, encoding="ascii")
    except OSError:
        release_worker_lock(lock)
        raise

    stop_event = threading.Event()

    def watch_stop_file() -> None:
        while not stop_event.wait(0.25):
            if stop_path.exists():
                try:
                    stop_path.unlink()
                except OSError:
                    pass
                stop_event.set()
                break

    watcher = threading.Thread(target=watch_stop_file, daemon=True)
    watcher.start()

    try:
        print(f"Background worker PID {worker_pid}.")
        print(f"Agent log: {data_dir / 'agent.log'}")
        return _run_loop(args, stop_event, "running in background")
    finally:
        stop_event.set()
        try:
            try:
                stop_path.unlink()
            except OSError:
                pass
            try:
                if pid_path.read_text(encoding="ascii").strip() == worker_pid:
                    pid_path.unlink()
            except OSError:
                pass
        finally:
            release_worker_lock(lock)


def start_background(args) -> int:
    try:
        AgentConfigStore().load()
        pid = start_background_worker(
            batch_size=args.batch_size,
            interval=args.interval,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Could not start background agent: {exc}")
        return 1

    print(f"BaseSentinel background agent started (PID {pid}).")
    print(f"Log file: {default_data_dir() / 'agent.log'}")
    print("The agent continues running after this terminal or GUI is closed.")
    return 0


def stop_background(args) -> int:
    try:
        if is_system_boot_task(_STARTUP_TASK_NAME):
            if not is_admin():
                run_elevated([
                    sys.executable,
                    "-m",
                    "basesentinel_agent.cli",
                    "startup-stop-admin",
                ])
                print("The elevated stop tool was launched. Approve the Windows UAC prompt to stop the collector.")
                return 0
            end_task(_STARTUP_TASK_NAME)
            print("BaseSentinel system-wide collector stopped.")
            print("Automatic startup at the next Windows boot remains enabled.")
            return 0

        stopped = request_background_stop(timeout=args.timeout)
    except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
        print(f"Could not confirm background agent shutdown: {exc}")
        return 1

    if stopped:
        print("BaseSentinel background agent stopped.")
    else:
        print("No BaseSentinel background agent is currently running.")
    return 0


def background_status_command(args) -> int:
    if is_system_boot_task(_STARTUP_TASK_NAME):
        from basesentinel_agent.system_install import machine_data_dir

        print("System-wide automatic collector: installed for all Windows users")
        print("Run account: Windows LocalSystem (SYSTEM)")
        print(f"Agent log: {machine_data_dir() / 'agent.log'}")
        return 0

    state = background_status()
    if state["running"]:
        pid = state["pid"] if state["pid"] is not None else "unknown"
        print(f"Background agent: running (PID {pid})")
    else:
        print("Background agent: stopped")
    print(f"Log file: {state['log_path']}")
    return 0


_STARTUP_TASK_NAME = "BaseSentinel Agent"


def _finish_system_install(config: dict, args) -> int:
    from basesentinel_agent.system_install import install_system_agent

    try:
        result = install_system_agent(
            config,
            interval=args.interval,
            batch_size=args.batch_size,
        )
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Could not install BaseSentinel for all Windows users: {exc}")
        return 1

    print("BaseSentinel system-wide automatic startup is installed.")
    print("Run account: Windows LocalSystem (SYSTEM)")
    print("Coverage: all Windows users, including before anyone signs in.")
    print(f"Protected runtime: {result['runtime_dir']}")
    print(f"Machine data: {result['data_dir']}")
    if result["started"]:
        print("The system-wide collector was started.")
    else:
        print("The startup task is installed, but it could not be started immediately.")
        print(f"Details: {result['start_error']}")
        print("Windows will try again at the next boot.")
    return 0 if result["started"] else 1


def install_startup(args) -> int:
    """Install one protected SYSTEM collector for all Windows user accounts."""
    try:
        config = AgentConfigStore(machine_scope=False).load()
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Could not load the enrolled BaseSentinel account: {exc}")
        print("Enroll this Windows endpoint before installing automatic startup.")
        return 1

    try:
        state = background_status()
        if state["running"]:
            stopped = request_background_stop(timeout=60.0)
            if not stopped or background_status()["running"]:
                raise TimeoutError("The existing per-user collector did not stop.")
    except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
        print(f"Could not stop the existing per-user collector: {exc}")
        print("No system-wide collector was installed.")
        return 1

    if is_admin():
        return _finish_system_install(config, args)

    bootstrap_path = None
    try:
        from basesentinel_agent.system_install import create_admin_bootstrap

        bootstrap_path = create_admin_bootstrap(config)
        command = [
            sys.executable,
            "-m",
            "basesentinel_agent.cli",
            "startup-install-admin",
            "--bootstrap-file",
            str(bootstrap_path),
            "--interval",
            str(args.interval),
            "--batch-size",
            str(args.batch_size),
        ]
        print("Administrator approval is required to install the all-users collector.")
        print("The elevated installer will:")
        print("  - Create the visible 'BaseSentinel Agent' task, running as SYSTEM at Windows boot.")
        print("  - Copy the Python runtime and BaseSentinel agent code to ProgramData\\BaseSentinel\\Runtime.")
        print("  - Store the machine-protected credential, event queue and log in ProgramData\\BaseSentinel\\Data.")
        print("  - Restrict writes to SYSTEM and Administrators; standard users get runtime read/execute only.")
        print("It will not change audit policy, firewall rules, user accounts or Windows services.")
        print("Windows will now display a UAC prompt for Administrator approval.")
        run_elevated(command)
    except (RuntimeError, ValueError, OSError) as exc:
        if bootstrap_path is not None:
            try:
                bootstrap_path.unlink()
            except OSError:
                pass
        print(f"Could not start the elevated BaseSentinel installer: {exc}")
        try:
            if 'stopped' in locals() and stopped:
                start_background_worker(
                    batch_size=args.batch_size,
                    interval=args.interval,
                )
                print("The existing per-user collector was restarted.")
        except (RuntimeError, ValueError, OSError) as restart_error:
            print(f"Could not restart the previous collector: {restart_error}")
        return 1

    print("The elevated installer was launched. Complete the Windows UAC prompt to finish setup.")
    return 0


def install_startup_admin(args) -> int:
    """Elevated continuation of the visible all-users installation."""
    from basesentinel_agent.system_install import read_admin_bootstrap

    bootstrap_path = Path(args.bootstrap_file)
    try:
        config = read_admin_bootstrap(bootstrap_path)
        if not is_admin():
            print("The elevated installer did not receive an Administrator token.")
            return 1
        return _finish_system_install(config, args)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"System-wide BaseSentinel installation failed: {exc}")
        return 1
    finally:
        try:
            bootstrap_path.unlink()
        except OSError:
            pass

def startup_launch(args) -> int:
    """Launch the detached worker silently from the Windows logon task."""
    try:
        AgentConfigStore().load()
        if not background_status()["running"]:
            start_background_worker(
                batch_size=args.batch_size,
                interval=args.interval,
            )
        return 0
    except (RuntimeError, ValueError, OSError) as exc:
        try:
            log_path = default_data_dir() / "agent.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"Automatic startup failed: {exc}\\n")
        except OSError:
            pass
        return 1


def remove_startup(args) -> int:
    """Remove the system-wide startup task after explicit Administrator approval."""
    if not is_admin():
        try:
            run_elevated([
                sys.executable,
                "-m",
                "basesentinel_agent.cli",
                "startup-remove-admin",
            ])
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"Could not request Administrator approval: {exc}")
            return 1
        print("The elevated removal tool was launched. Approve the Windows UAC prompt to continue.")
        return 0

    return remove_startup_admin(args)


def remove_startup_admin(args) -> int:
    from basesentinel_agent.system_install import remove_system_agent_startup

    if not is_admin():
        print("Removing the system-wide startup task requires Administrator privileges.")
        return 1
    try:
        removed = remove_system_agent_startup()
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"Could not remove BaseSentinel automatic startup: {exc}")
        return 1

    if removed:
        print("BaseSentinel system-wide automatic startup has been removed.")
        print("The protected runtime and agent data were retained.")
    else:
        print("BaseSentinel automatic startup was not installed.")
    return 0

def startup_status(args) -> int:
    try:
        installed = task_exists(_STARTUP_TASK_NAME)
        system_wide = installed and is_system_boot_task(_STARTUP_TASK_NAME)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"Could not read BaseSentinel startup status: {exc}")
        return 1

    if system_wide:
        from basesentinel_agent.system_install import machine_data_dir

        print("Automatic startup: installed for all Windows users")
        print("Run account: Windows LocalSystem (SYSTEM)")
        print("Start trigger: Windows boot (before user sign-in)")
        print(f"Agent log: {machine_data_dir() / 'agent.log'}")
    elif installed:
        print("Automatic startup: legacy per-user task detected")
        print("Run startup-install again to replace it with the all-users system task.")
    else:
        print("Automatic startup: not installed")
    return 0


def startup_service_run(args) -> int:
    """Run the system-wide collector in the foreground under Task Scheduler."""
    os.environ["BASESENTINEL_AGENT_SCOPE"] = "machine"
    data_dir = default_data_dir(machine_scope=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    log_path = data_dir / "agent.log"

    with log_path.open("a", encoding="utf-8", buffering=1) as log_stream:
        with redirect_stdout(log_stream), redirect_stderr(log_stream):
            print("BaseSentinel system-wide collector started under LocalSystem.")
            return background_worker(args)

def identity(args) -> int:
    client = _client_from_config()
    result = client.identity()
    print(f"Agent {result['agent_id']}: {result['status']}")
    if is_system_boot_task(_STARTUP_TASK_NAME):
        from basesentinel_agent.system_install import machine_data_dir

        print("Collector startup: installed for all Windows users (SYSTEM)")
        print(f"Agent log: {machine_data_dir() / 'agent.log'}")
        return 0

    state = background_status()
    if state["running"]:
        print(f"Background worker: running (PID {state['pid'] or 'unknown'})")
    else:
        print("Background worker: stopped")
    print(f"Log file: {state['log_path']}")
    return 0



def _stop_system_agent_admin() -> int:
    if not is_admin():
        print("Stopping the system-wide agent requires Administrator privileges.")
        return 1
    try:
        if not task_exists(_STARTUP_TASK_NAME):
            print("BaseSentinel automatic startup is not installed.")
            return 0
        end_task(_STARTUP_TASK_NAME)
    except RuntimeError as exc:
        print(f"Could not stop the system-wide BaseSentinel collector: {exc}")
        return 1
    print("BaseSentinel system-wide collector stopped.")
    print("Automatic startup at the next Windows boot remains enabled.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="basesentinel-agent")
    commands = parser.add_subparsers(dest="command", required=True)

    enroll_parser = commands.add_parser(
        "enroll",
        help="Enroll this Windows endpoint with a pairing code.",
    )
    enroll_parser.add_argument("--server", required=True, help="BaseSentinel HTTPS base URL.")
    enroll_parser.add_argument("--pairing-code", required=True)
    enroll_parser.set_defaults(handler=enroll)

    collect_parser = commands.add_parser(
        "collect",
        help="Collect and deliver allowlisted Windows Security events.",
    )
    collect_parser.add_argument("--batch-size", type=_batch_size, default=500)
    collect_parser.set_defaults(handler=collect)

    drain_parser = commands.add_parser(
        "drain",
        help="Deliver queued events without collecting new Windows events.",
    )
    drain_parser.add_argument("--batch-size", type=_batch_size, default=500)
    drain_parser.set_defaults(handler=drain)

    diagnostics_parser = commands.add_parser(
        "diagnostics",
        help="Check server connectivity, queue state and Windows Security log access.",
    )
    diagnostics_parser.set_defaults(handler=diagnostics)

    run_parser = commands.add_parser(
        "run",
        help="Continuously collect events and send periodic heartbeats.",
    )
    run_parser.add_argument(
        "--interval",
        type=_positive_interval,
        default=60.0,
        help="Seconds between collection cycles (default: 60).",
    )
    run_parser.add_argument("--batch-size", type=_batch_size, default=500)
    run_parser.set_defaults(handler=run)

    start_parser = commands.add_parser(
        "start",
        help="Start continuous collection as a detached, windowless background process.",
    )
    start_parser.add_argument("--interval", type=_positive_interval, default=60.0)
    start_parser.add_argument("--batch-size", type=_batch_size, default=500)
    start_parser.set_defaults(handler=start_background)

    stop_parser = commands.add_parser(
        "stop",
        help="Gracefully stop the background agent.",
    )
    stop_parser.add_argument("--timeout", type=float, default=60.0)
    stop_parser.set_defaults(handler=stop_background)

    background_status_parser = commands.add_parser(
        "background-status",
        help="Show whether the background agent is running.",
    )
    background_status_parser.set_defaults(handler=background_status_command)

    startup_install_parser = commands.add_parser(
        "startup-install",
        help="Install the protected system-wide agent startup (Administrator approval required).",
    )
    startup_install_parser.add_argument("--interval", type=_positive_interval, default=60.0)
    startup_install_parser.add_argument("--batch-size", type=_batch_size, default=500)
    startup_install_parser.set_defaults(handler=install_startup)

    startup_install_admin_parser = commands.add_parser(
        "startup-install-admin",
        help=argparse.SUPPRESS,
    )
    startup_install_admin_parser.add_argument("--bootstrap-file", required=True)
    startup_install_admin_parser.add_argument("--interval", type=_positive_interval, default=60.0)
    startup_install_admin_parser.add_argument("--batch-size", type=_batch_size, default=500)
    startup_install_admin_parser.set_defaults(handler=install_startup_admin)

    startup_remove_admin_parser = commands.add_parser(
        "startup-remove-admin",
        help=argparse.SUPPRESS,
    )
    startup_remove_admin_parser.set_defaults(handler=remove_startup_admin)

    startup_stop_admin_parser = commands.add_parser(
        "startup-stop-admin",
        help=argparse.SUPPRESS,
    )
    startup_stop_admin_parser.set_defaults(
        handler=lambda args: _stop_system_agent_admin()
    )

    startup_service_parser = commands.add_parser(
        "startup-service-run",
        help=argparse.SUPPRESS,
    )
    startup_service_parser.add_argument("--interval", type=_positive_interval, default=60.0)
    startup_service_parser.add_argument("--batch-size", type=_batch_size, default=500)
    startup_service_parser.set_defaults(handler=startup_service_run)

    startup_run_parser = commands.add_parser(
        "startup-run",
        help=argparse.SUPPRESS,
    )
    startup_run_parser.add_argument("--interval", type=_positive_interval, default=60.0)
    startup_run_parser.add_argument("--batch-size", type=_batch_size, default=500)
    startup_run_parser.set_defaults(handler=startup_launch)

    startup_remove_parser = commands.add_parser(
        "startup-remove",
        help="Remove the system-wide automatic startup task (Administrator approval required).",
    )
    startup_remove_parser.set_defaults(handler=remove_startup)

    startup_status_parser = commands.add_parser(
        "startup-status",
        help="Show whether system-wide automatic startup is installed.",
    )
    startup_status_parser.set_defaults(handler=startup_status)

    worker_parser = commands.add_parser(
        "_background-worker",
        help=argparse.SUPPRESS,
    )
    worker_parser.add_argument("--interval", type=_positive_interval, default=60.0)
    worker_parser.add_argument("--batch-size", type=_batch_size, default=500)
    worker_parser.set_defaults(handler=background_worker)

    identity_parser = commands.add_parser(
        "status",
        help="Check the enrolled agent identity.",
    )
    identity_parser.set_defaults(handler=identity)
    return parser


def main() -> int:
    if platform.system() != "Windows":
        raise SystemExit("The BaseSentinel endpoint agent currently supports Windows only.")
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
