from __future__ import annotations

import argparse
import math
import os
import platform
import socket
import sys
import threading

from basesentinel_agent.background import (
    background_status,
    release_worker_lock,
    request_background_stop,
    start_background_worker,
    try_acquire_worker_lock,
)
from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.storage import AgentConfigStore, default_data_dir
from basesentinel_agent.windows_eventlog import (
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
    discovered, next_checkpoint = collect_security_events(checkpoint)
    queue.add_batch_and_checkpoint(discovered, next_checkpoint)
    sent, pending = _deliver_pending(
        client,
        queue,
        batch_size,
        stop_event=stop_event,
    )
    return len(discovered), sent, pending, next_checkpoint


def collect(args) -> int:
    try:
        audit_state = ensure_pnp_audit_activity()
        if audit_state == "enabled":
            print("Windows Plug and Play success auditing enabled.")
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
    state = background_status()
    if state["running"]:
        pid = state["pid"] if state["pid"] is not None else "unknown"
        print(f"Background agent: running (PID {pid})")
    else:
        print("Background agent: stopped")
    print(f"Log file: {state['log_path']}")
    return 0


def identity(args) -> int:
    client = _client_from_config()
    result = client.identity()
    print(f"Agent {result['agent_id']}: {result['status']}")
    state = background_status()
    if state["running"]:
        print(f"Background worker: running (PID {state['pid'] or 'unknown'})")
    else:
        print("Background worker: stopped")
    print(f"Log file: {state['log_path']}")
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
