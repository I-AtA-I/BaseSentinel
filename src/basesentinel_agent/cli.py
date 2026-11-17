from __future__ import annotations

import argparse
import math
import platform
import socket
import sys
import threading

from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.storage import AgentConfigStore, default_data_dir
from basesentinel_agent.windows_eventlog import collect_security_events


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
            client.send_event(event)
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


def run(args) -> int:
    client = _client_from_config()
    queue = _queue()
    stop_event = threading.Event()

    input_stream = sys.stdin
    is_interactive = getattr(input_stream, "isatty", lambda: True)()
    if not is_interactive:
        threading.Thread(
            target=_watch_for_stop_request,
            args=(input_stream, stop_event),
            daemon=True,
        ).start()

    print(
        f"BaseSentinel agent running. Collection interval: "
        f"{args.interval:g}s. Delivery limit: {args.batch_size} event(s) per cycle. "
        "Press Ctrl+C or use the GUI Stop button to stop."
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

    print("\nBaseSentinel agent stopped.")
    return 0


def identity(args) -> int:
    client = _client_from_config()
    result = client.identity()
    print(f"Agent {result['agent_id']}: {result['status']}")
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
