from __future__ import annotations

import argparse
import platform
import socket
from pathlib import Path

from basesentinel_agent.client import BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.storage import AgentConfigStore, default_data_dir
from basesentinel_agent.windows_eventlog import collect_security_events


def _queue() -> EventQueue:
    return EventQueue(default_data_dir() / "events.sqlite3")


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


def collect(args) -> int:
    config = AgentConfigStore().load()
    client = BaseSentinelClient(config["server_url"], config["token"])
    queue = _queue()

    checkpoint = queue.security_checkpoint()
    discovered, next_checkpoint = collect_security_events(checkpoint)
    queue.add_batch_and_checkpoint(discovered, next_checkpoint)

    sent = 0
    for event in queue.pending(limit=args.batch_size):
        try:
            client.send_event(event)
        except ConnectionError:
            print(f"Server unavailable. {len(queue)} event(s) remain queued.")
            return 2
        except Exception as exc:
            print(f"Could not deliver event {event['event_uid']}: {exc}")
            continue
        queue.acknowledge(event["event_uid"])
        sent += 1

    print(
        f"Collected {len(discovered)} event(s); delivered {sent}; "
        f"pending {len(queue)}; Security log checkpoint {next_checkpoint}."
    )
    return 0


def identity(args) -> int:
    config = AgentConfigStore().load()
    client = BaseSentinelClient(config["server_url"], config["token"])
    result = client.identity()
    print(f"Agent {result['agent_id']}: {result['status']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="basesentinel-agent")
    commands = parser.add_subparsers(dest="command", required=True)

    enroll_parser = commands.add_parser("enroll", help="Enroll this Windows endpoint with a pairing code.")
    enroll_parser.add_argument("--server", required=True, help="BaseSentinel HTTPS base URL.")
    enroll_parser.add_argument("--pairing-code", required=True)
    enroll_parser.set_defaults(handler=enroll)

    collect_parser = commands.add_parser("collect", help="Collect and deliver allowlisted Windows Security events.")
    collect_parser.add_argument("--batch-size", type=int, default=50)
    collect_parser.set_defaults(handler=collect)

    identity_parser = commands.add_parser("status", help="Check the enrolled agent identity.")
    identity_parser.set_defaults(handler=identity)
    return parser


def main() -> int:
    if platform.system() != "Windows":
        raise SystemExit("The BaseSentinel endpoint agent currently supports Windows only.")
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
