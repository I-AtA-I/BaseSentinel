from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from basesentinel_agent.protection import protect_secret, unprotect_secret


def default_data_dir(*, machine_scope: bool | None = None) -> Path:
    if machine_scope is None:
        machine_scope = os.environ.get("BASESENTINEL_AGENT_SCOPE", "").casefold() == "machine"

    if machine_scope:
        root = os.environ.get("PROGRAMDATA")
        if not root and os.name == "nt":
            root = r"C:\ProgramData"
        if not root:
            raise RuntimeError("PROGRAMDATA is not available for the system-wide agent.")
        return Path(root) / "BaseSentinel" / "Data"

    root = os.environ.get("LOCALAPPDATA")
    if not root:
        raise RuntimeError("LOCALAPPDATA is not available; run the agent in a Windows user session.")
    return Path(root) / "BaseSentinel"


class AgentConfigStore:
    def __init__(
        self,
        path: Path | None = None,
        *,
        machine_scope: bool | None = None,
    ):
        if machine_scope is None:
            machine_scope = os.environ.get("BASESENTINEL_AGENT_SCOPE", "").casefold() == "machine"
        self.machine_scope = machine_scope
        self.path = path or default_data_dir(machine_scope=machine_scope) / "agent.json"

    def save(self, server_url: str, token: str, agent_id: str) -> None:
        encrypted = protect_secret(token, machine_scope=self.machine_scope)
        payload = {
            "config_version": 1,
            "server_url": server_url.rstrip("/"),
            "agent_id": agent_id,
            "protected_token": base64.b64encode(encrypted).decode("ascii"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)

    def load(self) -> dict:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if payload.get("config_version") != 1:
                raise ValueError("Unsupported agent configuration version.")
            token = unprotect_secret(
                base64.b64decode(payload["protected_token"], validate=True),
                machine_scope=self.machine_scope,
            )
            if not payload.get("server_url") or not payload.get("agent_id") or not token:
                raise ValueError("Agent configuration is incomplete.")
            return {"server_url": payload["server_url"], "agent_id": payload["agent_id"], "token": token}
        except FileNotFoundError:
            raise RuntimeError("Agent is not enrolled. Run the enroll command first.") from None
        except (KeyError, TypeError, ValueError, OSError) as exc:
            raise RuntimeError("Agent configuration is unreadable or invalid.") from exc
