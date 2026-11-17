from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit, urlunsplit
from urllib.request import Request, urlopen


class AgentApiError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class BaseSentinelClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 10.0):
        parsed = urlsplit(base_url)
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in local_hosts):
            raise ValueError("The BaseSentinel server URL must use HTTPS.")
        if not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Invalid BaseSentinel server URL.")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                data = json.loads(exc.read().decode("utf-8"))
                message = data.get("error", {}).get("message", "BaseSentinel request failed.")
            except (ValueError, AttributeError):
                message = "BaseSentinel request failed."
            raise AgentApiError(exc.code, message) from None
        except (URLError, TimeoutError, OSError) as exc:
            raise ConnectionError("Could not reach the BaseSentinel server.") from exc
        if not isinstance(data, dict):
            raise AgentApiError(502, "The server returned an invalid response.")
        return data

    def enroll(self, pairing_code: str, hostname: str, platform_version: str, architecture: str) -> dict:
        return self._request("POST", "/api/v1/agents/enroll", {
            "pairing_code": pairing_code,
            "hostname": hostname,
            "platform": "windows",
            "platform_version": platform_version,
            "architecture": architecture,
            "agent_version": "0.1.0",
        })

    def enroll_with_server(self, server_id: str, server_secret: str, connection_password: str | None,
                           hostname: str, platform_version: str, architecture: str) -> dict:
        return self._request("POST", "/api/v1/agents/enroll-server", {
            "server_id": server_id,
            "server_secret": server_secret,
            "connection_password": connection_password or None,
            "hostname": hostname,
            "platform": "windows",
            "platform_version": platform_version,
            "architecture": architecture,
            "agent_version": "0.1.0",
        })

    @staticmethod
    def parse_invitation_link(invitation_link: str) -> tuple[str, str]:
        if not isinstance(invitation_link, str) or len(invitation_link) > 4096:
            raise ValueError("Invalid invitation link.")
        parsed = urlsplit(invitation_link.strip())
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in local_hosts
        ):
            raise ValueError("Invitation links must use HTTPS.")
        if (
            not parsed.netloc or parsed.username or parsed.password
            or parsed.query or parsed.path.rstrip("/") != "/agent-invite"
        ):
            raise ValueError("Invalid BaseSentinel invitation link.")
        fragment = parse_qs(parsed.fragment, strict_parsing=True)
        tokens = fragment.get("invite", [])
        if len(tokens) != 1 or not tokens[0] or len(tokens[0]) > 256:
            raise ValueError("Invitation link does not contain a valid invitation.")
        server_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        return server_url, tokens[0]

    def enroll_with_invitation(self, hostname: str, platform_version: str,
                               architecture: str, invitation_token: str | None = None,
                               invitation_code: str | None = None) -> dict:
        if bool(invitation_token) == bool(invitation_code):
            raise ValueError("Provide exactly one invitation link token or invitation code.")
        payload = {
            "hostname": hostname,
            "hostname": hostname,
            "platform": "windows",
            "platform_version": platform_version,
            "architecture": architecture,
            "agent_version": "0.1.0",
        }
        if invitation_token:
            payload["invitation_token"] = invitation_token
        else:
            payload["invitation_code"] = invitation_code
        return self._request("POST", "/api/v1/agents/enroll-invitation", payload)

    def send_event(self, event: dict) -> dict:
        if not self.token:
            raise ValueError("Agent is not enrolled.")
        return self._request("POST", "/api/v1/events", event)

    def identity(self) -> dict:
        if not self.token:
            raise ValueError("Agent is not enrolled.")
        return self._request("GET", "/api/v1/agents/me")
