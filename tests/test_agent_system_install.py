from __future__ import annotations

import json
import subprocess

import pytest
from pathlib import Path

from basesentinel_agent import storage, system_install


def test_machine_data_directory_uses_programdata(monkeypatch, tmp_path):
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))

    assert storage.default_data_dir(machine_scope=True) == (
        tmp_path / "BaseSentinel" / "Data"
    )


def test_machine_scope_config_uses_machine_dpapi(monkeypatch, tmp_path):
    calls = []

    def fake_protect(secret, *, machine_scope=False):
        calls.append(("protect", secret, machine_scope))
        return b"protected-token"

    def fake_unprotect(encrypted, *, machine_scope=False):
        calls.append(("unprotect", encrypted, machine_scope))
        return "agent-token"

    monkeypatch.setattr(storage, "protect_secret", fake_protect)
    monkeypatch.setattr(storage, "unprotect_secret", fake_unprotect)

    store = storage.AgentConfigStore(
        path=tmp_path / "agent.json",
        machine_scope=True,
    )
    store.save("https://siem.example.com", "agent-token", "agent-123")
    loaded = store.load()

    assert loaded == {
        "server_url": "https://siem.example.com",
        "agent_id": "agent-123",
        "token": "agent-token",
    }
    assert calls == [
        ("protect", "agent-token", True),
        ("unprotect", b"protected-token", True),
    ]


def test_admin_bootstrap_uses_machine_dpapi_and_restricts_temp_file(
    monkeypatch,
    tmp_path,
):
    commands = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(
        system_install,
        "protect_secret",
        lambda secret, *, machine_scope=False: (
            b"machine-encrypted" if secret == "secret-token" and machine_scope else b""
        ),
    )
    monkeypatch.setattr(system_install, "_current_user_sid", lambda: "S-1-5-21-1000")

    def fake_run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="success", stderr="")

    monkeypatch.setattr(system_install.subprocess, "run", fake_run)
    monkeypatch.setattr(
        system_install,
        "unprotect_secret",
        lambda encrypted, *, machine_scope=False: (
            "secret-token" if encrypted == b"machine-encrypted" and machine_scope else ""
        ),
    )

    config = {
        "server_url": "https://siem.example.com",
        "agent_id": "agent-123",
        "token": "secret-token",
    }
    path = system_install.create_admin_bootstrap(config)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        restored = system_install.read_admin_bootstrap(path)
    finally:
        path.unlink(missing_ok=True)

    assert restored == config
    assert payload["protected_token"]
    assert commands[0][0] == "icacls.exe"
    assert "*S-1-5-21-1000:(F)" in commands[0]
    assert "*S-1-5-32-544:(F)" in commands[0]
    assert "*S-1-5-18:(F)" in commands[0]


def test_system_entry_point_selects_machine_scope():
    assert 'BASESENTINEL_AGENT_SCOPE"] = "machine"' in system_install._SYSTEM_ENTRY_POINT
    assert "startup-service-run" in system_install._SYSTEM_ENTRY_POINT


def test_admin_owner_uses_takeown_and_system32_tool(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(
        "basesentinel_windows.startup.windows_system_executable",
        lambda name: rf"C:\Windows\System32\{name}",
    )

    def fake_run(command, **kwargs):
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(system_install.subprocess, "run", fake_run)

    target = tmp_path / "Runtime"
    system_install._set_admin_owner(target)

    assert captured["command"] == [
        r"C:\Windows\System32\takeown.exe",
        "/F",
        str(target),
        "/A",
        "/R",
    ]


def test_admin_owner_can_be_applied_to_directory_without_recursion(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(
        "basesentinel_windows.startup.windows_system_executable",
        lambda name: rf"C:\Windows\System32\{name}",
    )
    monkeypatch.setattr(
        system_install.subprocess,
        "run",
        lambda command, **kwargs: (
            captured.update(command=command)
            or subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        ),
    )

    system_install._set_admin_owner(tmp_path, recursive=False)

    assert captured["command"][-1] == "/A"
    assert "/R" not in captured["command"]


def test_admin_owner_reports_takeown_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "basesentinel_windows.startup.windows_system_executable",
        lambda name: rf"C:\Windows\System32\{name}",
    )

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="",
            stderr="Access is denied.",
        )

    monkeypatch.setattr(system_install.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="Could not set Administrators ownership") as exc:
        system_install._set_admin_owner(tmp_path)

    assert "Access is denied." in str(exc.value)
