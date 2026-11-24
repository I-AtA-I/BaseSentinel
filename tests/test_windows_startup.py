import subprocess
import xml.etree.ElementTree as ET

import pytest

from basesentinel_windows import startup


_NAMESPACE = {"task": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def test_logon_task_xml_uses_current_user_and_visible_interactive_trigger(tmp_path):
    xml_text = startup.build_startup_task_xml(
        "BaseSentinel Agent",
        [
            r"C:\Program Files\Python\pythonw.exe",
            "-m",
            "basesentinel_agent.cli",
            "start",
            "--interval",
            "60",
            "--label",
            "Office PC",
        ],
        working_directory=tmp_path,
        description="Start the endpoint collector.",
        username=r"WORKSTATION\operator",
    )
    root = ET.fromstring(xml_text)

    trigger = root.find("task:Triggers/task:LogonTrigger", _NAMESPACE)
    principal = root.find("task:Principals/task:Principal", _NAMESPACE)
    action = root.find("task:Actions/task:Exec", _NAMESPACE)

    assert trigger.findtext("task:UserId", namespaces=_NAMESPACE) == r"WORKSTATION\operator"
    assert principal.findtext("task:LogonType", namespaces=_NAMESPACE) == "InteractiveToken"
    assert principal.findtext("task:RunLevel", namespaces=_NAMESPACE) == "LeastPrivilege"
    assert action.findtext("task:Command", namespaces=_NAMESPACE) == r"C:\Program Files\Python\pythonw.exe"
    assert action.findtext("task:WorkingDirectory", namespaces=_NAMESPACE) == str(tmp_path.resolve())
    arguments = action.findtext("task:Arguments", namespaces=_NAMESPACE)
    assert '"Office PC"' in arguments
    assert "basesentinel_agent.cli" in arguments

    settings = root.find("task:Settings", _NAMESPACE)
    assert settings.findtext("task:Hidden", namespaces=_NAMESPACE) == "false"
    assert settings.findtext("task:MultipleInstancesPolicy", namespaces=_NAMESPACE) == "IgnoreNew"


def test_server_task_can_be_configured_to_restart_after_failure(tmp_path):
    xml_text = startup.build_startup_task_xml(
        "BaseSentinel Server",
        [r"C:\Python\pythonw.exe", "-m", "basesentinel.server", "run"],
        working_directory=tmp_path,
        restart_on_failure=True,
        username="operator",
    )
    root = ET.fromstring(xml_text)
    restart = root.find("task:Settings/task:RestartOnFailure", _NAMESPACE)

    assert restart is not None
    assert restart.findtext("task:Interval", namespaces=_NAMESPACE) == "PT1M"
    assert restart.findtext("task:Count", namespaces=_NAMESPACE) == "3"


def test_logon_task_rejects_empty_commands():
    with pytest.raises(ValueError, match="executable"):
        startup.build_startup_task_xml("BaseSentinel", [], username="operator")


def test_register_logon_task_writes_xml_then_calls_schtasks(monkeypatch, tmp_path):
    captured = {}

    monkeypatch.setattr(startup, "_require_windows", lambda: None)

    def fake_run(arguments):
        captured["arguments"] = arguments
        xml_path = arguments[arguments.index("/XML") + 1]
        captured["xml"] = ET.parse(xml_path).getroot()
        return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

    monkeypatch.setattr(startup, "_run_schtasks", fake_run)
    startup.register_logon_task(
        "BaseSentinel Agent",
        [r"C:\Python\pythonw.exe", "-m", "basesentinel_agent.cli", "start"],
        working_directory=tmp_path,
        username="operator",
    )

    assert captured["arguments"][:3] == ["/Create", "/TN", "BaseSentinel Agent"]
    assert captured["xml"].findtext("task:Actions/task:Exec/task:Command", namespaces=_NAMESPACE) == r"C:\Python\pythonw.exe"
    xml_path = captured["arguments"][captured["arguments"].index("/XML") + 1]
    assert not __import__("pathlib").Path(xml_path).exists()


def test_logon_task_query_and_remove(monkeypatch):
    calls = []
    responses = [
        subprocess.CompletedProcess([], 0, stdout="TaskName", stderr=""),
        subprocess.CompletedProcess([], 0, stdout="", stderr=""),
    ]

    monkeypatch.setattr(startup, "_require_windows", lambda: None)

    def fake_run(arguments, **kwargs):
        calls.append(arguments)
        return responses.pop(0)

    monkeypatch.setattr(startup.subprocess, "run", fake_run)

    assert startup.logon_task_exists("BaseSentinel Agent") is True
    assert startup.remove_logon_task("BaseSentinel Agent") is True
    assert calls[0][:4] == ["schtasks.exe", "/Query", "/TN", "BaseSentinel Agent"]
    assert calls[1][:4] == ["schtasks.exe", "/Delete", "/TN", "BaseSentinel Agent"]



def test_boot_task_uses_system_account_and_boot_trigger(tmp_path):
    xml_text = startup.build_startup_task_xml(
        "BaseSentinel Server",
        [r"C:\Python\pythonw.exe", "-m", "basesentinel.server", "run"],
        working_directory=tmp_path,
        restart_on_failure=True,
        trigger="boot",
        service_account=True,
    )
    root = ET.fromstring(xml_text)

    trigger = root.find("task:Triggers/task:BootTrigger", _NAMESPACE)
    principal = root.find("task:Principals/task:Principal", _NAMESPACE)

    assert trigger is not None
    assert trigger.findtext("task:Enabled", namespaces=_NAMESPACE) == "true"
    assert principal.findtext("task:UserId", namespaces=_NAMESPACE) == "SYSTEM"
    assert principal.findtext("task:LogonType", namespaces=_NAMESPACE) == "ServiceAccount"
    assert principal.findtext("task:RunLevel", namespaces=_NAMESPACE) == "HighestAvailable"


def test_boot_task_requires_service_account():
    with pytest.raises(ValueError, match="service account"):
        startup.build_startup_task_xml(
            "BaseSentinel Server",
            ["python.exe", "-m", "basesentinel.server", "run"],
            trigger="boot",
            username="operator",
        )
