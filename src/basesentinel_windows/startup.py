from __future__ import annotations

import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Sequence


_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"
ET.register_namespace("", _NAMESPACE)


def _tag(name: str) -> str:
    return f"{{{_NAMESPACE}}}{name}"


def _current_user() -> str:
    username = os.environ.get("USERNAME")
    if not username:
        raise RuntimeError("Could not determine the current Windows username.")
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{username}" if domain else username


def build_logon_task_xml(
    task_name: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
    description: str = "",
    restart_on_failure: bool = False,
    username: str | None = None,
    trigger: str = "logon",
    service_account: bool = False,
) -> str:
    """Build a logon task or a system-start task for Windows Task Scheduler."""
    if not task_name.strip():
        raise ValueError("Task name must not be empty.")
    if not command or not str(command[0]).strip():
        raise ValueError("Task command must contain an executable.")

    if trigger not in {"logon", "boot"}:
        raise ValueError("Task trigger must be 'logon' or 'boot'.")
    if service_account and trigger != "boot":
        raise ValueError("A service account can only be used with a boot trigger.")
    if trigger == "boot" and not service_account:
        raise ValueError("A boot task must run under a Windows service account.")

    user = "SYSTEM" if service_account else (username or _current_user())
    root = ET.Element(_tag("Task"), {"version": "1.4"})

    registration = ET.SubElement(root, _tag("RegistrationInfo"))
    ET.SubElement(registration, _tag("Author")).text = "BaseSentinel"
    ET.SubElement(registration, _tag("Description")).text = description or task_name

    triggers = ET.SubElement(root, _tag("Triggers"))
    if trigger == "logon":
        trigger_element = ET.SubElement(triggers, _tag("LogonTrigger"))
        ET.SubElement(trigger_element, _tag("Enabled")).text = "true"
        ET.SubElement(trigger_element, _tag("UserId")).text = user
    else:
        trigger_element = ET.SubElement(triggers, _tag("BootTrigger"))
        ET.SubElement(trigger_element, _tag("Enabled")).text = "true"

    principals = ET.SubElement(root, _tag("Principals"))
    principal = ET.SubElement(principals, _tag("Principal"), {"id": "Author"})
    ET.SubElement(principal, _tag("UserId")).text = user
    ET.SubElement(principal, _tag("LogonType")).text = (
        "ServiceAccount" if service_account else "InteractiveToken"
    )
    ET.SubElement(principal, _tag("RunLevel")).text = (
        "HighestAvailable" if service_account else "LeastPrivilege"
    )

    settings = ET.SubElement(root, _tag("Settings"))
    ET.SubElement(settings, _tag("MultipleInstancesPolicy")).text = "IgnoreNew"
    ET.SubElement(settings, _tag("DisallowStartIfOnBatteries")).text = "false"
    ET.SubElement(settings, _tag("StopIfGoingOnBatteries")).text = "false"
    ET.SubElement(settings, _tag("AllowHardTerminate")).text = "true"
    ET.SubElement(settings, _tag("StartWhenAvailable")).text = "true"
    ET.SubElement(settings, _tag("RunOnlyIfNetworkAvailable")).text = "false"
    ET.SubElement(settings, _tag("AllowStartOnDemand")).text = "true"
    ET.SubElement(settings, _tag("Enabled")).text = "true"
    ET.SubElement(settings, _tag("Hidden")).text = "false"
    ET.SubElement(settings, _tag("ExecutionTimeLimit")).text = "PT0S"
    ET.SubElement(settings, _tag("Priority")).text = "7"
    if restart_on_failure:
        restart = ET.SubElement(settings, _tag("RestartOnFailure"))
        ET.SubElement(restart, _tag("Interval")).text = "PT1M"
        ET.SubElement(restart, _tag("Count")).text = "3"

    actions = ET.SubElement(root, _tag("Actions"), {"Context": "Author"})
    action = ET.SubElement(actions, _tag("Exec"))
    ET.SubElement(action, _tag("Command")).text = str(command[0])
    ET.SubElement(action, _tag("Arguments")).text = subprocess.list2cmdline(
        [str(part) for part in command[1:]]
    )
    if working_directory is not None:
        ET.SubElement(action, _tag("WorkingDirectory")).text = str(
            Path(working_directory).resolve()
        )

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Automatic startup registration is supported on Windows only.")


def _run_schtasks(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            ["schtasks.exe", *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not run Windows Task Scheduler command: {exc}") from exc

    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            details or f"Windows Task Scheduler command failed with exit code {result.returncode}."
        )
    return result


def register_logon_task(
    task_name: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
    description: str = "",
    restart_on_failure: bool = False,
) -> None:
    """Register a hidden per-user task that runs after the current user signs in."""
    _require_windows()
    xml_content = build_logon_task_xml(
        task_name,
        command,
        working_directory=working_directory,
        description=description,
        restart_on_failure=restart_on_failure,
    )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".xml",
            prefix="basesentinel-task-",
            delete=False,
        ) as stream:
            stream.write(xml_content)
            temporary_path = Path(stream.name)

        _run_schtasks(["/Create", "/TN", task_name, "/XML", str(temporary_path), "/F"])
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def logon_task_exists(task_name: str) -> bool:
    _require_windows()
    try:
        result = subprocess.run(
            ["schtasks.exe", "/Query", "/TN", task_name],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not query Windows Task Scheduler: {exc}") from exc
    return result.returncode == 0


def remove_logon_task(task_name: str) -> bool:
    """Remove a registered task, returning false when it does not exist."""
    _require_windows()
    if not logon_task_exists(task_name):
        return False
    _run_schtasks(["/Delete", "/TN", task_name, "/F"])
    return True


def run_logon_task(task_name: str) -> None:
    """Start a registered task now, without waiting for the next logon."""
    _require_windows()
    _run_schtasks(["/Run", "/TN", task_name])



def register_boot_task(
    task_name: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
    description: str = "",
    restart_on_failure: bool = False,
) -> None:
    """Register a task that starts with Windows under the LocalSystem account."""
    _require_windows()
    xml_content = build_logon_task_xml(
        task_name,
        command,
        working_directory=working_directory,
        description=description,
        restart_on_failure=restart_on_failure,
        trigger="boot",
        service_account=True,
    )

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".xml",
            prefix="basesentinel-boot-task-",
            delete=False,
        ) as stream:
            stream.write(xml_content)
            temporary_path = Path(stream.name)

        _run_schtasks(["/Create", "/TN", task_name, "/XML", str(temporary_path), "/F"])
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
