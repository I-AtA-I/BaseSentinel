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
    return f"{domain}{chr(92)}{username}" if domain else username


def build_startup_task_xml(
    task_name: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
    description: str = "",
    restart_on_failure: bool = False,
    username: str | None = None,
) -> str:
    """Build a visible, least-privilege task that runs after the user's logon."""
    if not task_name.strip():
        raise ValueError("Task name must not be empty.")
    if not command or not str(command[0]).strip():
        raise ValueError("Task command must contain an executable.")

    user = username or _current_user()
    root = ET.Element(_tag("Task"), {"version": "1.4"})

    registration = ET.SubElement(root, _tag("RegistrationInfo"))
    ET.SubElement(registration, _tag("Author")).text = "BaseSentinel"
    ET.SubElement(registration, _tag("Description")).text = description or task_name

    triggers = ET.SubElement(root, _tag("Triggers"))
    trigger = ET.SubElement(triggers, _tag("LogonTrigger"))
    ET.SubElement(trigger, _tag("Enabled")).text = "true"
    ET.SubElement(trigger, _tag("UserId")).text = user

    principals = ET.SubElement(root, _tag("Principals"))
    principal = ET.SubElement(principals, _tag("Principal"), {"id": "Author"})
    ET.SubElement(principal, _tag("UserId")).text = user
    ET.SubElement(principal, _tag("LogonType")).text = "InteractiveToken"
    ET.SubElement(principal, _tag("RunLevel")).text = "LeastPrivilege"

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



def windows_system_directory() -> Path:
    """Resolve System32 through the Windows API rather than environment variables."""
    if os.name != "nt":
        return Path()

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_system_directory(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buffer.value)


def windows_system_executable(name: str) -> str:
    """Return an absolute System32 path for a Windows inbox executable."""
    if not name or Path(name).name != name:
        raise ValueError("A System32 executable name is required.")
    if os.name != "nt":
        return name
    return str(windows_system_directory() / name)

def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Automatic startup registration is supported on Windows only.")


def _run_schtasks(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [windows_system_executable("schtasks.exe"), *arguments],
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
    """Register a visible per-user task that runs after the current user signs in."""
    _require_windows()
    xml_content = build_startup_task_xml(
        task_name,
        command,
        working_directory=working_directory,
        description=description,
        restart_on_failure=restart_on_failure,
    )

    temporary_path: Path | None = None
    try:
        # Task Scheduler's XML importer expects a matching Unicode encoding.
        # Serialize the document as UTF-16 (including its BOM and declaration)
        # instead of writing UTF-8 text with a potentially mismatched declaration.
        xml_bytes = ET.tostring(
            ET.fromstring(xml_content),
            encoding="utf-16",
            xml_declaration=True,
        )
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".xml",
            prefix="basesentinel-task-",
            delete=False,
        ) as stream:
            stream.write(xml_bytes)
            temporary_path = Path(stream.name)

        _run_schtasks(["/Create", "/TN", task_name, "/XML", str(temporary_path), "/F"])
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def task_exists(task_name: str) -> bool:
    _require_windows()
    try:
        result = subprocess.run(
            [windows_system_executable("schtasks.exe"), "/Query", "/TN", task_name],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not query Windows Task Scheduler: {exc}") from exc
    return result.returncode == 0


def remove_task(task_name: str) -> bool:
    """Remove a registered task, returning false when it does not exist."""
    _require_windows()
    if not task_exists(task_name):
        return False
    _run_schtasks(["/Delete", "/TN", task_name, "/F"])
    return True


def end_task(task_name: str) -> bool:
    """End a currently running task without removing or disabling it."""
    _require_windows()
    if not task_exists(task_name):
        return False
    _run_schtasks(["/End", "/TN", task_name])
    return True


def disable_task(task_name: str) -> bool:
    """Disable a registered task without deleting its definition."""
    _require_windows()
    if not task_exists(task_name):
        return False
    _run_schtasks(["/Change", "/TN", task_name, "/Disable"])
    return True


def run_task(task_name: str) -> None:
    """Start a registered task now, without waiting for the next user logon."""
    _require_windows()
    _run_schtasks(["/Run", "/TN", task_name])


def build_system_boot_task_xml(
    task_name: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
    description: str = "",
) -> str:
    """Build a visible SYSTEM task that starts the collector at Windows boot."""
    if not task_name.strip():
        raise ValueError("Task name must not be empty.")
    if not command or not str(command[0]).strip():
        raise ValueError("Task command must contain an executable.")

    root = ET.Element(_tag("Task"), {"version": "1.4"})

    registration = ET.SubElement(root, _tag("RegistrationInfo"))
    ET.SubElement(registration, _tag("Author")).text = "BaseSentinel"
    ET.SubElement(registration, _tag("Description")).text = (
        description or task_name
    )

    triggers = ET.SubElement(root, _tag("Triggers"))
    trigger = ET.SubElement(triggers, _tag("BootTrigger"))
    ET.SubElement(trigger, _tag("Enabled")).text = "true"

    principals = ET.SubElement(root, _tag("Principals"))
    principal = ET.SubElement(principals, _tag("Principal"), {"id": "System"})
    ET.SubElement(principal, _tag("UserId")).text = "S-1-5-18"
    ET.SubElement(principal, _tag("LogonType")).text = "ServiceAccount"
    ET.SubElement(principal, _tag("RunLevel")).text = "HighestAvailable"

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
    restart = ET.SubElement(settings, _tag("RestartOnFailure"))
    ET.SubElement(restart, _tag("Interval")).text = "PT1M"
    ET.SubElement(restart, _tag("Count")).text = "3"

    actions = ET.SubElement(root, _tag("Actions"), {"Context": "System"})
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


def register_system_boot_task(
    task_name: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
    description: str = "",
) -> None:
    """Register a visible, elevated SYSTEM task that runs before user sign-in."""
    _require_windows()
    xml_content = build_system_boot_task_xml(
        task_name,
        command,
        working_directory=working_directory,
        description=description,
    )

    temporary_path: Path | None = None
    try:
        xml_bytes = ET.tostring(
            ET.fromstring(xml_content),
            encoding="utf-16",
            xml_declaration=True,
        )
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".xml",
            prefix="basesentinel-system-task-",
            delete=False,
        ) as stream:
            stream.write(xml_bytes)
            temporary_path = Path(stream.name)

        _run_schtasks(
            ["/Create", "/TN", task_name, "/XML", str(temporary_path), "/F"]
        )
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def is_admin() -> bool:
    """Return whether the current Windows process has an elevated administrator token."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def run_elevated(command: Sequence[str]) -> None:
    """Launch a visible command after an explicit Windows UAC consent prompt."""
    _require_windows()
    if not command or not str(command[0]).strip():
        raise ValueError("An executable is required for elevation.")

    import ctypes
    from ctypes import wintypes

    parameters = subprocess.list2cmdline([str(part) for part in command[1:]])
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell_execute = shell32.ShellExecuteW
    shell_execute.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell_execute.restype = ctypes.c_void_p
    result = shell_execute(
        None,
        "runas",
        str(command[0]),
        parameters,
        str(windows_system_directory()),
        1,
    )
    result_code = result if isinstance(result, int) else getattr(result, "value", 0)
    if not result_code or result_code <= 32:
        error = ctypes.get_last_error()
        if error == 1223:
            raise RuntimeError("Administrator approval was cancelled.")
        raise RuntimeError(
            f"Windows could not start the elevated installer (ShellExecute result {result_code})."
        )


def is_system_boot_task(task_name: str) -> bool:
    """Return whether a registered task runs as SYSTEM from a boot trigger."""
    _require_windows()
    try:
        result = _run_schtasks(["/Query", "/TN", task_name, "/XML"])
        xml_text = result.stdout.lstrip("\ufeff")
        if xml_text.startswith("<?xml") and "?>" in xml_text:
            xml_text = xml_text.split("?>", 1)[1]
        root = ET.fromstring(xml_text)
    except (RuntimeError, ET.ParseError):
        return False

    principal = root.find(f".//{_tag('Principal')}")
    if principal is None:
        return False
    user_id = principal.findtext(_tag("UserId"))
    logon_type = principal.findtext(_tag("LogonType"))
    has_boot_trigger = root.find(f".//{_tag('BootTrigger')}") is not None
    return (
        user_id == "S-1-5-18"
        and logon_type == "ServiceAccount"
        and has_boot_trigger
    )
