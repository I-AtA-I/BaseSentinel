from __future__ import annotations

import base64
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from basesentinel_agent.protection import protect_secret, unprotect_secret
from basesentinel_agent.storage import AgentConfigStore


_TASK_NAME = "BaseSentinel Agent"
_RUNTIME_NAME = "Runtime"
_DATA_NAME = "Data"

_SYSTEM_ENTRY_POINT = """\
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

runtime_root = Path(__file__).resolve().parent
os.environ["BASESENTINEL_AGENT_SCOPE"] = "machine"
sys.path.insert(0, str(runtime_root / "src"))
sys.argv = ["basesentinel-agent", "startup-service-run", *sys.argv[1:]]
runpy.run_module("basesentinel_agent.cli", run_name="__main__")
"""


def product_root() -> Path:
    """Return the protected, machine-wide BaseSentinel application directory."""
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            ) as key:
                root, _ = winreg.QueryValueEx(key, "Common AppData")
        except (ImportError, OSError) as exc:
            raise RuntimeError(
                "Could not resolve the protected Windows ProgramData folder."
            ) from exc
    else:
        root = os.environ.get("PROGRAMDATA")
    if not root:
        raise RuntimeError("PROGRAMDATA is not available for the system-wide agent.")
    return Path(root) / "BaseSentinel"


def machine_data_dir() -> Path:
    return product_root() / _DATA_NAME


def system_runtime_dir() -> Path:
    return product_root() / _RUNTIME_NAME


def _run_icacls(
    path: Path,
    *,
    users_read_only: bool,
    recursive: bool = True,
) -> None:
    from basesentinel_windows.startup import windows_system_executable

    arguments = [
        windows_system_executable("icacls.exe"),
        str(path),
        "/inheritance:r",
        "/grant:r",
        "*S-1-5-18:(OI)(CI)(F)",
        "*S-1-5-32-544:(OI)(CI)(F)",
    ]
    if users_read_only:
        arguments.append("*S-1-5-32-545:(OI)(CI)(RX)")
    if recursive:
        arguments.append("/T")

    try:
        result = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not secure {path} with Windows ACLs: {exc}") from exc

    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()[-800:]
        raise RuntimeError(
            f"Could not secure {path} with Windows ACLs."
            + (f" Details: {details}" if details else "")
        )



def _set_admin_owner(path: Path, *, recursive: bool = True) -> None:
    """Assign ownership to Administrators using Windows' privilege-aware utility."""
    from basesentinel_windows.startup import windows_system_executable

    command = [
        windows_system_executable("takeown.exe"),
        "/F",
        str(path),
        "/A",
    ]
    if recursive:
        command.append("/R")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not set Administrators ownership on {path}: {exc}") from exc

    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()[-800:]
        raise RuntimeError(
            f"Could not set Administrators ownership on {path}."
            + (f" Details: {details}" if details else "")
        )

def _current_user_sid() -> str:
    try:
        from basesentinel_windows.startup import windows_system_executable

        result = subprocess.run(
            [windows_system_executable("whoami.exe"), "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not identify the current Windows account: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError("Could not identify the current Windows account.")
    try:
        row = next(csv.reader(result.stdout.splitlines()))
        sid = row[1].strip()
    except (StopIteration, IndexError):
        raise RuntimeError("Windows returned an invalid account SID.") from None
    if not sid.startswith("S-1-"):
        raise RuntimeError("Windows returned an invalid account SID.")
    return sid


def create_admin_bootstrap(config: dict) -> Path:
    """Write a short-lived, machine-protected enrollment handoff for the UAC child."""
    required = ("server_url", "agent_id", "token")
    if any(not isinstance(config.get(key), str) or not config[key] for key in required):
        raise ValueError("The enrolled agent configuration is incomplete.")

    local_app_data = os.environ.get("LOCALAPPDATA")
    temporary_root = (
        Path(local_app_data) / "Temp"
        if local_app_data
        else Path(tempfile.gettempdir())
    )
    temporary_root.mkdir(parents=True, exist_ok=True)

    protected = protect_secret(config["token"], machine_scope=True)
    payload = {
        "version": 1,
        "server_url": config["server_url"],
        "agent_id": config["agent_id"],
        "protected_token": base64.b64encode(protected).decode("ascii"),
    }

    handle, raw_path = tempfile.mkstemp(
        prefix="basesentinel-admin-",
        suffix=".json",
        dir=temporary_root,
    )
    path = Path(raw_path)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, separators=(",", ":"))

        # The token is machine-protected, but still restrict access to the
        # enrolled user, Administrators and SYSTEM while the UAC child runs.
        result = subprocess.run(
            [
                "icacls.exe",
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{_current_user_sid()}:(F)",
                "*S-1-5-32-544:(F)",
                "*S-1-5-18:(F)",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            details = (result.stderr or result.stdout).strip()[-500:]
            raise RuntimeError(
                "Could not protect the temporary administrator handoff."
                + (f" Details: {details}" if details else "")
            )
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


def read_admin_bootstrap(path: str | Path) -> dict:
    """Read and decrypt the one-time enrollment handoff in the elevated process."""
    bootstrap_path = Path(path)
    try:
        payload = json.loads(bootstrap_path.read_text(encoding="utf-8"))
        if payload.get("version") != 1:
            raise ValueError("Unsupported administrator handoff version.")
        token = unprotect_secret(
            base64.b64decode(payload["protected_token"], validate=True),
            machine_scope=True,
        )
        config = {
            "server_url": payload["server_url"],
            "agent_id": payload["agent_id"],
            "token": token,
        }
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise RuntimeError("The administrator handoff is unreadable or invalid.") from exc

    if any(not isinstance(config[key], str) or not config[key] for key in config):
        raise RuntimeError("The administrator handoff is incomplete.")
    return config


def _copy_runtime(destination: Path) -> None:
    python_home = Path(sys.base_prefix).resolve()
    python_exe = python_home / "python.exe"
    pythonw_exe = python_home / "pythonw.exe"
    if not python_exe.is_file() or not pythonw_exe.is_file():
        raise RuntimeError(
            "A complete Windows Python installation (python.exe and pythonw.exe) "
            "is required to install the system-wide agent."
        )

    source_root = Path(__file__).resolve().parents[1]
    package_names = ("basesentinel_agent", "basesentinel_windows")
    if any(not (source_root / package / "__init__.py").is_file() for package in package_names):
        raise RuntimeError("Could not locate the installed BaseSentinel agent packages.")

    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    python_runtime = destination / "python"
    shutil.copytree(python_home, python_runtime, ignore=ignore)

    # The collector only uses the standard library. Exclude user-installed
    # Python packages and .pth startup hooks from the copied runtime.
    shutil.rmtree(python_runtime / "Lib" / "site-packages", ignore_errors=True)

    source_destination = destination / "src"
    source_destination.mkdir()
    for package in package_names:
        shutil.copytree(
            source_root / package,
            source_destination / package,
            ignore=ignore,
        )

    (destination / "start_agent.py").write_text(
        _SYSTEM_ENTRY_POINT,
        encoding="utf-8",
    )


def install_system_agent(
    config: dict,
    *,
    interval: float = 60.0,
    batch_size: int = 500,
) -> dict:
    """Install one protected LocalSystem collector for every Windows user."""
    from basesentinel_windows.startup import (
        end_task,
        is_admin,
        register_system_boot_task,
        run_task,
        task_exists,
    )

    if os.name != "nt":
        raise RuntimeError("System-wide automatic startup is supported on Windows only.")
    if not is_admin():
        raise RuntimeError("System-wide installation requires an elevated Administrator process.")
    if not 1 <= batch_size <= 500 or interval <= 0:
        raise ValueError("Invalid agent collection settings.")

    root = product_root()
    data_dir = machine_data_dir()
    runtime_dir = system_runtime_dir()
    root.mkdir(parents=True, exist_ok=True)

    # Lock existing machine data before changing the product-root ACL. The
    # Data directory contains a machine-DPAPI credential and queued events.
    data_dir.mkdir(parents=True, exist_ok=True)
    _run_icacls(data_dir, users_read_only=False)
    _set_admin_owner(data_dir)

    # Do not recursively grant Users access to the product root.
    _run_icacls(root, users_read_only=True, recursive=False)
    _set_admin_owner(root, recursive=False)

    staging = Path(tempfile.mkdtemp(prefix=".Runtime-staging-", dir=root))
    backup: Path | None = None
    installed_new_runtime = False
    try:
        _copy_runtime(staging)
        _run_icacls(staging, users_read_only=True)
        _set_admin_owner(staging)

        if task_exists(_TASK_NAME):
            # The old per-user task may exist from an earlier agent version.
            # Ending it before the replacement avoids two active collectors.
            try:
                end_task(_TASK_NAME)
            except RuntimeError:
                pass

        if runtime_dir.exists():
            backup = root / ".Runtime-backup"
            if backup.exists():
                shutil.rmtree(backup)
            runtime_dir.rename(backup)

        staging.rename(runtime_dir)
        installed_new_runtime = True

        AgentConfigStore(
            path=data_dir / "agent.json",
            machine_scope=True,
        ).save(
            config["server_url"],
            config["token"],
            config["agent_id"],
        )

        pythonw = runtime_dir / "python" / "pythonw.exe"
        register_system_boot_task(
            _TASK_NAME,
            [
                str(pythonw),
                str(runtime_dir / "start_agent.py"),
                "--interval",
                str(interval),
                "--batch-size",
                str(batch_size),
            ],
            working_directory=runtime_dir,
            description=(
                "Run the BaseSentinel endpoint collector as LocalSystem at Windows startup. "
                "This single collector covers all Windows user accounts."
            ),
        )
    except Exception:
        if installed_new_runtime and runtime_dir.exists():
            shutil.rmtree(runtime_dir, ignore_errors=True)
        if backup is not None and backup.exists() and not runtime_dir.exists():
            backup.rename(runtime_dir)
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    if backup is not None and backup.exists():
        shutil.rmtree(backup, ignore_errors=True)

    started = True
    start_error = None
    try:
        run_task(_TASK_NAME)
    except RuntimeError as exc:
        started = False
        start_error = str(exc)

    return {
        "task_name": _TASK_NAME,
        "runtime_dir": str(runtime_dir),
        "data_dir": str(data_dir),
        "started": started,
        "start_error": start_error,
    }


def remove_system_agent_startup() -> bool:
    """Stop and remove the system-wide startup task without deleting agent data."""
    from basesentinel_windows.startup import end_task, remove_task, task_exists

    if not task_exists(_TASK_NAME):
        return False
    try:
        end_task(_TASK_NAME)
    except RuntimeError:
        # The task may be installed but not currently running.
        pass
    return remove_task(_TASK_NAME)
