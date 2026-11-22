from __future__ import annotations

import math
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import BinaryIO

from basesentinel_agent.storage import default_data_dir


class _WindowsFileLock:
    """Keep the file handle and OVERLAPPED structure alive for a Win32 lock."""

    def __init__(self, handle: BinaryIO, kernel32, overlapped) -> None:
        self.handle = handle
        self.kernel32 = kernel32
        self.overlapped = overlapped


def _try_acquire_windows_file_lock(
    handle: BinaryIO,
    *,
    shared: bool,
) -> _WindowsFileLock | None:
    """Use LockFileEx so status readers can share a lock on Windows."""
    import ctypes
    from ctypes import wintypes

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    lock_file_ex = kernel32.LockFileEx
    lock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(OVERLAPPED),
    ]
    lock_file_ex.restype = wintypes.BOOL

    import msvcrt

    overlapped = OVERLAPPED()
    flags = 0x00000001  # LOCKFILE_FAIL_IMMEDIATELY
    if not shared:
        flags |= 0x00000002  # LOCKFILE_EXCLUSIVE_LOCK

    succeeded = lock_file_ex(
        msvcrt.get_osfhandle(handle.fileno()),
        flags,
        0,
        1,
        0,
        ctypes.byref(overlapped),
    )
    if not succeeded:
        error = ctypes.get_last_error()
        handle.close()
        if error == 33:  # ERROR_LOCK_VIOLATION
            return None
        raise OSError(error, ctypes.FormatError(error))

    return _WindowsFileLock(handle, kernel32, overlapped)


def _release_windows_file_lock(lock: _WindowsFileLock) -> None:
    import ctypes
    from ctypes import wintypes

    unlock_file_ex = lock.kernel32.UnlockFileEx
    unlock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(type(lock.overlapped)),
    ]
    unlock_file_ex.restype = wintypes.BOOL
    import msvcrt

    succeeded = unlock_file_ex(
        msvcrt.get_osfhandle(lock.handle.fileno()),
        0,
        1,
        0,
        ctypes.byref(lock.overlapped),
    )
    if not succeeded:
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))
    lock.handle.close()


_LOCK_NAME = "agent.lock"
_PID_NAME = "agent.pid"
_STOP_NAME = "agent.stop"
_LOG_NAME = "agent.log"


def _paths(data_dir: Path | None = None) -> dict[str, Path]:
    root = data_dir or default_data_dir()
    return {
        "root": root,
        "lock": root / _LOCK_NAME,
        "pid": root / _PID_NAME,
        "stop": root / _STOP_NAME,
        "log": root / _LOG_NAME,
    }


def agent_log_path(data_dir: Path | None = None) -> Path:
    """Return the persistent background-agent log path."""
    return _paths(data_dir)["log"]


def console_python_executable(executable: str | None = None) -> str:
    """Use python.exe for CLI workers even when this GUI runs under pythonw.exe."""
    selected = executable or sys.executable
    if os.name == "nt" and Path(selected).name.lower() == "pythonw.exe":
        console_executable = Path(selected).with_name("python.exe")
        if console_executable.is_file():
            return str(console_executable)
    return selected


def _try_acquire_file_lock(
    data_dir: Path | None = None,
    *,
    shared: bool,
) -> BinaryIO | _WindowsFileLock | None:
    """Acquire a shared status lock or an exclusive worker lock without waiting."""
    paths = _paths(data_dir)
    paths["root"].mkdir(parents=True, exist_ok=True)
    handle = paths["lock"].open("a+b")

    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)

    if os.name == "nt":
        # _try_acquire_windows_file_lock returns None only for
        # ERROR_LOCK_VIOLATION. Other Windows API errors must remain visible;
        # treating them as contention makes a stopped worker look active.
        return _try_acquire_windows_file_lock(handle, shared=shared)

    try:
        import fcntl

        operation = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        fcntl.flock(handle.fileno(), operation | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None

    return handle


def try_acquire_worker_lock(
    data_dir: Path | None = None,
) -> BinaryIO | _WindowsFileLock | None:
    """Acquire the exclusive single-instance lock for the background worker."""
    return _try_acquire_file_lock(data_dir, shared=False)


def _try_acquire_status_lock(
    data_dir: Path | None = None,
) -> BinaryIO | _WindowsFileLock | None:
    """Acquire a shared lock so concurrent status checks do not block one another."""
    return _try_acquire_file_lock(data_dir, shared=True)


def release_worker_lock(handle: BinaryIO | _WindowsFileLock) -> None:
    """Release a lock returned by try_acquire_worker_lock or a status check."""
    if isinstance(handle, _WindowsFileLock):
        try:
            _release_windows_file_lock(handle)
        finally:
            if not handle.handle.closed:
                handle.handle.close()
        return

    try:
        handle.seek(0)
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def background_status(data_dir: Path | None = None) -> dict:
    """Check whether the background worker currently owns the process lock."""
    paths = _paths(data_dir)
    lock = _try_acquire_status_lock(paths["root"])
    if lock is not None:
        release_worker_lock(lock)
        return {
            "running": False,
            "pid": None,
            "log_path": str(paths["log"]),
        }

    try:
        pid_text = paths["pid"].read_text(encoding="ascii").strip()
        pid = int(pid_text)
    except (FileNotFoundError, ValueError, OSError):
        pid = None

    return {
        "running": True,
        "pid": pid,
        "log_path": str(paths["log"]),
    }


def _read_log_tail(path: Path, limit: int = 2500) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            return "".join(stream.readlines()[-limit:])
    except OSError:
        return ""


def start_background_worker(
    batch_size: int = 500,
    interval: float = 60.0,
    data_dir: Path | None = None,
    python_executable: str | None = None,
) -> int:
    """Launch one detached, windowless worker and return its process ID."""
    if type(batch_size) is not int or not 1 <= batch_size <= 500:
        raise ValueError("Batch size must be an integer between 1 and 500.")
    if not isinstance(interval, (int, float)) or not math.isfinite(interval) or interval <= 0:
        raise ValueError("Collection interval must be a finite number greater than zero.")

    paths = _paths(data_dir)
    paths["root"].mkdir(parents=True, exist_ok=True)

    if background_status(paths["root"])["running"]:
        raise RuntimeError("The BaseSentinel background agent is already running.")

    for stale_path in (paths["stop"], paths["pid"]):
        try:
            stale_path.unlink()
        except FileNotFoundError:
            pass

    executable = console_python_executable(python_executable)
    command = [
        executable,
        "-u",
        "-m",
        "basesentinel_agent.cli",
        "_background-worker",
        "--interval",
        str(interval),
        "--batch-size",
        str(batch_size),
    ]

    with paths["log"].open("a", encoding="utf-8", buffering=1) as log_file:
        flags = 0
        popen_options = {
            "stdin": subprocess.DEVNULL,
            "stdout": log_file,
            "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            flags = (
                getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
            )
            popen_options["creationflags"] = flags
        else:
            popen_options["start_new_session"] = True

        process = subprocess.Popen(command, **popen_options)

    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        state = background_status(paths["root"])
        if state["running"]:
            if state["pid"] == process.pid:
                return process.pid
            if state["pid"] is not None:
                raise RuntimeError(
                    "Another BaseSentinel background agent started at the same time."
                )

        exit_code = process.poll()
        if exit_code is not None:
            tail = _read_log_tail(paths["log"], limit=30).strip()
            detail = f" Background log: {tail}" if tail else ""
            raise RuntimeError(
                f"The background agent exited during startup (code {exit_code}).{detail}"
            )
        time.sleep(0.1)

    raise RuntimeError(
        "The background agent did not acquire its process lock. "
        f"Check its log at {paths['log']}."
    )


def request_background_stop(
    data_dir: Path | None = None,
    timeout: float = 20.0,
) -> bool:
    """Ask the background worker to stop and wait for a clean exit."""
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("Stop timeout must be a finite non-negative number.")

    paths = _paths(data_dir)
    if not background_status(paths["root"])["running"]:
        return False

    paths["stop"].write_text("stop\n", encoding="ascii")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not background_status(paths["root"])["running"]:
            return True
        time.sleep(0.2)

    raise TimeoutError(
        "The background agent has not stopped yet. "
        f"Check its log at {paths['log']}."
    )
