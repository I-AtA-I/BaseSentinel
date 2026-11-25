from __future__ import annotations

import os
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path

import pystray
from PIL import Image, ImageDraw, ImageFont
from pystray import MenuItem

from basesentinel_agent.background import (
    background_status,
    request_background_stop,
    start_background_worker,
)
from basesentinel_agent.storage import AgentConfigStore
from basesentinel_windows.startup import is_system_boot_task


_SYSTEM_STARTUP_TASK_NAME = "BaseSentinel Agent"


class AgentTray:
    """Small Windows notification-area controller for the detached agent."""

    def __init__(self) -> None:
        self.icon: pystray.Icon | None = None
        self.stopping = threading.Event()
        self.last_running: bool | None = None
        self.last_enrolled: bool | None = None
        self.last_system_wide: bool | None = None

    @staticmethod
    def _is_enrolled() -> bool:
        try:
            AgentConfigStore().load()
        except (RuntimeError, OSError, ValueError):
            return False
        return True

    @staticmethod
    def _running() -> tuple[bool, int | None]:
        try:
            status = background_status()
        except (OSError, RuntimeError, ValueError):
            return False, None
        return bool(status.get("running")), status.get("pid")

    @staticmethod
    def _system_wide_installed() -> bool:
        try:
            return is_system_boot_task(_SYSTEM_STARTUP_TASK_NAME)
        except (OSError, RuntimeError, ValueError):
            return False

    def _status_text(self) -> str:
        if self._system_wide_installed():
            return "System-wide collector installed · SYSTEM"
        running, pid = self._running()
        if running:
            return f"Monitoring active · PID {pid or 'unknown'}"
        if not self._is_enrolled():
            return "Not enrolled · open the endpoint console"
        return "Monitoring paused"

    @staticmethod
    def _image(running: bool) -> Image.Image:
        image = Image.new("RGBA", (64, 64), (9, 16, 24, 255))
        draw = ImageDraw.Draw(image)
        accent = (91, 211, 154, 255) if running else (133, 148, 167, 255)
        draw.rounded_rectangle((3, 3, 61, 61), radius=13, fill=(17, 26, 38, 255), outline=(53, 73, 91, 255), width=2)
        draw.ellipse((43, 8, 57, 22), fill=accent)
        try:
            font = ImageFont.truetype("segoeui.ttf", 31)
        except OSError:
            font = ImageFont.load_default()
        draw.text((15, 12), "B", font=font, fill=(200, 241, 105, 255))
        return image

    def _notify(self, message: str, title: str = "BaseSentinel") -> None:
        if self.icon is None:
            return
        try:
            self.icon.notify(message, title)
        except (AttributeError, OSError, RuntimeError):
            pass

    def _refresh(self) -> None:
        running, _ = self._running()
        enrolled = self._is_enrolled()
        system_wide = self._system_wide_installed()
        if (
            running != self.last_running
            or enrolled != self.last_enrolled
            or system_wide != self.last_system_wide
        ):
            self.last_running = running
            self.last_enrolled = enrolled
            self.last_system_wide = system_wide
            if self.icon is not None:
                self.icon.icon = self._image(running or system_wide)
                self.icon.title = self._status_text()
                try:
                    self.icon.update_menu()
                except (AttributeError, RuntimeError):
                    pass

    def _refresh_loop(self) -> None:
        while not self.stopping.wait(3):
            self._refresh()

    def open_console(self, icon, item) -> None:
        try:
            if getattr(sys, "frozen", False):
                executable = str(Path(sys.executable).with_name("BaseSentinelEndpoint.exe"))
                command = [executable]
            else:
                executable = sys.executable
                if os.name == "nt" and Path(executable).name.lower() == "python.exe":
                    candidate = Path(executable).with_name("pythonw.exe")
                    if candidate.is_file():
                        executable = str(candidate)
                command = [executable, "-m", "basesentinel_agent.gui"]
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            self._notify(str(exc), "Could not open endpoint console")

    def resume(self, icon, item) -> None:
        if not self._is_enrolled():
            self._notify("Connect this device in the endpoint console before starting monitoring.")
            self.open_console(icon, item)
            return
        try:
            pid = start_background_worker(batch_size=500, interval=60)
        except (RuntimeError, ValueError, OSError) as exc:
            self._notify(str(exc), "Could not start monitoring")
            return
        self._notify(f"Background monitoring started (PID {pid}).")
        self._refresh()

    def pause(self, icon, item) -> None:
        try:
            stopped = request_background_stop(timeout=60)
        except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
            self._notify(str(exc), "Could not pause monitoring")
            return
        if stopped:
            self._notify("Monitoring paused. The local event queue is preserved.")
        else:
            self._notify("Monitoring is already paused.")
        self._refresh()

    def exit_tray(self, icon, item) -> None:
        self.stopping.set()
        icon.stop()

    def run(self) -> None:
        menu = pystray.Menu(
            MenuItem(lambda item: self._status_text(), None, enabled=False),
            MenuItem("Open endpoint console", self.open_console, default=True),
            MenuItem(
                "Resume monitoring",
                self.resume,
                visible=lambda item: (
                    not self._running()[0] and not self._system_wide_installed()
                ),
                enabled=lambda item: self._is_enrolled(),
            ),
            MenuItem(
                "Pause monitoring",
                self.pause,
                visible=lambda item: self._running()[0],
            ),
            pystray.Menu.SEPARATOR,
            MenuItem("Exit tray", self.exit_tray),
        )
        self.icon = pystray.Icon(
            "BaseSentinel",
            self._image(self._running()[0] or self._system_wide_installed()),
            title=self._status_text(),
            menu=menu,
        )
        threading.Thread(target=self._refresh_loop, daemon=True).start()
        self.icon.run()
        self.stopping.set()


def main() -> None:
    if platform.system() != "Windows":
        raise SystemExit("The BaseSentinel system tray currently supports Windows only.")
    AgentTray().run()


if __name__ == "__main__":
    main()
