from __future__ import annotations

import platform
import socket
import subprocess
import sys
import tkinter as tk
from tkinter import messagebox, ttk

from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.storage import AgentConfigStore


class AgentWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("BaseSentinel Agent")
        self.root.geometry("520x390")
        self.root.minsize(480, 360)
        self.process = None

        frame = ttk.Frame(root, padding=22)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="BASESENTINEL", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Connect this Windows device to your security server.").pack(anchor="w", pady=(2, 18))

        self.server = self._field(frame, "Server URL", "https://")
        self.server_id = self._field(frame, "Server ID")
        self.server_secret = self._field(frame, "Server access code", show="•")
        self.password = self._field(frame, "Connection password (optional)", show="•")

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(16, 8))
        self.connect_button = ttk.Button(actions, text="Connect device", command=self.connect)
        self.connect_button.pack(side="left")
        self.start_button = ttk.Button(actions, text="Start monitoring", command=self.start, state="disabled")
        self.start_button.pack(side="left", padx=8)
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left")

        self.status = tk.StringVar(value="Not connected")
        ttk.Label(frame, textvariable=self.status, wraplength=460).pack(anchor="w", pady=(12, 0))
        ttk.Label(frame, text="Credentials are protected with Windows DPAPI for this Windows user.",
                  wraplength=460).pack(anchor="w", side="bottom", pady=(18, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _field(self, parent, label, default="", show=None):
        ttk.Label(parent, text=label).pack(anchor="w")
        entry = ttk.Entry(parent, show=show)
        entry.pack(fill="x", pady=(3, 10))
        if default:
            entry.insert(0, default)
        return entry

    def connect(self):
        server = self.server.get().strip()
        server_id = self.server_id.get().strip()
        secret = self.server_secret.get().strip()
        password = self.password.get()
        if not all((server, server_id, secret)):
            messagebox.showerror("Missing information", "Enter the server URL, Server ID and access code.")
            return
        self.connect_button.configure(state="disabled")
        self.status.set("Connecting...")
        self.root.update_idletasks()
        try:
            client = BaseSentinelClient(server)
            result = client.enroll_with_server(
                server_id, secret, password, socket.gethostname(),
                platform.platform()[:80], platform.machine()[:32],
            )
            AgentConfigStore().save(server, result["token"], result["agent_id"])
            self.status.set(f"Connected. Agent ID: {result['agent_id']}")
            self.start_button.configure(state="normal")
            self.server_secret.delete(0, "end")
            self.password.delete(0, "end")
        except (ValueError, RuntimeError, ConnectionError, AgentApiError, OSError) as exc:
            messagebox.showerror("Connection failed", str(exc))
            self.status.set("Connection failed.")
        finally:
            self.connect_button.configure(state="normal")

    def start(self):
        if self.process and self.process.poll() is None:
            return
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            self.process = subprocess.Popen(
                [sys.executable, "-m", "basesentinel_agent.cli", "run"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            self.status.set("Monitoring is running. Close this window to stop it.")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.root.after(1000, self.check_process)
        except OSError as exc:
            messagebox.showerror("Could not start agent", str(exc))

    def check_process(self):
        if not self.process:
            return
        code = self.process.poll()
        if code is None:
            self.root.after(1000, self.check_process)
        else:
            self.status.set(f"Agent stopped (exit code {code}).")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.status.set("Monitoring stopped.")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

    def close(self):
        self.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    AgentWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
