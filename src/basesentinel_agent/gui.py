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
        self.root.geometry("600x500")
        self.root.minsize(540, 460)
        self.process = None

        frame = ttk.Frame(root, padding=22)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="BASESENTINEL", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Connect this Windows device to your security server.").pack(anchor="w", pady=(2, 14))

        notebook = ttk.Notebook(frame)
        notebook.pack(fill="x", expand=False)
        link_tab = ttk.Frame(notebook, padding=14)
        code_tab = ttk.Frame(notebook, padding=14)
        notebook.add(link_tab, text="Invitation link")
        notebook.add(code_tab, text="Invitation code")

        ttk.Label(link_tab, text="Paste the complete invitation link").pack(anchor="w")
        self.invitation = ttk.Entry(link_tab)
        self.invitation.pack(fill="x", pady=(6, 8))
        ttk.Label(link_tab, text="The link includes the server address and one-time invitation.").pack(anchor="w")

        ttk.Label(code_tab, text="Server URL").pack(anchor="w")
        self.server_url = ttk.Entry(code_tab)
        self.server_url.pack(fill="x", pady=(4, 10))
        ttk.Label(code_tab, text="Invitation code").pack(anchor="w")
        self.invitation_code = ttk.Entry(code_tab, font=("Consolas", 13))
        self.invitation_code.pack(fill="x", pady=(4, 8))
        ttk.Label(code_tab, text="Enter the code shown by the administrator.").pack(anchor="w")

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(16, 8))
        self.connect_button = ttk.Button(actions, text="Connect device", command=lambda: self.connect(notebook.index("current")))
        self.connect_button.pack(side="left")
        self.start_button = ttk.Button(actions, text="Start monitoring", command=self.start, state="disabled")
        self.start_button.pack(side="left", padx=8)
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left")

        self.status = tk.StringVar(value="Not connected")
        ttk.Label(frame, textvariable=self.status, wraplength=500).pack(anchor="w", pady=(12, 0))
        ttk.Label(frame, text="Agent credentials are protected with Windows DPAPI for this Windows user.",
                  wraplength=500).pack(anchor="w", side="bottom", pady=(18, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def connect(self, tab_index):
        try:
            if tab_index == 0:
                server, invitation_token = BaseSentinelClient.parse_invitation_link(self.invitation.get().strip())
                invitation_code = None
            else:
                server = self.server_url.get().strip()
                BaseSentinelClient(server)
                invitation_token = None
                invitation_code = self.invitation_code.get().strip()
                if not invitation_code:
                    raise ValueError("Enter the invitation code.")
        except ValueError as exc:
            messagebox.showerror("Invalid invitation", str(exc))
            return

        self.connect_button.configure(state="disabled")
        self.status.set("Connecting...")
        self.root.update_idletasks()
        try:
            client = BaseSentinelClient(server)
            result = client.enroll_with_invitation(
                socket.gethostname(),
                platform.platform()[:80],
                platform.machine()[:32],
                invitation_token=invitation_token,
                invitation_code=invitation_code,
            )
            AgentConfigStore().save(server, result["token"], result["agent_id"])
            self.status.set(f"Connected. Agent ID: {result['agent_id']}")
            self.start_button.configure(state="normal")
            self.invitation.delete(0, "end")
            self.invitation_code.delete(0, "end")
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
