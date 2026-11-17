from __future__ import annotations

import platform
import queue as thread_queue
import re
import socket
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.storage import AgentConfigStore


class AgentWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("BaseSentinel Agent")
        self.root.geometry("820x700")
        self.root.minsize(700, 600)

        self.messages = thread_queue.Queue()
        self.process = None
        self.process_task = None
        self.enrolling = False
        self.closing = False
        self.config_loaded = False
        self.batch_size = tk.StringVar(value="500")

        frame = ttk.Frame(root, padding=20)
        frame.pack(fill="both", expand=True)

        header = ttk.Frame(frame)
        header.pack(fill="x")
        ttk.Label(
            header,
            text="BASESENTINEL",
            font=("Segoe UI", 19, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            header,
            text="Windows endpoint agent",
        ).pack(anchor="w", pady=(1, 10))

        self.agent_summary = tk.StringVar(value="Not enrolled")
        ttk.Label(
            frame,
            textvariable=self.agent_summary,
            wraplength=760,
        ).pack(anchor="w", pady=(0, 12))

        notebook = ttk.Notebook(frame)
        notebook.pack(fill="x", expand=False)

        link_tab = ttk.Frame(notebook, padding=14)
        code_tab = ttk.Frame(notebook, padding=14)
        notebook.add(link_tab, text="Invitation link")
        notebook.add(code_tab, text="Invitation code")

        ttk.Label(
            link_tab,
            text="Paste the complete one-time invitation link",
        ).pack(anchor="w")
        self.invitation = ttk.Entry(link_tab)
        self.invitation.pack(fill="x", pady=(6, 8))
        ttk.Label(
            link_tab,
            text="The link contains the server address and invitation token.",
        ).pack(anchor="w")

        ttk.Label(code_tab, text="Server URL").pack(anchor="w")
        self.server_url = ttk.Entry(code_tab)
        self.server_url.pack(fill="x", pady=(4, 10))
        ttk.Label(code_tab, text="Invitation code").pack(anchor="w")
        self.invitation_code = ttk.Entry(
            code_tab,
            font=("Consolas", 13),
        )
        self.invitation_code.pack(fill="x", pady=(4, 8))
        ttk.Label(
            code_tab,
            text="Enter the code supplied by the BaseSentinel administrator.",
        ).pack(anchor="w")

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(14, 8))

        self.connect_button = ttk.Button(
            actions,
            text="Connect device",
            command=lambda: self.connect(notebook.index("current")),
        )
        self.connect_button.pack(side="left")

        self.diagnostics_button = ttk.Button(
            actions,
            text="Run diagnostics",
            command=self.diagnose,
        )
        self.diagnostics_button.pack(side="left", padx=(8, 0))

        self.collect_button = ttk.Button(
            actions,
            text="Collect now",
            command=self.collect_now,
        )
        self.collect_button.pack(side="left", padx=(8, 0))

        self.start_button = ttk.Button(
            actions,
            text="Start monitoring",
            command=self.start,
        )
        self.start_button.pack(side="left", padx=(8, 0))

        self.stop_button = ttk.Button(
            actions,
            text="Stop",
            command=self.stop,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=(8, 0))

        batch_control = ttk.Frame(actions)
        batch_control.pack(side="right")
        ttk.Label(batch_control, text="Delivery batch").pack(side="left", padx=(0, 6))
        self.batch_size_select = ttk.Combobox(
            batch_control,
            textvariable=self.batch_size,
            values=("50", "100", "250", "500"),
            width=5,
            state="readonly",
        )
        self.batch_size_select.pack(side="left")

        self.status = tk.StringVar(value="Not connected")
        ttk.Label(
            frame,
            textvariable=self.status,
            font=("Segoe UI", 10, "bold"),
            wraplength=760,
        ).pack(anchor="w", pady=(10, 4))

        self.metrics = tk.StringVar(
            value="No collection cycle has run in this session."
        )
        ttk.Label(
            frame,
            textvariable=self.metrics,
            wraplength=760,
        ).pack(anchor="w", pady=(0, 10))

        log_header = ttk.Frame(frame)
        log_header.pack(fill="x")
        ttk.Label(
            log_header,
            text="AGENT OUTPUT",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="left")
        ttk.Label(
            log_header,
            text="Live diagnostics and delivery results",
        ).pack(side="right")

        log_frame = ttk.Frame(frame)
        log_frame.pack(fill="both", expand=True, pady=(6, 0))

        self.log = tk.Text(
            log_frame,
            height=14,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            padx=8,
            pady=8,
        )
        self.log.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log.yview,
        )
        scrollbar.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=scrollbar.set)

        ttk.Label(
            frame,
            text=(
                "Connect only enrolls this device. Use Collect now for one batch "
                "or Start monitoring for continuous collection. The window must "
                "remain open while monitoring."
            ),
            wraplength=760,
        ).pack(anchor="w", pady=(10, 0))

        ttk.Label(
            frame,
            text=(
                "The agent currently reads Windows Security events "
                "4624, 4625, 4672 and 4720. Credentials are protected with "
                "Windows DPAPI for this Windows user."
            ),
            wraplength=760,
        ).pack(anchor="w", pady=(5, 0))

        self._refresh_config_status()
        self._update_actions()
        self._append_log("BaseSentinel Agent GUI ready.")
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(150, self._poll_messages)

    def _append_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{timestamp}] {message}\n")

        line_count = int(self.log.index("end-1c").split(".")[0])
        if line_count > 600:
            self.log.delete("1.0", f"{line_count - 500}.0")

        self.log.see("end")
        self.log.configure(state="disabled")

    def _refresh_config_status(self) -> None:
        try:
            config = AgentConfigStore().load()
        except (RuntimeError, OSError, ValueError):
            self.config_loaded = False
            self.agent_summary.set("Not enrolled on this Windows user account.")
        else:
            self.config_loaded = True
            self.agent_summary.set(
                f"Agent ID: {config['agent_id']}    Server: {config['server_url']}"
            )

    def _update_actions(self) -> None:
        idle = self.process is None
        ready = self.config_loaded

        self.connect_button.configure(
            state="disabled" if self.enrolling or not idle else "normal"
        )
        self.diagnostics_button.configure(
            state="normal" if idle and ready else "disabled"
        )
        self.collect_button.configure(
            state="normal" if idle and ready else "disabled"
        )
        self.start_button.configure(
            state="normal" if idle and ready else "disabled"
        )
        self.stop_button.configure(
            state=(
                "normal"
                if self.process is not None and self.process_task == "run"
                else "disabled"
            )
        )

    def connect(self, tab_index: int) -> None:
        if self.enrolling:
            return

        try:
            if tab_index == 0:
                server, invitation_token = BaseSentinelClient.parse_invitation_link(
                    self.invitation.get().strip()
                )
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

        self.enrolling = True
        self.status.set("Connecting to the BaseSentinel server...")
        self._update_actions()
        self._append_log("Starting device enrollment.")

        worker = threading.Thread(
            target=self._enroll_worker,
            args=(server, invitation_token, invitation_code),
            daemon=True,
        )
        worker.start()

    def _enroll_worker(
        self,
        server: str,
        invitation_token: str | None,
        invitation_code: str | None,
    ) -> None:
        try:
            client = BaseSentinelClient(server)
            result = client.enroll_with_invitation(
                socket.gethostname(),
                platform.platform()[:80],
                platform.machine()[:32],
                invitation_token=invitation_token,
                invitation_code=invitation_code,
            )

            if result.get("status") == "pending_approval":
                self.messages.put(("enrollment_pending", result))
                return

            AgentConfigStore().save(
                server,
                result["token"],
                result["agent_id"],
            )
            self.messages.put(("enrollment_success", result))
        except (ValueError, RuntimeError, ConnectionError, AgentApiError, OSError) as exc:
            self.messages.put(("enrollment_error", str(exc)))
        except Exception as exc:
            self.messages.put((
                "enrollment_error",
                f"Unexpected enrollment error: {exc}",
            ))

    def _start_process(self, task: str, arguments: list[str]) -> None:
        if self.process is not None:
            return

        command = [
            sys.executable,
            "-u",
            "-m",
            "basesentinel_agent.cli",
            *arguments,
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
        except OSError as exc:
            self.status.set("Could not start the agent process.")
            self._append_log(f"Process start failed: {exc}")
            messagebox.showerror("Could not start agent", str(exc))
            return

        self.process = process
        self.process_task = task
        self.status.set({
            "diagnostics": "Running diagnostics...",
            "collect": "Collecting and delivering one batch...",
            "run": "Continuous monitoring is running.",
        }.get(task, "Agent process running."))
        self._update_actions()
        self._append_log(f"Started agent task: {task}.")

        reader = threading.Thread(
            target=self._read_process_output,
            args=(process,),
            daemon=True,
        )
        reader.start()

    def _read_process_output(self, process: subprocess.Popen) -> None:
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    self.messages.put((
                        "process_output",
                        (process, line.rstrip("\r\n")),
                    ))
        finally:
            if process.stdout is not None:
                process.stdout.close()
            code = process.wait()
            self.messages.put(("process_exit", (process, code)))

    def _handle_process_output(self, message: str) -> None:
        if not message:
            return

        self._append_log(message)
        match = re.search(
            r"collected\s+(\d+).*?delivered\s+(\d+).*?"
            r"pending\s+(\d+).*?checkpoint\s+(\d+)",
            message,
            re.IGNORECASE,
        )
        if match:
            discovered, delivered, pending, checkpoint = match.groups()
            self.metrics.set(
                f"Last cycle: {discovered} collected · {delivered} delivered · "
                f"{pending} pending · checkpoint {checkpoint}"
            )

        if "Heartbeat OK" in message:
            self.status.set("Monitoring active · last heartbeat succeeded.")
        elif "Server unavailable" in message:
            self.status.set("Server unavailable · events remain queued locally.")
        elif "authentication failed" in message.lower():
            self.status.set("Agent authentication failed. Re-enrollment is required.")
        elif "Windows Security event log" in message:
            self.status.set("Windows Security event log reported an error.")

    def _poll_messages(self) -> None:
        if self.closing:
            return

        while True:
            try:
                kind, payload = self.messages.get_nowait()
            except thread_queue.Empty:
                break

            if kind == "process_output":
                process, message = payload
                if process is self.process:
                    self._handle_process_output(message)

            elif kind == "process_exit":
                process, code = payload
                if process is self.process:
                    task = self.process_task
                    self.process = None
                    self.process_task = None
                    if code == 0:
                        self.status.set(
                            "Collection batch finished; review delivery results below."
                            if task == "collect"
                            else "Diagnostics complete."
                            if task == "diagnostics"
                            else "Monitoring stopped."
                        )
                    else:
                        self.status.set(
                            f"Agent task '{task}' exited with code {code}."
                        )
                    self._append_log(
                        f"Agent task '{task}' exited with code {code}."
                    )
                    self._update_actions()

            elif kind == "enrollment_pending":
                self.enrolling = False
                self.status.set(
                    "Waiting for administrator approval. Retry Connect after approval."
                )
                self._append_log(
                    "Enrollment request is pending administrator approval."
                )
                messagebox.showinfo(
                    "Approval required",
                    "The server received this device's request. Ask the administrator "
                    "to approve it, then click Connect device again.",
                )
                self._update_actions()

            elif kind == "enrollment_success":
                self.enrolling = False
                self._refresh_config_status()
                self.status.set(
                    "Device enrolled. Run diagnostics, collect a batch, or start monitoring."
                )
                self.invitation.delete(0, "end")
                self.invitation_code.delete(0, "end")
                self._append_log("Device enrollment completed successfully.")
                self._update_actions()

            elif kind == "enrollment_error":
                self.enrolling = False
                self.status.set("Device enrollment failed.")
                self._append_log(f"Enrollment failed: {payload}")
                messagebox.showerror("Connection failed", payload)
                self._update_actions()

        self.root.after(150, self._poll_messages)

    def diagnose(self) -> None:
        self._start_process("diagnostics", ["diagnostics"])

    def _selected_batch_size(self) -> str:
        return self.batch_size.get()

    def collect_now(self) -> None:
        self._start_process(
            "collect",
            ["collect", "--batch-size", self._selected_batch_size()],
        )

    def start(self) -> None:
        self._start_process(
            "run",
            ["run", "--batch-size", self._selected_batch_size()],
        )

    @staticmethod
    def _send_stop_request(process: subprocess.Popen) -> None:
        stream = process.stdin
        if stream is None or stream.closed:
            return
        try:
            stream.write("\n")
            stream.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def stop(self) -> None:
        process = self.process
        if (
            process is None
            or process.poll() is not None
            or self.process_task != "run"
        ):
            return

        self._send_stop_request(process)
        self.status.set("Stop requested · finishing the current operation...")
        self._append_log("Graceful stop requested.")

        self.stop_button.configure(state="disabled")

    def close(self) -> None:
        self.closing = True
        process = self.process
        if (
            process is not None
            and process.poll() is None
            and self.process_task == "run"
        ):
            self._send_stop_request(process)
        self.root.destroy()


def main():
    root = tk.Tk()
    AgentWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
