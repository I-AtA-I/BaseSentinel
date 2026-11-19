from __future__ import annotations

import platform
import queue as thread_queue
import socket
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from basesentinel_agent.background import (
    agent_log_path,
    background_status,
    console_python_executable,
)
from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.storage import AgentConfigStore, default_data_dir


COLORS = {
    "background": "#0b1018",
    "sidebar": "#080d14",
    "panel": "#111a26",
    "panel_alt": "#162231",
    "border": "#263547",
    "text": "#e6edf5",
    "muted": "#8594a7",
    "accent": "#43d6c5",
    "accent_hover": "#65e4d5",
    "danger": "#ef6b76",
    "success": "#5bd39a",
    "warning": "#f0bd68",
    "input": "#0c1420",
    "log": "#09111b",
}


class AgentWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("BaseSentinel | Endpoint")
        self.root.geometry("1180x820")
        self.root.minsize(1000, 720)
        self.root.configure(background=COLORS["background"])

        self.messages = thread_queue.Queue()
        self.process: subprocess.Popen | None = None
        self.process_task: str | None = None
        self.enrolling = False
        self.control_busy = False
        self.closing = False
        self.config_loaded = False
        self.background_running = False
        self.log_offset = 0

        self.batch_size = tk.StringVar(value="500")
        self.interval = tk.StringVar(value="60")
        self.status_text = tk.StringVar(value="Checking agent status…")
        self.status_detail = tk.StringVar(value="No background worker detected")
        self.agent_value = tk.StringVar(value="Not enrolled")
        self.server_value = tk.StringVar(value="—")
        self.pid_value = tk.StringVar(value="—")
        self.queue_value = tk.StringVar(value="—")
        self.last_activity = tk.StringVar(value="Waiting for first collection cycle")

        self._configure_styles()
        self._build_interface()
        self._refresh_config_status()
        self._refresh_runtime_state()
        self._read_log_updates(initial=True)
        self._append_activity("BaseSentinel endpoint console opened.", "info")

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(150, self._poll_messages)
        self.root.after(1200, self._periodic_refresh)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        bg = COLORS["background"]
        panel = COLORS["panel"]
        text = COLORS["text"]
        muted = COLORS["muted"]

        style.configure(".", font=("Segoe UI", 9))
        style.configure("TFrame", background=panel)
        style.configure("TLabel", background=panel, foreground=text)
        style.configure("App.TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("Sidebar.TFrame", background=COLORS["sidebar"])
        style.configure("App.TLabel", background=bg, foreground=text)
        style.configure("Panel.TLabel", background=panel, foreground=text)
        style.configure("Muted.TLabel", background=panel, foreground=muted)
        style.configure("Sidebar.TLabel", background=COLORS["sidebar"], foreground=muted)
        style.configure(
            "Title.TLabel",
            background=bg,
            foreground=text,
            font=("Segoe UI Semibold", 23),
        )
        style.configure(
            "Section.TLabel",
            background=panel,
            foreground=text,
            font=("Segoe UI Semibold", 11),
        )
        style.configure(
            "Overline.TLabel",
            background=bg,
            foreground=COLORS["accent"],
            font=("Segoe UI Semibold", 8),
        )
        style.configure(
            "Accent.TButton",
            background=COLORS["accent"],
            foreground="#07131a",
            borderwidth=0,
            padding=(15, 9),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "Accent.TButton",
            background=[("active", COLORS["accent_hover"]), ("disabled", "#31424d")],
            foreground=[("disabled", "#8a98a4")],
        )
        style.configure(
            "Secondary.TButton",
            background=COLORS["panel_alt"],
            foreground=text,
            borderwidth=1,
            bordercolor=COLORS["border"],
            padding=(12, 8),
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#203246"), ("disabled", "#17212d")],
            foreground=[("disabled", "#718094")],
        )
        style.configure(
            "Danger.TButton",
            background="#3a2029",
            foreground="#ffb6bd",
            borderwidth=1,
            bordercolor="#70404a",
            padding=(12, 8),
        )
        style.map("Danger.TButton", background=[("active", "#512832")])
        style.configure(
            "TEntry",
            fieldbackground=COLORS["input"],
            foreground=text,
            insertcolor=text,
            bordercolor=COLORS["border"],
            lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
            padding=8,
        )
        style.configure(
            "TCombobox",
            fieldbackground=COLORS["input"],
            background=COLORS["panel_alt"],
            foreground=text,
            arrowcolor=COLORS["accent"],
            bordercolor=COLORS["border"],
            padding=6,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", COLORS["input"])],
            foreground=[("readonly", text)],
            selectbackground=[("readonly", COLORS["input"])],
            selectforeground=[("readonly", text)],
        )
        style.configure(
            "TNotebook",
            background=panel,
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=COLORS["panel_alt"],
            foreground=muted,
            padding=(14, 8),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", panel)],
            foreground=[("selected", COLORS["accent"])],
        )

    def _build_interface(self) -> None:
        shell = tk.Frame(self.root, bg=COLORS["background"])
        shell.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(
            shell,
            bg=COLORS["sidebar"],
            width=224,
            padx=18,
            pady=22,
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        main = tk.Frame(shell, bg=COLORS["background"], padx=24, pady=20)
        main.pack(side="left", fill="both", expand=True)

        self._build_sidebar()
        self._build_main(main)

    def _build_sidebar(self) -> None:
        brand = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
        brand.pack(fill="x", pady=(0, 35))

        mark = tk.Label(
            brand,
            text="B",
            bg=COLORS["accent"],
            fg="#07131a",
            font=("Segoe UI Semibold", 19),
            width=2,
            height=1,
        )
        mark.pack(side="left", padx=(0, 11))
        brand_text = tk.Frame(brand, bg=COLORS["sidebar"])
        brand_text.pack(side="left")
        tk.Label(
            brand_text,
            text="BASESENTINEL",
            bg=COLORS["sidebar"],
            fg=COLORS["text"],
            font=("Segoe UI Semibold", 11),
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text="ENDPOINT CLIENT",
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=("Segoe UI", 7, "bold"),
        ).pack(anchor="w", pady=(2, 0))

        self._side_heading("WORKSPACE")
        self._side_item("◈", "Endpoint overview", selected=True)
        self._side_item("⌁", "Event collection")
        self._side_item("▤", "Local event queue")

        self._side_heading("CONNECTION")
        self.sidebar_status_dot = tk.Label(
            self.sidebar,
            text="●",
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=("Segoe UI", 9),
        )
        status_row = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
        status_row.pack(fill="x", pady=(4, 18))
        self.sidebar_status_dot.pack_forget()
        self.sidebar_status_dot = tk.Label(
            status_row,
            text="●",
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=("Segoe UI", 9),
        )
        self.sidebar_status_dot.pack(side="left", padx=(2, 8))
        self.sidebar_status_label = tk.Label(
            status_row,
            text="Checking…",
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=("Segoe UI", 9),
        )
        self.sidebar_status_label.pack(side="left")

        info = tk.Frame(
            self.sidebar,
            bg=COLORS["panel"],
            padx=12,
            pady=12,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        info.pack(side="bottom", fill="x")
        tk.Label(
            info,
            text="COLLECTOR SCOPE",
            bg=COLORS["panel"],
            fg=COLORS["accent"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w")
        tk.Label(
            info,
            text="Windows Security\n4624 · 4625\n4672 · 4720",
            justify="left",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Consolas", 9),
            pady=7,
        ).pack(anchor="w")
        tk.Label(
            info,
            text="Runs under the current Windows user.",
            justify="left",
            wraplength=175,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w")

        tk.Label(
            self.sidebar,
            text="BASESENTINEL  /  0.1.0",
            bg=COLORS["sidebar"],
            fg="#536174",
            font=("Consolas", 8),
        ).pack(side="bottom", anchor="w", pady=(0, 13))

    def _side_heading(self, text: str) -> None:
        tk.Label(
            self.sidebar,
            text=text,
            bg=COLORS["sidebar"],
            fg="#65758a",
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", pady=(0, 10))

    def _side_item(self, icon: str, text: str, selected: bool = False) -> None:
        bg = "#142430" if selected else COLORS["sidebar"]
        fg = COLORS["accent"] if selected else COLORS["muted"]
        row = tk.Frame(self.sidebar, bg=bg, padx=10, pady=9)
        row.pack(fill="x", pady=(0, 4))
        tk.Label(
            row,
            text=icon,
            bg=bg,
            fg=fg,
            font=("Segoe UI", 11),
        ).pack(side="left", padx=(0, 10))
        tk.Label(
            row,
            text=text,
            bg=bg,
            fg=COLORS["text"] if selected else COLORS["muted"],
            font=("Segoe UI Semibold" if selected else "Segoe UI", 9),
        ).pack(side="left")

    def _build_main(self, parent: tk.Frame) -> None:
        header = tk.Frame(parent, bg=COLORS["background"])
        header.pack(fill="x", pady=(0, 17))

        title_area = tk.Frame(header, bg=COLORS["background"])
        title_area.pack(side="left")
        ttk.Label(
            title_area,
            text="ENDPOINT / OVERVIEW",
            style="Overline.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            title_area,
            text="Endpoint agent",
            style="Title.TLabel",
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            title_area,
            text="Manage enrollment, collection and background monitoring.",
            style="App.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        right_header = tk.Frame(header, bg=COLORS["background"])
        right_header.pack(side="right", anchor="n")
        self.header_status = tk.Label(
            right_header,
            text="●  CHECKING",
            bg="#17232c",
            fg=COLORS["muted"],
            padx=12,
            pady=7,
            font=("Segoe UI Semibold", 8),
        )
        self.header_status.pack(anchor="e", pady=(3, 0))
        ttk.Label(
            right_header,
            text="LOCAL WINDOWS DEVICE",
            style="Overline.TLabel",
        ).pack(anchor="e", pady=(7, 0))

        stats = tk.Frame(parent, bg=COLORS["background"])
        stats.pack(fill="x", pady=(0, 15))
        for col in range(3):
            stats.grid_columnconfigure(col, weight=1, uniform="stats")

        self._stat_card(stats, 0, "AGENT STATUS", self.status_text, "●")
        self._stat_card(stats, 1, "PENDING EVENTS", self.queue_value, "▤")
        self._stat_card(stats, 2, "BACKGROUND PID", self.pid_value, "⌘")

        body = tk.Frame(parent, bg=COLORS["background"])
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=6, uniform="body")
        body.grid_columnconfigure(1, weight=5, uniform="body")
        body.grid_rowconfigure(0, weight=0)
        body.grid_rowconfigure(1, weight=1)

        left = tk.Frame(body, bg=COLORS["background"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        right = tk.Frame(body, bg=COLORS["background"])
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        self._build_enrollment_card(left)
        self._build_monitoring_card(left)
        self._build_device_card(right)
        self._build_activity_card(body)

    def _stat_card(
        self,
        parent: tk.Frame,
        column: int,
        title: str,
        value: tk.StringVar,
        icon: str,
    ) -> None:
        card = tk.Frame(
            parent,
            bg=COLORS["panel"],
            padx=14,
            pady=12,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 7, 7))
        top = tk.Frame(card, bg=COLORS["panel"])
        top.pack(fill="x")
        tk.Label(
            top,
            text=title,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI Semibold", 8),
        ).pack(side="left")
        tk.Label(
            top,
            text=icon,
            bg=COLORS["panel"],
            fg=COLORS["accent"],
            font=("Segoe UI", 12),
        ).pack(side="right")
        tk.Label(
            card,
            textvariable=value,
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI Semibold", 13),
            anchor="w",
        ).pack(fill="x", pady=(7, 0))

    def _panel(
        self,
        parent: tk.Widget,
        title: str,
        subtitle: str | None = None,
        **grid_options,
    ) -> tk.Frame:
        panel = tk.Frame(
            parent,
            bg=COLORS["panel"],
            padx=15,
            pady=13,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        panel.pack(fill="x", pady=(0, 12))
        heading = tk.Frame(panel, bg=COLORS["panel"])
        heading.pack(fill="x", pady=(0, 10))
        tk.Label(
            heading,
            text=title,
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w")
        if subtitle:
            tk.Label(
                heading,
                text=subtitle,
                bg=COLORS["panel"],
                fg=COLORS["muted"],
                font=("Segoe UI", 8),
            ).pack(anchor="w", pady=(2, 0))
        return panel

    def _build_enrollment_card(self, parent: tk.Frame) -> None:
        panel = self._panel(
            parent,
            "Connect this device",
            "Use a one-time invitation from your BaseSentinel administrator.",
        )

        notebook = ttk.Notebook(panel)
        notebook.pack(fill="x", expand=True)

        link_tab = ttk.Frame(notebook, padding=(8, 12, 8, 8))
        code_tab = ttk.Frame(notebook, padding=(8, 12, 8, 8))
        notebook.add(link_tab, text="Invitation link")
        notebook.add(code_tab, text="Invitation code")

        ttk.Label(
            link_tab,
            text="Paste the complete invitation link",
            style="Panel.TLabel",
        ).pack(anchor="w")
        self.invitation = ttk.Entry(link_tab)
        self.invitation.pack(fill="x", pady=(6, 4))
        ttk.Label(
            link_tab,
            text="The server address is included in the link.",
            style="Muted.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            code_tab,
            text="Server URL",
            style="Panel.TLabel",
        ).pack(anchor="w")
        self.server_url = ttk.Entry(code_tab)
        self.server_url.pack(fill="x", pady=(5, 8))
        ttk.Label(
            code_tab,
            text="Invitation code",
            style="Panel.TLabel",
        ).pack(anchor="w")
        self.invitation_code = ttk.Entry(
            code_tab,
            font=("Consolas", 12),
        )
        self.invitation_code.pack(fill="x", pady=(5, 4))
        ttk.Label(
            code_tab,
            text="Enter the code exactly as provided.",
            style="Muted.TLabel",
        ).pack(anchor="w")

        action_row = tk.Frame(panel, bg=COLORS["panel"])
        action_row.pack(fill="x", pady=(8, 0))
        self.connect_button = ttk.Button(
            action_row,
            text="Connect device",
            style="Accent.TButton",
            command=lambda: self.connect(notebook.index("current")),
        )
        self.connect_button.pack(side="left")
        ttk.Label(
            action_row,
            text="Credentials protected by Windows DPAPI",
            style="Muted.TLabel",
        ).pack(side="right", padx=(8, 0))

    def _build_monitoring_card(self, parent: tk.Frame) -> None:
        panel = self._panel(
            parent,
            "Background monitoring",
            "Runs independently of this window. The process stays visible in Task Manager.",
        )

        settings = tk.Frame(panel, bg=COLORS["panel"])
        settings.pack(fill="x", pady=(0, 11))

        tk.Label(
            settings,
            text="DELIVERY BATCH",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI Semibold", 8),
        ).pack(side="left")
        self.batch_size_select = ttk.Combobox(
            settings,
            textvariable=self.batch_size,
            values=("50", "100", "250", "500"),
            width=6,
            state="readonly",
        )
        self.batch_size_select.pack(side="left", padx=(8, 18))

        tk.Label(
            settings,
            text="INTERVAL (SEC)",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI Semibold", 8),
        ).pack(side="left")
        self.interval_entry = ttk.Entry(
            settings,
            textvariable=self.interval,
            width=7,
        )
        self.interval_entry.pack(side="left", padx=(8, 0))

        controls = tk.Frame(panel, bg=COLORS["panel"])
        controls.pack(fill="x")
        self.start_button = ttk.Button(
            controls,
            text="Start background",
            style="Accent.TButton",
            command=self.start_background,
        )
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(
            controls,
            text="Stop agent",
            style="Danger.TButton",
            command=self.stop_background,
            state="disabled",
        )
        self.stop_button.pack(side="left", padx=(8, 0))

        tools = tk.Frame(panel, bg=COLORS["panel"])
        tools.pack(fill="x", pady=(12, 0))
        self.diagnostics_button = ttk.Button(
            tools,
            text="Diagnostics",
            style="Secondary.TButton",
            command=self.diagnose,
        )
        self.diagnostics_button.pack(side="left")
        self.collect_button = ttk.Button(
            tools,
            text="Collect now",
            style="Secondary.TButton",
            command=self.collect_now,
        )
        self.collect_button.pack(side="left", padx=(6, 0))
        self.drain_button = ttk.Button(
            tools,
            text="Drain queue",
            style="Secondary.TButton",
            command=self.drain_backlog,
        )
        self.drain_button.pack(side="left", padx=(6, 0))

    def _build_device_card(self, parent: tk.Frame) -> None:
        panel = self._panel(
            parent,
            "Device details",
            "Enrollment identity and local runtime information.",
        )

        self._detail_row(panel, "AGENT ID", self.agent_value)
        self._detail_row(panel, "SERVER", self.server_value)
        self._detail_row(panel, "WORKER PID", self.pid_value)
        self._detail_row(panel, "QUEUE", self.queue_value)
        self._detail_row(panel, "LAST ACTIVITY", self.last_activity)

        note = tk.Frame(panel, bg=COLORS["panel_alt"], padx=10, pady=9)
        note.pack(fill="x", pady=(9, 0))
        tk.Label(
            note,
            text="NO AUTO-START",
            bg=COLORS["panel_alt"],
            fg=COLORS["accent"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w")
        tk.Label(
            note,
            text=(
                "Background collection starts only when you press Start. "
                "Closing this window does not stop an active worker."
            ),
            bg=COLORS["panel_alt"],
            fg=COLORS["muted"],
            justify="left",
            wraplength=310,
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(4, 0))

    def _detail_row(self, parent: tk.Frame, title: str, value: tk.StringVar) -> None:
        row = tk.Frame(parent, bg=COLORS["panel"])
        row.pack(fill="x", pady=4)
        tk.Label(
            row,
            text=title,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI Semibold", 7),
        ).pack(anchor="w")
        tk.Label(
            row,
            textvariable=value,
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI", 9),
            anchor="w",
            wraplength=330,
            justify="left",
        ).pack(fill="x", pady=(1, 0))

    def _build_activity_card(self, parent: tk.Frame) -> None:
        panel = tk.Frame(
            parent,
            bg=COLORS["panel"],
            padx=15,
            pady=12,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        panel.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(2, 0))
        panel.grid_rowconfigure(1, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        header = tk.Frame(panel, bg=COLORS["panel"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        tk.Label(
            header,
            text="Activity log",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Segoe UI Semibold", 10),
        ).pack(side="left")
        tk.Label(
            header,
            text="LIVE  /  LOCAL LOG FILE",
            bg=COLORS["panel"],
            fg=COLORS["accent"],
            font=("Segoe UI Semibold", 8),
        ).pack(side="right")

        log_frame = tk.Frame(panel, bg=COLORS["log"])
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.log = tk.Text(
            log_frame,
            height=10,
            wrap="word",
            state="disabled",
            bg=COLORS["log"],
            fg="#c7d4e3",
            insertbackground=COLORS["text"],
            selectbackground="#264354",
            relief="flat",
            borderwidth=0,
            padx=12,
            pady=10,
            font=("Cascadia Code", 9),
        )
        self.log.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scrollbar.set)
        self.log.tag_configure("error", foreground="#ff8790")
        self.log.tag_configure("success", foreground=COLORS["success"])
        self.log.tag_configure("info", foreground=COLORS["accent"])

        footer = tk.Frame(panel, bg=COLORS["panel"])
        footer.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.log_path_label = tk.Label(
            footer,
            text=f"Log: {agent_log_path()}",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 7),
            anchor="w",
        )
        self.log_path_label.pack(side="left", fill="x", expand=True)
        ttk.Button(
            footer,
            text="Open log folder",
            style="Secondary.TButton",
            command=self.open_log_folder,
        ).pack(side="right")

    def _append_activity(self, message: str, tag: str | None = None) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n", tag or "")
        line_count = int(self.log.index("end-1c").split(".")[0])
        if line_count > 1000:
            self.log.delete("1.0", f"{line_count - 800}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _refresh_config_status(self) -> None:
        try:
            config = AgentConfigStore().load()
        except (RuntimeError, OSError, ValueError):
            self.config_loaded = False
            self.agent_value.set("Not enrolled")
            self.server_value.set("—")
        else:
            self.config_loaded = True
            self.agent_value.set(config["agent_id"])
            self.server_value.set(config["server_url"])

        self._update_actions()

    def _refresh_runtime_state(self) -> None:
        try:
            state = background_status()
            queue = EventQueue(default_data_dir() / "events.sqlite3")
            pending = len(queue)
        except (RuntimeError, OSError, ValueError) as exc:
            self.status_detail.set(str(exc))
            self.queue_value.set("Unavailable")
            self._update_actions()
            return

        self.background_running = state["running"]
        self.pid_value.set(str(state["pid"]) if state["pid"] else "—")
        self.queue_value.set(f"{pending:,} pending")
        self.status_text.set("Running" if self.background_running else "Stopped")

        if self.background_running:
            self.status_detail.set("Collecting in a detached background process")
            self.header_status.configure(
                text="●  BACKGROUND ACTIVE",
                bg="#15352f",
                fg=COLORS["success"],
            )
            self.sidebar_status_dot.configure(fg=COLORS["success"])
            self.sidebar_status_label.configure(
                text="Background agent active",
                fg=COLORS["success"],
            )
        else:
            self.status_detail.set("No background worker is currently running")
            self.header_status.configure(
                text="●  AGENT STOPPED",
                bg="#2b2630",
                fg=COLORS["muted"],
            )
            self.sidebar_status_dot.configure(fg=COLORS["muted"])
            self.sidebar_status_label.configure(
                text="Agent stopped",
                fg=COLORS["muted"],
            )

        self._update_actions()

    def _update_actions(self) -> None:
        idle_task = self.process is None and not self.control_busy
        self.connect_button.configure(
            state=(
                "normal"
                if not self.enrolling and idle_task and not self.background_running
                else "disabled"
            )
        )
        ready = self.config_loaded and idle_task and not self.background_running
        self.diagnostics_button.configure(state="normal" if ready else "disabled")
        self.collect_button.configure(state="normal" if ready else "disabled")
        self.drain_button.configure(state="normal" if ready else "disabled")
        self.start_button.configure(
            state=(
                "normal"
                if self.config_loaded and idle_task and not self.background_running
                else "disabled"
            )
        )
        self.stop_button.configure(
            state=(
                "normal"
                if self.config_loaded and idle_task and self.background_running
                else "disabled"
            )
        )

    def connect(self, tab_index: int) -> None:
        if self.enrolling or self.process is not None or self.control_busy:
            return
        if self.background_running:
            messagebox.showwarning(
                "Agent is running",
                "Stop the background agent before changing this device's enrollment.",
            )
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
        self.status_detail.set("Connecting this device to the BaseSentinel server…")
        self._append_activity("Starting device enrollment.", "info")
        self._update_actions()

        threading.Thread(
            target=self._enroll_worker,
            args=(server, invitation_token, invitation_code),
            daemon=True,
        ).start()

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
            AgentConfigStore().save(server, result["token"], result["agent_id"])
            self.messages.put(("enrollment_success", result))
        except (ValueError, RuntimeError, ConnectionError, AgentApiError, OSError) as exc:
            self.messages.put(("enrollment_error", str(exc)))
        except Exception as exc:
            self.messages.put(("enrollment_error", f"Unexpected enrollment error: {exc}"))

    def _start_task(self, task: str, arguments: list[str]) -> None:
        if self.process is not None or self.control_busy:
            return

        command = [
            sys.executable,
            "-u",
            "-m",
            "basesentinel_agent.cli",
            *arguments,
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            self._append_activity(f"Could not start {task}: {exc}", "error")
            messagebox.showerror("Could not start task", str(exc))
            return

        self.process = process
        self.process_task = task
        self.status_detail.set({
            "diagnostics": "Checking server, queue and Security log access",
            "collect": "Collecting new Windows Security events",
            "drain": "Delivering the existing local event queue",
        }.get(task, "Agent task running"))
        self._update_actions()
        threading.Thread(
            target=self._read_process_output,
            args=(process,),
            daemon=True,
        ).start()

    def _read_process_output(self, process: subprocess.Popen) -> None:
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    self.messages.put((
                        "task_output",
                        (process, line.rstrip("\r\n")),
                    ))
        finally:
            if process.stdout is not None:
                process.stdout.close()
            code = process.wait()
            self.messages.put(("task_exit", (process, code)))

    def _run_control(self, action: str, arguments: list[str]) -> None:
        if self.control_busy or self.process is not None:
            return
        self.control_busy = True
        self.status_detail.set(
            "Starting background worker…" if action == "start"
            else "Requesting graceful shutdown…"
        )
        self._update_actions()
        command = [
            console_python_executable(),
            "-m",
            "basesentinel_agent.cli",
            *arguments,
        ]
        threading.Thread(
            target=self._control_worker,
            args=(action, command),
            daemon=True,
        ).start()

    def _control_worker(self, action: str, command: list[str]) -> None:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=75,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = (result.stdout or "").strip()
            error = (result.stderr or "").strip()
            self.messages.put((
                "control_result",
                (action, result.returncode, output, error),
            ))
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.messages.put(("control_error", (action, str(exc))))

    def start_background(self) -> None:
        if not self.config_loaded:
            messagebox.showinfo("Enrollment required", "Connect this device before starting collection.")
            return
        try:
            batch = int(self.batch_size.get())
            interval = int(self.interval.get())
            if not 1 <= batch <= 500 or not 5 <= interval <= 86400:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Invalid settings",
                "Batch must be 1–500 and interval must be 5–86400 seconds.",
            )
            return
        self._append_activity(
            f"Starting windowless background agent (batch {batch}, interval {interval}s)…",
            "info",
        )
        self._run_control(
            "start",
            ["start", "--batch-size", str(batch), "--interval", str(interval)],
        )

    def stop_background(self) -> None:
        self._append_activity("Requesting background worker shutdown…", "info")
        self._run_control("stop", ["stop", "--timeout", "60"])

    def diagnose(self) -> None:
        self._start_task("diagnostics", ["diagnostics"])

    def collect_now(self) -> None:
        self._start_task(
            "collect",
            ["collect", "--batch-size", self.batch_size.get()],
        )

    def drain_backlog(self) -> None:
        self._start_task(
            "drain",
            ["drain", "--batch-size", self.batch_size.get()],
        )

    def _handle_task_output(self, message: str) -> None:
        if not message:
            return
        lower = message.lower()
        tag = "error" if any(word in lower for word in ("failed", "error", "unavailable")) else None
        if "heartbeat ok" in lower or "server connection: ok" in lower:
            tag = "success"
        self._append_activity(message, tag)

        if "Heartbeat OK" in message:
            self.last_activity.set("Latest collection cycle completed")
        elif "Collected " in message or "Delivered " in message:
            self.last_activity.set(message[:110])
        elif "Agent identity:" in message:
            self.agent_value.set(message.split(":", 1)[-1].strip())

    def _poll_messages(self) -> None:
        if self.closing:
            return

        while True:
            try:
                kind, payload = self.messages.get_nowait()
            except thread_queue.Empty:
                break

            if kind == "task_output":
                process, message = payload
                if process is self.process:
                    self._handle_task_output(message)

            elif kind == "task_exit":
                process, code = payload
                if process is self.process:
                    task = self.process_task
                    self.process = None
                    self.process_task = None
                    self._append_activity(
                        f"Task '{task}' finished with exit code {code}.",
                        "success" if code == 0 else "error",
                    )
                    self._refresh_runtime_state()

            elif kind == "enrollment_pending":
                self.enrolling = False
                self.status_detail.set("Waiting for administrator approval")
                self._append_activity(
                    "Enrollment request is pending administrator approval.",
                    "info",
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
                self._append_activity("Device enrollment completed successfully.", "success")
                self.invitation.delete(0, "end")
                self.invitation_code.delete(0, "end")
                self.status_detail.set("Device enrolled. Start background monitoring when ready.")
                self._update_actions()

            elif kind == "enrollment_error":
                self.enrolling = False
                self.status_detail.set("Device enrollment failed")
                self._append_activity(f"Enrollment failed: {payload}", "error")
                messagebox.showerror("Connection failed", payload)
                self._update_actions()

            elif kind == "control_result":
                action, code, output, error = payload
                self.control_busy = False
                if output:
                    for line in output.splitlines():
                        self._append_activity(line, "success" if code == 0 else "error")
                if error:
                    self._append_activity(error, "error")
                if action == "start" and code == 0:
                    self._append_activity(
                        "Background monitoring is now independent of this GUI.",
                        "success",
                    )
                elif action == "stop" and code == 0:
                    self._append_activity("Background worker stopped cleanly.", "success")
                elif code != 0:
                    messagebox.showerror(
                        "Background agent",
                        output or error or f"Command exited with code {code}.",
                    )
                self._refresh_runtime_state()

            elif kind == "control_error":
                action, error = payload
                self.control_busy = False
                self._append_activity(f"{action.title()} failed: {error}", "error")
                self._refresh_runtime_state()

        self.root.after(150, self._poll_messages)

    def _read_log_updates(self, initial: bool = False) -> None:
        try:
            path = agent_log_path()
            if not path.exists():
                return
            size = path.stat().st_size
            with path.open("rb") as stream:
                if initial:
                    stream.seek(max(0, size - 64 * 1024))
                    self.log_offset = stream.tell()
                elif size < self.log_offset:
                    self.log_offset = 0
                else:
                    stream.seek(self.log_offset)
                data = stream.read(64 * 1024)
                self.log_offset = stream.tell()
            if not data:
                return
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            for line in lines:
                if line.strip():
                    lower = line.lower()
                    tag = (
                        "error"
                        if any(word in lower for word in ("failed", "error", "unavailable"))
                        else "success"
                        if "heartbeat ok" in lower
                        else None
                    )
                    self._append_activity(line, tag)
                    if "Heartbeat OK" in line:
                        self.last_activity.set("Latest background collection cycle completed")
                    if "pending " in line.lower():
                        self.queue_value.set(
                            line.rsplit("pending", 1)[-1].split(";", 1)[0].strip()
                            + " pending"
                        )
        except OSError:
            return

    def _periodic_refresh(self) -> None:
        if self.closing:
            return
        self._refresh_runtime_state()
        self._read_log_updates()
        self.root.after(1500, self._periodic_refresh)

    def open_log_folder(self) -> None:
        path = agent_log_path()
        try:
            subprocess.Popen(
                ["explorer.exe", "/select,", str(path)],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            messagebox.showerror("Could not open log folder", str(exc))

    def close(self) -> None:
        self.closing = True
        # The explicitly started background process is intentionally left running.
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    AgentWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
