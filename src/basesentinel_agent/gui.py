from __future__ import annotations

import os
import platform
import queue as thread_queue
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import traceback
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

from basesentinel_agent.background import (
    agent_cli_command,
    agent_log_path,
    background_status,
)
from basesentinel_windows.startup import is_system_boot_task, is_task_running
from basesentinel_agent.client import AgentApiError, BaseSentinelClient
from basesentinel_agent.queue import EventQueue
from basesentinel_agent.storage import AgentConfigStore, default_data_dir


_SYSTEM_STARTUP_TASK_NAME = "BaseSentinel Agent"


def _endpoint_log_path() -> Path:
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP")
    base = Path(root) if root else Path.home() / "AppData" / "Local"
    return base / "BaseSentinel" / "endpoint.log"


def _write_endpoint_diagnostic(message: str) -> None:
    try:
        path = _endpoint_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        with path.open("a", encoding="utf-8") as stream:
            stream.write(f"[{timestamp}] {message.rstrip()}\n")
    except OSError:
        pass


def _report_tk_callback_exception(exc_type, exc_value, exc_traceback) -> None:
    details = "".join(
        traceback.format_exception(exc_type, exc_value, exc_traceback)
    )
    _write_endpoint_diagnostic("Unhandled Endpoint GUI callback exception:\n" + details)
    try:
        messagebox.showerror(
            "BaseSentinel Endpoint",
            "An unexpected error occurred in the Endpoint window. "
            "Details were written to %LOCALAPPDATA%\\BaseSentinel.",
        )
    except tk.TclError:
        pass


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
    # After an approved Start/Stop request the window keeps polling until the
    # collector really reaches the requested state ("running" or "stopped"),
    # instead of trusting a single early status check.
    expected_runtime: str | None = None
    expected_runtime_deadline: float = 0.0

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
        self.system_wide_installed = False
        self.runtime_check_running = False
        self.runtime_state_checked = False
        self.runtime_state_error = False
        self.system_install_result_running = False
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
        self.root.after(1500, self._periodic_refresh)
        self.root.after(10000, self._periodic_runtime_refresh)

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
            "Queue.Treeview",
            background=COLORS["log"],
            fieldbackground=COLORS["log"],
            foreground=text,
            borderwidth=0,
            relief="flat",
            bordercolor=COLORS["log"],
            lightcolor=COLORS["log"],
            darkcolor=COLORS["log"],
            rowheight=27,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Queue.Vertical.TScrollbar",
            background=COLORS["panel_alt"],
            troughcolor=COLORS["panel"],
            bordercolor=COLORS["panel"],
            arrowcolor=muted,
            relief="flat",
        )
        style.configure(
            "Queue.Treeview.Heading",
            background=COLORS["panel_alt"],
            foreground=muted,
            borderwidth=0,
            font=("Segoe UI Semibold", 8),
            padding=(8, 7),
        )
        style.map(
            "Queue.Treeview",
            background=[("selected", "#264354")],
            foreground=[("selected", text)],
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
        self.nav_buttons = {}
        self._side_item("◈", "Endpoint overview", target="overview", selected=True)
        self._side_item("⌁", "Event collection", target="collection")
        self._side_item("▤", "Local event queue", target="queue")

        self._side_heading("CONNECTION")
        status_row = tk.Frame(self.sidebar, bg=COLORS["sidebar"])
        status_row.pack(fill="x", pady=(4, 18))
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
            text="Windows Security +\nMicrosoft Defender\nAllowlisted events",
            justify="left",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            font=("Consolas", 9),
            pady=7,
        ).pack(anchor="w")
        tk.Label(
            info,
            text="The system-wide collector runs as Windows SYSTEM after Administrator approval.",
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

    def _side_item(
        self,
        icon: str,
        text: str,
        *,
        target: str,
        selected: bool = False,
    ) -> None:
        button = tk.Button(
            self.sidebar,
            text=f"{icon}  {text}",
            command=lambda: self._navigate_to(target),
            anchor="w",
            bg="#142430" if selected else COLORS["sidebar"],
            fg=COLORS["accent"] if selected else COLORS["muted"],
            activebackground="#1b303d",
            activeforeground=COLORS["text"],
            relief="flat",
            borderwidth=0,
            padx=11,
            pady=11,
            font=("Segoe UI Semibold" if selected else "Segoe UI", 9),
            cursor="hand2",
        )
        button.pack(fill="x", pady=(0, 4))
        self.nav_buttons[target] = button

    def _build_main(self, parent: tk.Frame) -> None:
        # Use a plain frame as the page host. The sidebar already provides
        # navigation, so a hidden ttk.Notebook only leaves an unwanted tab frame.
        self.workspace = tk.Frame(parent, bg=COLORS["background"])
        self.workspace.pack(fill="both", expand=True)

        self.pages = {}
        for key in ("overview", "collection", "queue"):
            page = tk.Frame(
                self.workspace,
                bg=COLORS["background"],
                padx=20,
                pady=16,
            )
            page.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[key] = page

        self._build_overview_page(self.pages["overview"])
        self._build_collection_page(self.pages["collection"])
        self._build_queue_page(self.pages["queue"])
        self.current_page = None
        self._navigate_to("overview")

    def _page_heading(
        self,
        parent: tk.Frame,
        overline: str,
        title: str,
        subtitle: str,
        *,
        show_status: bool = False,
    ) -> None:
        header = tk.Frame(parent, bg=COLORS["background"])
        header.pack(fill="x", pady=(0, 17))

        title_area = tk.Frame(header, bg=COLORS["background"])
        title_area.pack(side="left")
        ttk.Label(
            title_area,
            text=overline,
            style="Overline.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            title_area,
            text=title,
            style="Title.TLabel",
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            title_area,
            text=subtitle,
            style="App.TLabel",
        ).pack(anchor="w", pady=(3, 0))

        if show_status:
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

    def _build_overview_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "ENDPOINT / OVERVIEW",
            "Endpoint agent",
            "Manage enrollment and review this device's runtime status.",
            show_status=True,
        )

        stats = tk.Frame(page, bg=COLORS["background"])
        stats.pack(fill="x", pady=(0, 15))
        for col in range(3):
            stats.grid_columnconfigure(col, weight=1, uniform="stats")
        self._stat_card(stats, 0, "AGENT STATUS", self.status_text, "●")
        self._stat_card(stats, 1, "PENDING EVENTS", self.queue_value, "▤")
        self._stat_card(stats, 2, "BACKGROUND PID", self.pid_value, "⌘")

        body = tk.Frame(page, bg=COLORS["background"])
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
        self._build_device_card(right)

    def _build_collection_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "WORKSPACE / COLLECTION",
            "Event collection",
            "Configure and control the detached Windows Security event collector.",
        )

        stats = tk.Frame(page, bg=COLORS["background"])
        stats.pack(fill="x", pady=(0, 15))
        for col in range(3):
            stats.grid_columnconfigure(col, weight=1, uniform="collection-stats")
        self._stat_card(stats, 0, "AGENT STATUS", self.status_text, "●")
        self._stat_card(stats, 1, "PENDING EVENTS", self.queue_value, "▤")
        self._stat_card(stats, 2, "BACKGROUND PID", self.pid_value, "⌘")

        body = tk.Frame(page, bg=COLORS["background"])
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=6, uniform="collection")
        body.grid_columnconfigure(1, weight=5, uniform="collection")
        body.grid_rowconfigure(0, weight=0)
        body.grid_rowconfigure(1, weight=1)

        controls = tk.Frame(body, bg=COLORS["background"])
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._build_monitoring_card(controls)

        scope_parent = tk.Frame(body, bg=COLORS["background"])
        scope_parent.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        scope = self._panel(
            scope_parent,
            "Collector scope",
            "Only the allowlisted Windows Security event types are collected.",
        )
        tk.Label(
            scope,
            text="4624  Successful logon\n4625  Failed logon\n4672  Special privileges assigned\n4720  User account created",
            bg=COLORS["panel"],
            fg=COLORS["text"],
            justify="left",
            anchor="w",
            font=("Cascadia Code", 9),
        ).pack(fill="x", pady=(4, 10))
        tk.Label(
            scope,
            text="The background worker runs independently of this window. After enrollment, use Install system-wide collector from the Start menu to enable one protected collector at Windows boot. Administrator approval is required.",
            bg=COLORS["panel_alt"],
            fg=COLORS["muted"],
            justify="left",
            anchor="w",
            wraplength=300,
            padx=10,
            pady=9,
            font=("Segoe UI", 8),
        ).pack(fill="x")

        self._build_activity_card(body)

    def _build_queue_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "WORKSPACE / LOCAL STORAGE",
            "Local event queue",
            "Inspect events waiting for delivery to the BaseSentinel server.",
        )

        panel = self._panel(
            page,
            "Pending events",
            "The table shows the oldest queued events. Refresh after collection or delivery.",
        )
        toolbar = tk.Frame(panel, bg=COLORS["panel"])
        toolbar.pack(fill="x", pady=(0, 10))
        self.queue_status = tk.StringVar(value="Loading local event queue…")
        tk.Label(
            toolbar,
            textvariable=self.queue_status,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
        ).pack(side="left", fill="x", expand=True)
        ttk.Button(
            toolbar,
            text="Refresh queue",
            style="Secondary.TButton",
            command=self._refresh_queue_table,
        ).pack(side="right")
        self.drain_button = ttk.Button(
            toolbar,
            text="Drain queue",
            style="Accent.TButton",
            command=self.drain_backlog,
        )
        self.drain_button.pack(side="right", padx=(0, 8))

        table_frame = tk.Frame(panel, bg=COLORS["panel"])
        table_frame.pack(fill="both", expand=True)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        columns = ("code", "type", "occurred", "computer", "message")
        self.queue_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=17,
            style="Queue.Treeview",
        )
        headings = {
            "code": ("EVENT ID", 80),
            "type": ("EVENT TYPE", 175),
            "occurred": ("OCCURRED AT (UTC)", 170),
            "computer": ("COMPUTER", 130),
            "message": ("MESSAGE", 360),
        }
        for column, (label, width) in headings.items():
            self.queue_table.heading(column, text=label)
            self.queue_table.column(column, width=width, minwidth=65, anchor="w")
        self.queue_table.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.queue_table.yview,
            style="Queue.Vertical.TScrollbar",
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.queue_table.configure(yscrollcommand=scrollbar.set)
        self._refresh_queue_table()

    def _navigate_to(self, section: str) -> None:
        page = self.pages.get(section)
        if page is None:
            return
        page.tkraise()
        self.current_page = section
        self._update_navigation(section)
        if section == "queue":
            self._refresh_queue_table()

    def _update_navigation(self, selected: str) -> None:
        for key, button in self.nav_buttons.items():
            active = key == selected
            button.configure(
                bg="#142430" if active else COLORS["sidebar"],
                fg=COLORS["accent"] if active else COLORS["muted"],
                font=("Segoe UI Semibold" if active else "Segoe UI", 9),
            )

    def _refresh_queue_table(self) -> None:
        try:
            queue = EventQueue(default_data_dir() / "events.sqlite3")
            pending = queue.pending(limit=50)
            total = len(queue)
        except (RuntimeError, OSError, ValueError) as exc:
            self.queue_status.set(f"Could not read the local queue: {exc}")
            self.queue_value.set("Unavailable")
            return

        self.queue_value.set(f"{total:,} pending")
        for item in self.queue_table.get_children():
            self.queue_table.delete(item)

        for index, event in enumerate(pending):
            event_data = event.get("event_data")
            if not isinstance(event_data, dict):
                event_data = {}
            self.queue_table.insert(
                "",
                "end",
                iid=f"event-{index}",
                values=(
                    event.get("event_code", "—"),
                    event.get("event_type", "—"),
                    event.get("occurred_at", "—"),
                    event_data.get("computer", "—"),
                    str(event.get("message", "—"))[:220],
                ),
            )

        if total:
            self.queue_status.set(
                f"Showing {len(pending)} oldest event(s) of {total:,} pending."
            )
        else:
            self.queue_status.set("The local event queue is empty.")

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

        tab_bar = tk.Frame(panel, bg=COLORS["panel"])
        tab_bar.pack(fill="x", pady=(0, 1))

        content = tk.Frame(panel, bg=COLORS["panel"], height=132)
        content.pack(fill="x", expand=True)
        content.pack_propagate(False)

        link_tab = tk.Frame(content, bg=COLORS["panel"], padx=8, pady=12)
        code_tab = tk.Frame(content, bg=COLORS["panel"], padx=8, pady=12)
        link_tab.place(relx=0, rely=0, relwidth=1, relheight=1)
        code_tab.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.enrollment_tab = 0
        self.enrollment_tab_buttons = []

        def select_tab(index: int) -> None:
            self.enrollment_tab = index
            (link_tab if index == 0 else code_tab).tkraise()
            for button_index, button in enumerate(self.enrollment_tab_buttons):
                active = button_index == index
                button.configure(
                    bg=COLORS["panel_alt"] if active else COLORS["panel"],
                    fg=COLORS["accent"] if active else COLORS["muted"],
                )

        for index, label in enumerate(("Invitation link", "Invitation code")):
            button = tk.Button(
                tab_bar,
                text=label,
                command=lambda selected=index: select_tab(selected),
                bg=COLORS["panel_alt"] if index == 0 else COLORS["panel"],
                fg=COLORS["accent"] if index == 0 else COLORS["muted"],
                activebackground=COLORS["panel_alt"],
                activeforeground=COLORS["text"],
                relief="flat",
                borderwidth=0,
                padx=12,
                pady=8,
                font=("Segoe UI Semibold", 9),
                cursor="hand2",
            )
            button.pack(side="left", padx=(0, 5))
            self.enrollment_tab_buttons.append(button)

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
            command=lambda: self.connect(self.enrollment_tab),
        )
        self.connect_button.pack(side="left")
        ttk.Label(
            action_row,
            text="Credentials protected by Windows DPAPI",
            style="Muted.TLabel",
        ).pack(side="right", padx=(8, 0))

        select_tab(0)

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
            text=(
                "Install system-wide collector"
                if getattr(sys, "frozen", False)
                else "Start background"
            ),
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

    def _build_device_card(self, parent: tk.Frame) -> None:
        panel = self._panel(
            parent,
            "Device details",
            "Enrollment identity and local runtime information.",
        )

        self._detail_row(panel, "AGENT ID", self.agent_value)
        self._detail_row(panel, "RUNTIME STATUS", self.status_detail)
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
        """Inspect Task Scheduler and the local queue without blocking Tk's UI thread."""
        if self.closing or self.runtime_check_running:
            return
        self.runtime_check_running = True
        threading.Thread(
            target=self._runtime_state_worker,
            name="BaseSentinelRuntimeStatus",
            daemon=True,
        ).start()

    def _runtime_state_worker(self) -> None:
        try:
            system_wide = is_system_boot_task(_SYSTEM_STARTUP_TASK_NAME)
            if system_wide:
                payload = {
                    "system_wide": True,
                    "system_wide_running": is_task_running(_SYSTEM_STARTUP_TASK_NAME),
                }
            else:
                state = background_status()
                pending = len(EventQueue(default_data_dir() / "events.sqlite3"))
                payload = {
                    "system_wide": False,
                    "running": bool(state["running"]),
                    "pid": state["pid"],
                    "pending": pending,
                }
        except Exception as exc:
            details = traceback.format_exc()
            _write_endpoint_diagnostic(
                "Runtime status check failed: " + str(exc) + "\n" + details
            )
            payload = {"error": str(exc)}

        self.messages.put(("runtime_state", payload))

    def _apply_runtime_state(self, payload: dict) -> None:
        self.runtime_check_running = False
        if self.closing:
            return

        self.runtime_state_checked = True
        if "error" in payload:
            self.runtime_state_error = True
            self.background_running = False
            self.pid_value.set("—")
            self.status_detail.set(f"Status check failed: {payload['error']}")
            self.queue_value.set("Unavailable")
            self._update_actions()
            return

        self.runtime_state_error = False
        self.system_wide_installed = bool(payload["system_wide"])
        if self.system_wide_installed:
            self.background_running = bool(payload["system_wide_running"])
            self.pid_value.set("SYSTEM")
            self.queue_value.set("Protected")
            self.status_text.set(
                "System-wide · Running" if self.background_running else "System-wide · Stopped"
            )
            self.status_detail.set(
                "Installed and running as SYSTEM"
                if self.background_running
                else "Installed, but stopped. Start the system-wide collector to resume monitoring."
            )
            self.header_status.configure(
                text=(
                    "●  SYSTEM COLLECTOR RUNNING"
                    if self.background_running
                    else "●  SYSTEM COLLECTOR STOPPED"
                ),
                bg="#15352f" if self.background_running else "#2b2630",
                fg=COLORS["success"] if self.background_running else COLORS["muted"],
            )
            self.sidebar_status_dot.configure(
                fg=COLORS["success"] if self.background_running else COLORS["muted"]
            )
            self.sidebar_status_label.configure(
                text=(
                    "System-wide collector running"
                    if self.background_running
                    else "System-wide collector installed · stopped"
                ),
                fg=COLORS["success"] if self.background_running else COLORS["muted"],
            )
            self._update_actions()
            return

        self.background_running = bool(payload["running"])
        self.pid_value.set(str(payload["pid"]) if payload["pid"] else "—")
        self.queue_value.set(f"{payload['pending']:,} pending")
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

    def _expect_runtime(self, expected: str) -> None:
        """Wait until the collector reaches "running" or "stopped"."""
        self.expected_runtime = expected
        self.expected_runtime_deadline = time.monotonic() + 60.0
        self.status_detail.set(
            "Waiting for the system-wide collector to start…"
            if expected == "running"
            else "Waiting for the system-wide collector to stop…"
        )
        self._update_actions()

    def _check_runtime_expectation(self) -> None:
        """Called after every runtime status check while a request is pending."""
        expected = self.expected_runtime
        if expected is None or self.closing:
            return

        want_running = expected == "running"
        reached = (
            self.runtime_state_checked
            and not self.runtime_state_error
            and self.background_running == want_running
        )
        if reached:
            self.expected_runtime = None
            self._append_activity(
                "System-wide collector is running."
                if want_running
                else "System-wide collector stopped.",
                "success",
            )
            self._update_actions()
            return

        if time.monotonic() >= self.expected_runtime_deadline:
            self.expected_runtime = None
            self._append_activity(
                "The system-wide collector did not "
                + ("start" if want_running else "stop")
                + " within 60 seconds. Check the agent log.",
                "error",
            )
            self._update_actions()
            return

        self.status_detail.set(
            "Waiting for the system-wide collector to start…"
            if want_running
            else "Waiting for the system-wide collector to stop…"
        )
        self.root.after(1500, self._refresh_runtime_state)

    def _update_actions(self) -> None:
        idle_task = (
            self.process is None
            and not self.control_busy
            and not self.system_install_result_running
            and self.expected_runtime is None
        )
        self.connect_button.configure(
            state=(
                "normal"
                if (
                    not self.enrolling
                    and idle_task
                    and not self.background_running
                    and not self.system_wide_installed
                )
                else "disabled"
            )
        )
        runtime_ready = self.runtime_state_checked and not self.runtime_state_error
        ready = (
            runtime_ready
            and self.config_loaded
            and idle_task
            and not self.background_running
            and not self.system_wide_installed
        )
        self.batch_size_select.configure(
            state=(
                "readonly"
                if not self.background_running
                and not self.system_wide_installed
                and not self.control_busy
                else "disabled"
            )
        )
        self.interval_entry.configure(
            state=(
                "normal"
                if not self.background_running
                and not self.system_wide_installed
                and not self.control_busy
                else "disabled"
            )
        )
        self.diagnostics_button.configure(state="normal" if ready else "disabled")
        self.collect_button.configure(state="normal" if ready else "disabled")
        self.drain_button.configure(state="normal" if ready else "disabled")
        self.start_button.configure(
            text=(
                "Checking collector status…"
                if not self.runtime_state_checked
                else "Collector status unavailable"
                if self.runtime_state_error
                else "System-wide collector running"
                if self.system_wide_installed and self.background_running
                else "Start system-wide collector"
                if self.system_wide_installed
                else "Install system-wide collector"
                if getattr(sys, "frozen", False)
                else "Start background"
            ),
            state=(
                "normal"
                if runtime_ready
                and self.config_loaded
                and idle_task
                and not self.background_running
                else "disabled"
            ),
        )
        self.stop_button.configure(
            text=(
                "Checking collector status…"
                if not self.runtime_state_checked
                else "Status unavailable"
                if self.runtime_state_error
                else "Stop system-wide collector"
                if self.system_wide_installed
                else "Stop agent"
            ),
            state=(
                "normal"
                if runtime_ready
                and self.config_loaded
                and idle_task
                and self.background_running
                else "disabled"
            ),
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

        try:
            command = agent_cli_command(*arguments)
        except (OSError, RuntimeError) as exc:
            self._append_activity(f"Could not start {task}: {exc}", "error")
            messagebox.showerror("Could not start task", str(exc))
            return

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
        try:
            command = agent_cli_command(*arguments)
        except (OSError, RuntimeError) as exc:
            self._append_activity(f"{action.title()} failed: {exc}", "error")
            messagebox.showerror("Background agent", str(exc))
            return

        self.control_busy = True
        self.status_detail.set(
            "Requesting Administrator approval…" if action == "install"
            else "Starting background worker…" if action == "start"
            else "Restoring the previous per-user collector…" if action == "restore"
            else "Requesting graceful shutdown…"
        )
        self._update_actions()
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

    def _watch_system_install_result(self, result_file: str) -> None:
        """Wait for the elevated helper to write its final result without blocking Tk."""
        path = Path(result_file)
        marker = "BASESENTINEL_INSTALL_EXIT_CODE="
        deadline = time.monotonic() + 180
        while not self.closing and time.monotonic() < deadline:
            try:
                contents = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                contents = ""

            for line in reversed(contents.splitlines()):
                if line.startswith(marker):
                    try:
                        exit_code = int(line.partition("=")[2].strip())
                    except ValueError:
                        break
                    output = contents.split(marker, 1)[0].strip()
                    self.messages.put((
                        "install_result",
                        (str(path), exit_code, output),
                    ))
                    return
            time.sleep(0.5)

        if not self.closing:
            self.messages.put(("install_result_timeout", str(path)))

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
        if getattr(sys, "frozen", False) and self.system_wide_installed:
            self._run_control("system-start", ["startup-start"])
        elif getattr(sys, "frozen", False):
            self._run_control(
                "install",
                [
                    "startup-install",
                    "--batch-size",
                    str(batch),
                    "--interval",
                    str(interval),
                ],
            )
        else:
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
                self.status_detail.set(
                    "Device enrolled. Install the system-wide collector to enable monitoring."
                    if getattr(sys, "frozen", False)
                    else "Device enrolled. Start background monitoring when ready."
                )
                self._update_actions()

            elif kind == "enrollment_error":
                self.enrolling = False
                self.status_detail.set("Device enrollment failed")
                self._append_activity(f"Enrollment failed: {payload}", "error")
                messagebox.showerror("Connection failed", payload)
                self._update_actions()

            elif kind == "runtime_state":
                self._apply_runtime_state(payload)
                self._check_runtime_expectation()

            elif kind == "control_result":
                action, code, output, error = payload
                self.control_busy = False
                if action == "start" and code == 0:
                    self._append_activity("Agent started successfully.", "success")
                elif action == "system-start" and code == 0:
                    self._append_activity(
                        "System-wide collector start was requested.",
                        "success",
                    )
                    self._expect_runtime("running")
                elif action == "restore" and code == 0:
                    self._append_activity(
                        "The previous per-user collector is running again.",
                        "success",
                    )
                elif action == "install" and code == 0:
                    result_file = None
                    for line in output.splitlines():
                        if line.startswith("BASESENTINEL_INSTALL_RESULT_FILE="):
                            result_file = line.partition("=")[2].strip()
                        elif line.strip():
                            self._append_activity(line, "info")
                    if error:
                        self._append_activity(error, "error")
                    if result_file:
                        self.system_install_result_running = True
                        self.status_detail.set(
                            "Waiting for Administrator approval and installation result…"
                        )
                        self._append_activity(
                            "Elevated installer launched; waiting for its final result.",
                            "info",
                        )
                        threading.Thread(
                            target=self._watch_system_install_result,
                            args=(result_file,),
                            name="BaseSentinelSystemInstallResult",
                            daemon=True,
                        ).start()
                    else:
                        self._append_activity(
                            "Installer launch was requested, but no result-log path was returned.",
                            "error",
                        )
                else:
                    if output:
                        for line in output.splitlines():
                            self._append_activity(line, "success" if code == 0 else "error")
                    if error:
                        self._append_activity(error, "error")
                if action == "stop" and code == 0:
                    if self.system_wide_installed:
                        # The elevated stop was only launched; wait for the real result.
                        self._expect_runtime("stopped")
                    else:
                        self._append_activity("Background worker stopped cleanly.", "success")
                elif code != 0:
                    messagebox.showerror(
                        "Background agent",
                        output or error or f"Command exited with code {code}.",
                    )
                self._refresh_runtime_state()

            elif kind == "install_result":
                result_file, code, output = payload
                self.system_install_result_running = False
                for line in output.splitlines():
                    if line.strip():
                        self._append_activity(line, "success" if code == 0 else "error")
                if code == 0:
                    self._append_activity(
                        "System-wide collector installation completed.",
                        "success",
                    )
                    self.status_detail.set("System-wide collector installed; verifying Task Scheduler state…")
                else:
                    details = output or "The elevated installer returned a failure code without details."
                    self.status_detail.set("System-wide collector installation failed")
                    self._run_control(
                        "restore",
                        [
                            "startup-restore-user-worker",
                            "--batch-size",
                            self.batch_size.get(),
                            "--interval",
                            self.interval.get(),
                        ],
                    )
                    messagebox.showerror(
                        "System-wide installation failed",
                        details[-5000:],
                    )
                try:
                    Path(result_file).unlink()
                except OSError:
                    pass
                self._refresh_runtime_state()

            elif kind == "install_result_timeout":
                self.system_install_result_running = False
                self.status_detail.set("The elevated installer did not report completion")
                self._append_activity(
                    f"Installer result timed out. Diagnostic log: {payload}",
                    "error",
                )
                messagebox.showerror(
                    "System-wide installation",
                    "The elevated installer did not report a final result. "
                    f"Its diagnostic log was left at:\n{payload}",
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
        except (OSError, RuntimeError, ValueError) as exc:
            _write_endpoint_diagnostic(f"Could not read the background agent log: {exc}")
            return

    def _periodic_refresh(self) -> None:
        if self.closing:
            return
        self._read_log_updates()
        self.root.after(1500, self._periodic_refresh)

    def _periodic_runtime_refresh(self) -> None:
        if self.closing:
            return
        self._refresh_runtime_state()
        self.root.after(10000, self._periodic_runtime_refresh)

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
        # The detached background worker is intentionally left running when the console closes.
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
        self.root.destroy()


def main() -> None:
    root = None
    try:
        root = tk.Tk()
        root.report_callback_exception = _report_tk_callback_exception
        if "--self-test" in sys.argv[1:]:
            root.withdraw()
            AgentWindow(root)
            root.update_idletasks()
            root.destroy()
            return
        AgentWindow(root)
        root.mainloop()
    except Exception:
        details = traceback.format_exc()
        _write_endpoint_diagnostic(
            "Endpoint GUI startup or main loop failed:\n" + details
        )
        message = (
            "BaseSentinel Endpoint could not start.\\n\\n"
            "The error details were saved to:\\n"
            + str(_endpoint_log_path())
        )
        try:
            if os.name == "nt":
                import ctypes

                ctypes.windll.user32.MessageBoxW(
                    None,
                    message,
                    "BaseSentinel Endpoint",
                    0x10,
                )
            else:
                messagebox.showerror("BaseSentinel Endpoint", message)
        except Exception:
            pass
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass
        raise SystemExit(1)


if __name__ == "__main__":
    main()
