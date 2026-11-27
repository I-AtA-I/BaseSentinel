from __future__ import annotations

import time

from basesentinel_agent import gui


class _Var:
    def __init__(self):
        self.value = None

    def set(self, value):
        self.value = value


class _Root:
    def __init__(self):
        self.scheduled = []

    def after(self, delay, callback):
        self.scheduled.append((delay, callback))


def _window(*, running: bool):
    app = gui.AgentWindow.__new__(gui.AgentWindow)
    app.closing = False
    app.runtime_state_checked = True
    app.runtime_state_error = False
    app.background_running = running
    app.status_detail = _Var()
    app.root = _Root()
    app.log = []
    app.updates = 0
    app._append_activity = lambda message, tag=None: app.log.append((message, tag))

    def update_actions():
        app.updates += 1

    app._update_actions = update_actions
    app._refresh_runtime_state = lambda: None
    return app


def test_expect_runtime_locks_the_buttons_and_shows_a_waiting_message():
    app = _window(running=True)

    app._expect_runtime("stopped")

    assert app.expected_runtime == "stopped"
    assert "stop" in app.status_detail.value
    assert app.updates == 1


def test_still_running_keeps_waiting_and_polls_again():
    app = _window(running=True)
    app._expect_runtime("stopped")
    app.log.clear()

    app._check_runtime_expectation()

    assert app.expected_runtime == "stopped"
    assert app.log == []
    assert [delay for delay, _callback in app.root.scheduled] == [1500]


def test_reaching_the_requested_state_unlocks_and_reports_it():
    app = _window(running=True)
    app._expect_runtime("stopped")
    app.background_running = False
    app.updates = 0

    app._check_runtime_expectation()

    assert app.expected_runtime is None
    assert app.log == [("System-wide collector stopped.", "success")]
    assert app.updates == 1
    assert app.root.scheduled == []


def test_start_expectation_is_reached_when_collector_runs():
    app = _window(running=False)
    app._expect_runtime("running")
    app.background_running = True

    app._check_runtime_expectation()

    assert app.expected_runtime is None
    assert app.log == [("System-wide collector is running.", "success")]


def test_timeout_unlocks_the_buttons_and_reports_an_error():
    app = _window(running=True)
    app._expect_runtime("stopped")
    app.expected_runtime_deadline = time.monotonic() - 1

    app._check_runtime_expectation()

    assert app.expected_runtime is None
    assert app.log[-1][1] == "error"
    assert "did not stop" in app.log[-1][0]


def test_status_check_errors_do_not_count_as_stopped():
    app = _window(running=False)
    app._expect_runtime("stopped")
    app.runtime_state_error = True

    app._check_runtime_expectation()

    assert app.expected_runtime == "stopped"
    assert app.log == []
