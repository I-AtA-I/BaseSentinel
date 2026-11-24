# BaseSentinel Windows Agent (MVP)

The Windows endpoint agent can run as a single, machine-wide collector under the Windows LocalSystem account. It starts at system boot, before any user signs in, and monitors the computer for every Windows account. The GUI remains optional. The system-wide collector runs from a protected ProgramData copy of its Python runtime and application code.

## Requirements

- Windows 10/11 or Windows Server with Task Scheduler and PowerShell.
- Python 3.12+ installed on the device.
- Administrator approval for the system-wide startup installation.
- A BaseSentinel server reachable over HTTPS (plain HTTP is accepted only for localhost development).

## Install

From the repository root:

```powershell
py -m pip install -e .
```

## Enroll

Create a short-lived pairing code in the BaseSentinel admin UI/API, then run:

```powershell
basesentinel-agent enroll --server https://siem.example.com --pairing-code XXXX-XXXX-XXXX
```

The one-time pairing code is exchanged for an agent credential. The credential is protected using Windows DPAPI for the current Windows user and stored under `%LOCALAPPDATA%\BaseSentinel`.

## Collect once

```powershell
basesentinel-agent collect
```

The MVP reads a limited allowlist from the Windows Security log: 4624, 4625, 4672, and 4720. It sends normalized events to `POST /api/v1/events`. Events are kept in a local SQLite queue until the server acknowledges them; stable event IDs make retries idempotent.

## Continuous collection

Start a visible foreground process:

```powershell
basesentinel-agent run
```

By default, the agent runs a collection cycle every 60 seconds and attempts to deliver up to 500 queued events per cycle. Each cycle first makes an authenticated identity request, which also refreshes the server-side heartbeat, then reads the next Security log batch and delivers queued events. Configure the interval and delivery limit if needed (the delivery limit is 1–500):

```powershell
basesentinel-agent run --interval 30 --batch-size 250
```

Stop the foreground process with `Ctrl+C`. If the server is unavailable, pending events stay in the local SQLite queue and the agent retries on the next cycle. Authentication failures (HTTP 401/403) stop the process so the endpoint can be re-enrolled or its access fixed.

### Windowless background mode

Start an independent background process that has no console window and continues after the terminal or GUI closes:

```powershell
basesentinel-agent start --interval 60 --batch-size 500
basesentinel-agent background-status
basesentinel-agent stop
```

The background worker is a separate `pythonw.exe` process. It is visible in Windows Task Manager, holds a single-instance process lock, and writes its output to `%LOCALAPPDATA%\\BaseSentinel\\agent.log`. The GUI can show the worker state and read this log while it is open. Closing the GUI does not stop the worker. Use **Stop agent** in the GUI or `basesentinel-agent stop` to request a graceful shutdown; an in-progress Windows Event Log read or HTTP request is allowed to finish before the process exits.

After enrolling the endpoint under the Windows account that owns its enrollment credential, install the machine-wide collector with:

## Automatic startup

```powershell
basesentinel-agent startup-install --interval 60 --batch-size 500
basesentinel-agent startup-status
```

This requests one system-wide installation. Windows displays a UAC prompt so an Administrator can explicitly approve the changes. After approval, BaseSentinel copies the required Python runtime and agent code to ProgramData\BaseSentinel\Runtime, restricts the runtime so ordinary users can read and execute but cannot modify it, and stores the encrypted enrollment credential and event queue under ProgramData\BaseSentinel\Data. The credential is protected with Windows DPAPI machine scope and the data directory is restricted to SYSTEM and Administrators.

The visible Task Scheduler task named BaseSentinel Agent runs as NT AUTHORITY\SYSTEM at Windows boot. It is one collector for the whole computer, not one copy per logged-in user, and it can read the Windows Security log without relying on each user's Event Log Readers token. It starts before sign-in and restarts after a task failure. It does not run the optional GUI.

Remove automatic startup with:

```powershell
basesentinel-agent startup-remove
```

Removing automatic startup requires Administrator approval. It stops and removes the system task, but deliberately retains the protected runtime and machine data so event history and configuration are not silently deleted. Use `basesentinel-agent stop` to stop a running collector without disabling the next boot trigger.

## Check enrollment

```powershell
basesentinel-agent status
```

Reading the Security log may require an elevated terminal or membership in the local Event Log Readers group. The collector does not change audit policy or Windows security settings.

## Scope and limitations

- The system-wide automatic collector runs as LocalSystem from a protected copy under ProgramData. It starts at boot and covers all Windows accounts; it does not start one collector per user.
- The collector stores a Windows Security EventRecordID checkpoint alongside queued events in one SQLite transaction. It reads ordered batches of up to 1,000 matching records, so backlogs can be drained over repeated cycles without relying on a short time window. If the Windows Security log is cleared and its record ID resets below the saved checkpoint, collection restarts from the beginning of the retained log.
- Initial enrollment still takes place in the current Windows user session. The system-wide installer securely transfers the token into a machine-scope DPAPI configuration for the LocalSystem collector.
- Treat event messages and event data as security telemetry; review retention and access controls on the SIEM server.


## Graphical setup

Install the project in its virtual environment, then launch:

```powershell
basesentinel-agent-gui
```

Use either the one-time invitation link or the invitation code plus the server URL. The current invitation workflow does not require a Server ID, server access code, or connection password. The client exchanges the invitation for an individual agent credential and stores it using Windows DPAPI.

The GUI is packaged as a windowed Windows application so launching it does not open an extra console. **Start background** launches a per-user windowless collector when system-wide startup has not been installed. Once the machine-wide task is installed, a separate per-user collector is blocked to avoid duplicate event collection. Use the CLI startup-status and stop commands to inspect or stop the system-wide task. Automatic startup is configured separately with the CLI commands above and requires Administrator approval.

## Enrollment policy

The administrator can choose **Automatic**, **Approval required**, or **Disabled** for new invitation-based enrollments. Existing agents continue authenticating with their own individual credentials.

The server still retains internal legacy identity fields for compatibility with the old `/api/v1/agents/enroll-server` endpoint. They are not displayed in the enrollment UI and are not used by the current invitation link/code flow. New devices should be enrolled with one-time invitations.


## Temporary invitation links

Administrators can create single-use enrollment invitations from **Agent enrollment** in the dashboard. Choose an expiry between 5 minutes and 24 hours, then share either the generated HTTPS invitation link or the human-readable invitation code with the device owner. Both represent the same one-time invitation: using either one invalidates the other. The random link token and invitation code are stored only as keyed hashes, shown only when created, and can be revoked before use. The manual code is 16 ambiguity-resistant Base32-style characters grouped for readability.

On Windows, open `basesentinel-agent-gui`. Either paste the complete link into **Invitation link**, or select **Invitation code** and enter the server URL plus the code. The link contains the server address and a temporary token in its URL fragment; browsers do not send the fragment to the server in HTTP requests. The client exchanges the invitation for an individual agent credential. Invitations work in **Automatic** mode or **Approval required** mode; disabled enrollment rejects them. Existing enrolled agents are not affected.


### Approval-required enrollment

The server can also use **Approval required** mode. A device can submit its invitation, but it does not receive an agent credential immediately. The request appears in **Agent enrollment → Enrollment requests** with hostname and platform metadata. An administrator can approve or reject it. After approval, the device owner clicks **Connect device** again with the same invitation link or code to complete enrollment. Rejected requests cannot be reused. Invitations still expire and can be revoked while awaiting review.


## Client overview

Administrators can open **Clients** from the dashboard navigation to view enrolled endpoints, platform and agent versions, last check-in, enrollment time, and current status. Revoking a client disables its agent credentials; historical security events remain available for investigation.


## Agent diagnostics and event delivery

The Windows agent GUI now provides **Run diagnostics**, **Collect now**, **Start monitoring**, and **Stop** actions. Its output panel shows collection results, delivery failures, server errors, queue depth, and the Security log checkpoint. The GUI is not required while continuous background monitoring is running. Closing the GUI does not stop the detached collector.

Run the same checks and lifecycle controls from PowerShell:

```powershell
basesentinel-agent diagnostics
basesentinel-agent collect --batch-size 500
basesentinel-agent drain --batch-size 500
basesentinel-agent start --interval 60 --batch-size 500
basesentinel-agent background-status
basesentinel-agent stop
```

Diagnostics checks the authenticated server connection, local pending queue, checkpoint, and whether the current Windows user can read the Security event log. It does not send events or change the checkpoint. **Collect now** (or the `collect` command) reads new events, persists them and the checkpoint locally, then attempts to deliver up to 500 queued events by default. **Drain backlog** (or the `drain` command) sends only events already stored in the local SQLite queue; it does not read the Windows event log or change the checkpoint. The GUI lets the operator choose a delivery limit of 50, 100, 250, or 500. Continuous mode repeats collection and delivery, and sends an authenticated heartbeat every cycle. A large pending count is a backlog, not a delivery confirmation; it decreases as the server acknowledges queued events.

The current collector reads only Windows Security event IDs **4624**, **4625**, **4672**, and **4720**. It does not ingest every Windows event or events from other channels. The Windows account running the agent must have permission to read the Security log. If diagnostics reports access denied, run the agent under an account with the required Security log read permission.

A non-zero pending count means events are still stored locally and have not yet been acknowledged by the server. They remain queued for another delivery attempt. The dashboard currently shows aggregate event counts; the `GET /api/v1/events` endpoint provides individual event records.
