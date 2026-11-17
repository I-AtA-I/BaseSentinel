# BaseSentinel Windows Agent (MVP)

The Windows endpoint agent is an explicitly run, user-visible command-line collector. Continuous mode runs only while its terminal process is open; it is not installed as a service and does not start automatically with Windows.

## Requirements

- Windows 10/11 or Windows Server with PowerShell and access to the Windows Security event log.
- Python 3.12+.
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

Stop the foreground process with `Ctrl+C`. The GUI Stop button sends a graceful stop request and lets the current event operation finish instead of force-killing the process. If the server is unavailable, pending events stay in the local SQLite queue and the agent retries on the next cycle. Authentication failures (HTTP 401/403) stop the process so the endpoint can be re-enrolled or its access fixed.

## Check enrollment

```powershell
basesentinel-agent status
```

Reading the Security log may require an elevated terminal or membership in the local Event Log Readers group. The collector does not change audit policy or Windows security settings.

## Scope and limitations

- Continuous mode is a foreground process only. There is no Windows service, scheduled task, auto-start, remote command execution, or stealth behavior.
- The collector stores a Windows Security EventRecordID checkpoint alongside queued events in one SQLite transaction. It reads ordered batches of up to 1,000 matching records, so backlogs can be drained over repeated cycles without relying on a short time window. If the Windows Security log is cleared and its record ID resets below the saved checkpoint, collection restarts from the beginning of the retained log.
- Run enrollment and collection as the same Windows user so DPAPI can decrypt the stored credential.
- Treat event messages and event data as security telemetry; review retention and access controls on the SIEM server.


## Graphical setup

Install the project in its virtual environment, then launch:

```powershell
basesentinel-agent-gui
```

Use either the one-time invitation link or the invitation code plus the server URL. The current invitation workflow does not require a Server ID, server access code, or connection password. The client exchanges the invitation for an individual agent credential and stores it using Windows DPAPI.

Use **Start monitoring** to launch collection in a background process while the GUI remains open. Closing the GUI stops that process. The GUI does not install a Windows service or configure automatic startup.

## Enrollment policy

The administrator can choose **Automatic**, **Approval required**, or **Disabled** for new invitation-based enrollments. Existing agents continue authenticating with their own individual credentials.

The server still retains internal legacy identity fields for compatibility with the old `/api/v1/agents/enroll-server` endpoint. They are not displayed in the enrollment UI and are not used by the current invitation link/code flow. New devices should be enrolled with one-time invitations.


## Temporary invitation links

Administrators can create single-use enrollment invitations from **Agent enrollment** in the dashboard. Choose an expiry between 5 minutes and 24 hours, then share either the generated HTTPS invitation link or the human-readable invitation code with the device owner. Both represent the same one-time invitation: using either one invalidates the other. The random link token and invitation code are stored only as keyed hashes, shown only when created, and can be revoked before use. The manual code is 16 ambiguity-resistant Base32-style characters grouped for readability.

On Windows, open `basesentinel-agent-gui`. Either paste the complete link into **Invitation link**, or select **Invitation code** and enter the server URL plus the code. The link contains the server address and a temporary token in its URL fragment; browsers do not send the fragment to the server in HTTP requests. The client exchanges the invitation for an individual agent credential. Invitations work while server enrollment mode is set to **Automatic**; disabled enrollment rejects them. Existing enrolled agents are not affected.


### Approval-required enrollment

The server can also use **Approval required** mode. A device can submit its invitation, but it does not receive an agent credential immediately. The request appears in **Agent enrollment → Enrollment requests** with hostname and platform metadata. An administrator can approve or reject it. After approval, the device owner clicks **Connect device** again with the same invitation link or code to complete enrollment. Rejected requests cannot be reused. Invitations still expire and can be revoked while awaiting review.


## Client overview

Administrators can open **Clients** from the dashboard navigation to view enrolled endpoints, platform and agent versions, last check-in, enrollment time, and current status. Revoking a client disables its agent credentials; historical security events remain available for investigation.


## Agent diagnostics and event delivery

The Windows agent GUI now provides **Run diagnostics**, **Collect now**, **Start monitoring**, and **Stop** actions. Its output panel shows collection results, delivery failures, server errors, queue depth, and the Security log checkpoint. Keep the GUI open while continuous monitoring is running; closing it stops the foreground agent process.

Run the same checks from PowerShell:

```powershell
basesentinel-agent diagnostics
basesentinel-agent collect --batch-size 50
basesentinel-agent run --interval 60 --batch-size 50
```

Diagnostics checks the authenticated server connection, local pending queue, checkpoint, and whether the current Windows user can read the Security event log. It does not send events or change the checkpoint. **Collect now** (or the `collect` command) reads new events, persists them and the checkpoint locally, then attempts to deliver up to 500 queued events by default. The GUI lets the operator choose a delivery limit of 50, 100, 250, or 500. Continuous mode repeats that process and sends an authenticated heartbeat every cycle. A large pending count is a backlog, not a delivery confirmation; it decreases as the server acknowledges queued events.

The current collector reads only Windows Security event IDs **4624**, **4625**, **4672**, and **4720**. It does not ingest every Windows event or events from other channels. The Windows account running the agent must have permission to read the Security log. If diagnostics reports access denied, run the agent under an account with the required Security log read permission.

A non-zero pending count means events are still stored locally and have not yet been acknowledged by the server. They remain queued for another delivery attempt. The dashboard currently shows aggregate event counts; the `GET /api/v1/events` endpoint provides individual event records.
