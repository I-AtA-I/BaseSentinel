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

By default, the agent runs a collection cycle every 60 seconds. Each cycle first makes an authenticated identity request, which also refreshes the server-side heartbeat, then reads the next Security log batch and delivers queued events. Configure the interval and delivery batch size if needed:

```powershell
basesentinel-agent run --interval 30 --batch-size 100
```

Stop the process with `Ctrl+C`. If the server is unavailable, pending events stay in the local SQLite queue and the agent retries on the next cycle. Authentication failures (HTTP 401/403) stop the process so the endpoint can be re-enrolled or its access fixed.

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
