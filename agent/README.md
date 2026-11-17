# BaseSentinel Windows Agent (MVP)

The first agent release is an explicitly run, user-visible Windows command-line collector. It is not installed as a service and does not run persistently in the background.

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

## Collect and send

```powershell
basesentinel-agent collect
```

The MVP reads a limited allowlist from the Windows Security log: 4624, 4625, 4672, and 4720. It sends normalized events to `POST /api/v1/events`. Events are kept in a local SQLite queue until the server acknowledges them; stable event IDs make retries idempotent.

Reading the Security log may require an elevated terminal or membership in the local Event Log Readers group. The collector does not change audit policy or Windows security settings.

Check enrollment:

```powershell
basesentinel-agent status
```

## Scope and limitations

- Collection is manual; there is no Windows service, scheduled task, auto-start, remote command execution, or stealth behavior.
- The collector stores a Windows Security EventRecordID checkpoint alongside queued events in one SQLite transaction. It reads ordered batches of up to 1,000 matching records, so backlogs can be drained over repeated runs without relying on a short time window. If the Windows Security log is cleared and its record ID resets below the saved checkpoint, collection restarts from the beginning of the retained log.
- Run enrollment and collection as the same Windows user so DPAPI can decrypt the stored credential.
- Treat event messages and event data as security telemetry; review retention and access controls on the SIEM server.
