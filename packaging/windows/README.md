# Windows client installer

The Windows installer bundles the endpoint console, tray application, agent CLI, and a dedicated LocalSystem worker executable. End users do not need to install Python.

## Build requirements

- Windows 10/11 x64 build machine.
- Python 3.12 or newer.
- Inno Setup 6.
- Internet access during the build to install Python build dependencies.

## Build

From the repository root in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\windows\build.ps1
```

The build creates the four executable payloads under `dist\windows-client` and the installer at:

```text
dist\windows-client\installer\BaseSentinel-Client-Setup.exe
```

## Install and enroll

1. Run the installer and approve the Windows Administrator prompt.
2. Open **BaseSentinel Endpoint** from the Start menu.
3. Enroll the device using a one-time invitation link or invitation code from the BaseSentinel administrator.
4. Start monitoring from the endpoint console, or use the CLI to install the all-users collector:

   ```powershell
   & "$env:ProgramFiles\BaseSentinel\BaseSentinelAgent.exe" startup-install
   ```

   Approve the UAC prompt. The installer transfers the enrolled credential into machine-scope DPAPI storage and registers one LocalSystem task at Windows boot.

The tray application is optional and can be opened from the Start menu. It is not required for collection.

## Uninstall

The uninstaller removes the system-wide scheduled task before removing the application executables. The protected runtime and data under `%ProgramData%\BaseSentinel` are intentionally retained; this preserves queued events and enrollment data rather than silently deleting them. They can be reviewed and removed separately by an administrator after uninstall.

## Current scope

This package is for Windows x64 endpoints only. It does not install or configure the BaseSentinel server, database, firewall, Windows audit policy, or Cloudflare Tunnel. The server must already be reachable by the endpoint.
