# Windows client installer

The Windows x64 installer bundles the endpoint console, tray application, agent CLI, and a dedicated LocalSystem worker executable. It includes the Python runtime and GUI dependencies; a clean Windows 11 x64 device does not need Python, pip, or a separate runtime installer.

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
3. Enroll the device using a one-time invitation link or invitation code from the BaseSentinel administrator. The server must already be reachable over HTTPS.
4. Open **Event collection** and select **Install system-wide collector**. Approve the UAC prompt.

   The elevated setup transfers the enrolled credential into machine-scope DPAPI storage, enables only the Windows audit subcategories used by the current collector, and registers one LocalSystem task at Windows boot. If Windows or an organization policy blocks an audit setting, the setup reports a warning and continues; the corresponding events may be unavailable.

The tray application is optional and can be opened from the Start menu. It is not required for collection.

## Uninstall

The uninstaller removes the system-wide scheduled task before removing the application executables. The protected runtime and data under `%ProgramData%\BaseSentinel` are intentionally retained; this preserves queued events and enrollment data rather than silently deleting them. They can be reviewed and removed separately by an administrator after uninstall.

## Clean Windows 11 support

The installer targets Windows 11 x64 and bundles all client-side Python and GUI runtime components. PowerShell, Windows Event Log, Task Scheduler, DPAPI, and auditpol are Windows inbox components. No Python installation, pip setup, or manual package installation is required on the endpoint.

This is a **client installer**, not an all-in-one SIEM deployment. It does not install the BaseSentinel server or database, configure DNS/Cloudflare, or create enrollment invitations. A reachable BaseSentinel HTTPS server and a one-time invitation from its administrator are still required. The installer is not Authenticode-signed, so Windows may display an unknown-publisher or SmartScreen warning.
