# Windows agent system tray

BaseSentinel installs a separate Windows notification-area application:

```powershell
basesentinel-agent-tray
```

The tray application is available after installing the project with its declared dependencies. It does not start automatically.

## Menu

- **Open endpoint console** opens the existing Tkinter agent console, including enrollment and collection settings.
- **Resume monitoring** starts the detached background worker with the default batch size (500) and collection interval (60 seconds).
- **Pause monitoring** asks the worker to stop cleanly. Events already stored in the local queue are preserved.
- **Exit tray** closes only the tray application. It deliberately does not stop a running background worker.

The tray icon and tooltip refresh every three seconds. A green status indicator means the detached worker currently owns the agent process lock; a muted indicator means it is paused or stopped.

The tray application requires Windows and an enrolled endpoint before monitoring can be resumed. It uses the same per-user configuration, local queue, worker lock and stop-file protocol as the existing endpoint console and CLI.
