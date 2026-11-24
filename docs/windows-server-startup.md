# BaseSentinel Windows server

The BaseSentinel web/API application can run on Windows with Waitress. The development server from `flask run` is not used for this deployment.

## Requirements

- Windows 10/11 or Windows Server.
- Python 3.12+ and the BaseSentinel virtual environment.
- A reachable MariaDB database.
- A configured `.env` file containing the database credentials, `SECRET_KEY`, and `PAIRING_CODE_PEPPER`.
- The database schema must already be upgraded to the current Alembic head. The server launcher does not modify the database or run migrations automatically.

Install or update the project dependencies from the repository root:

```powershell
py -m pip install -e .
```

## Run the server

Run the following from the directory containing the server's `.env` file:

```powershell
basesentinel-server run
```

The defaults are `127.0.0.1:5000` and eight Waitress threads. The server writes its log to:

```text
%PROGRAMDATA%\BaseSentinel\Logs\server.log
```

The default host is loopback-only. This is intentional: do not expose the application directly to the public internet. When remote endpoints need to connect, place the server behind a correctly configured HTTPS reverse proxy and configure the proxy/network access deliberately. For a trusted LAN deployment behind an HTTPS proxy, the listener can be bound to all interfaces:

```powershell
basesentinel-server run --host 0.0.0.0 --port 5000
```

## Start automatically after Windows sign-in

From PowerShell opened in the directory containing the `.env` file, register a per-user Task Scheduler task:

```powershell
basesentinel-server startup-install --host 127.0.0.1 --port 5000
basesentinel-server startup-status
```

The task starts the server when the current Windows user signs in. It runs with that user's normal privileges, uses the same working directory so the existing `.env` file is loaded, and retries a server process that exits unexpectedly. The command also asks Task Scheduler to start the server immediately. Administrator privileges are not required.

Remove the automatic startup task with:

```powershell
basesentinel-server startup-remove
```

Removing the task does not stop a server process that is already running. The server runs in the signed-in user's session; this is not a Windows service and it does not start before sign-in.

## Database and network notes

The server does not automatically run `flask db upgrade`. Apply pending migrations deliberately before starting a new server version, and keep a database backup before schema changes.

Waitress provides the HTTP application server, not TLS termination. Agent credentials and event telemetry must travel over HTTPS outside localhost. Configure TLS at a trusted reverse proxy before allowing remote clients to connect.
