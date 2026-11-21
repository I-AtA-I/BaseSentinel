from __future__ import annotations

import json
import os
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


_EVENT_MAP = {
    4624: ("authentication", "login.success", 0),
    4625: ("authentication", "login.failed", 7),
    4672: ("authentication", "privilege.special_assignment", 5),
    4697: ("system", "service.installed", 7),
    4719: ("security", "audit.policy_changed", 8),
    4720: ("account", "account.created", 7),
    4722: ("account", "account.enabled", 5),
    4723: ("account", "password.change_attempted", 4),
    4724: ("account", "password.reset", 6),
    4725: ("account", "account.disabled", 6),
    4726: ("account", "account.deleted", 7),
    4732: ("account", "group.member_added", 7),
    4733: ("account", "group.member_removed", 6),
    6416: ("device", "device.usb_storage_recognized", 5),
    1102: ("security", "security_log.cleared", 9),
}
_ALLOWED_EVENT_FIELDS = {
    "TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName",
    "LogonType", "ProcessName", "TargetDomainName", "SubjectDomainName",
    "Status", "SubStatus", "PrivilegeList",
    "TargetSid", "MemberName", "MemberSid", "TargetUserSid",
    "ServiceName", "ServiceFileName", "ServiceType", "StartType",
    "SubjectLogonId", "TargetLogonId", "DeviceId", "DeviceInstanceId",
    "DeviceDescription", "DeviceName", "ClassId", "ClassName",
    "VendorIds", "CompatibleIds", "LocationInformation", "LocationPaths",
    "ContainerId", "ManufacturerName",
}
_MAX_BATCH = 1000
_PNP_AUDIT_SUBCATEGORY = "{0CCE9248-69AE-11D9-BED3-505054503030}"


def _auditpol_success_enabled(output: str) -> bool:
    """Recognize an enabled Success audit setting in common Windows locales."""
    normalized = output.casefold()
    return any(
        marker in normalized
        for marker in ("success", "úspěch", "erfolg", "réussite", "éxito", "sucesso")
    )


def ensure_pnp_audit_activity() -> str:
    """Enable successful Plug and Play auditing, requesting UAC elevation if needed."""
    if os.name != "nt":
        return "unsupported"

    query = [
        "auditpol.exe",
        "/get",
        f"/subcategory:{_PNP_AUDIT_SUBCATEGORY}",
        "/r",
    ]
    try:
        current = subprocess.run(
            query,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not inspect Plug and Play audit policy: {exc}") from exc

    if current.returncode != 0:
        detail = current.stderr.strip()[:300]
        raise RuntimeError(
            "Could not inspect the Plug and Play audit policy."
            + (f" Details: {detail}" if detail else "")
        )
    if _auditpol_success_enabled(current.stdout):
        return "already-enabled"

    # Only the narrowly scoped auditpol command is elevated. The agent itself
    # continues running as the enrolled Windows user.
    command = (
        "$p = Start-Process -FilePath "
        '"$env:SystemRoot\\System32\\auditpol.exe" '
        "-ArgumentList '/set /subcategory:"
        + _PNP_AUDIT_SUBCATEGORY
        + " /success:enable' -Verb RunAs -Wait -PassThru; "
        "exit $p.ExitCode"
    )
    try:
        elevated = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Could not request administrator approval for Plug and Play auditing: {exc}"
        ) from exc

    if elevated.returncode != 0:
        detail = elevated.stderr.strip()[:300]
        raise RuntimeError(
            "Plug and Play auditing was not enabled. Approve the Windows "
            "administrator prompt, or enable the policy with an administrator account."
            + (f" Details: {detail}" if detail else "")
        )

    try:
        verified = subprocess.run(
            query,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not verify Plug and Play audit policy: {exc}") from exc

    if verified.returncode != 0 or not _auditpol_success_enabled(verified.stdout):
        raise RuntimeError(
            "Windows did not confirm that successful Plug and Play auditing is enabled. "
            "A domain policy may be overriding the local setting."
        )
    return "enabled"

# The only interpolated value is a validated integer Windows EventRecordID.
_POWERSHELL = r"""
$ErrorActionPreference = 'Stop'
$checkpoint = {record_id}

try {{
    $securityLog = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    if (-not $securityLog.IsEnabled) {{
        throw 'The Windows Security event log is disabled.'
    }}

    $latestId = 0
    if ([long]$securityLog.RecordCount -gt 0) {{
        $latest = Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop
        if ($null -ne $latest) {{
            $latestId = [long]$latest.RecordId
        }}
    }}

    if ($checkpoint -gt $latestId) {{ $checkpoint = 0 }}
    $xpath = "*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4697 or EventID=4719 or EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4732 or EventID=4733 or EventID=6416 or EventID=1102) and (EventRecordID > $checkpoint)]]"

    $events = @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath -Oldest -MaxEvents {_max_batch} -ErrorAction SilentlyContinue | ForEach-Object {{
        [pscustomobject]@{{
            Id = $_.Id
            RecordId = $_.RecordId
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
            MachineName = $_.MachineName
            Message = $_.Message
            Xml = $_.ToXml()
        }}
    }})

    $payload = [pscustomobject]@{{
        LatestRecordId = $latestId
        Events = $events
    }}
    ConvertTo-Json -InputObject $payload -Depth 5 -Compress
}}
catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}}
"""


def _event_data(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    values = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name")
        if name in _ALLOWED_EVENT_FIELDS and len(values) < 20:
            values[name] = (item.text or "")[:512]
    return values


def _is_usb_storage_device(event_data: dict) -> bool:
    """Return True only for Plug and Play records identifying USB storage."""
    identifiers = " ".join(
        str(event_data.get(key) or "")
        for key in (
            "DeviceId",
            "DeviceInstanceId",
            "CompatibleIds",
            "ClassName",
            "DeviceDescription",
        )
    ).casefold()

    return (
        "usbstor\\" in identifiers
        or ("usb\\" in identifiers and "diskdrive" in identifiers)
    )


def collect_security_events(last_record_id: int = 0) -> tuple[list[dict], int]:
    """Read the next ordered batch of allowlisted Security events."""
    if type(last_record_id) is not int or last_record_id < 0:
        raise ValueError("Invalid Windows event record checkpoint.")

    script = _POWERSHELL.format(
        record_id=last_record_id,
        _max_batch=_MAX_BATCH,
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=45,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Reading the Windows Security event log timed out."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            "Could not start PowerShell to read the Windows Security event log."
        ) from exc

    if result.returncode != 0:
        detail = result.stderr.strip()[:300]
        message = (
            "Could not read the Windows Security event log. "
            "Run the agent with an account that has permission to read "
            "the Security log (for example, an administrator or an account "
            "granted the required Event Log Readers access)."
        )
        raise RuntimeError(
            message + (f" Details: {detail}" if detail else "")
        )

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows event log returned invalid data.") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("Events"), list):
        raise RuntimeError("Windows event log returned an unexpected response.")

    try:
        latest_record_id = max(0, int(raw.get("LatestRecordId") or 0))
    except (TypeError, ValueError):
        raise RuntimeError(
            "Windows event log returned an invalid checkpoint."
        ) from None

    events = []
    record_ids = []
    for item in raw["Events"]:
        if not isinstance(item, dict) or item.get("Id") not in _EVENT_MAP:
            continue
        category, event_type, severity = _EVENT_MAP[item["Id"]]
        record_id = item.get("RecordId")
        computer = str(item.get("MachineName") or "windows-host")
        if record_id is None:
            continue
        try:
            record_id = int(record_id)
            occurred_at = datetime.fromisoformat(
                item["TimeCreated"].replace("Z", "+00:00")
            )
            event_data = _event_data(item["Xml"])
        except (KeyError, ValueError, ET.ParseError, TypeError):
            continue
        record_ids.append(record_id)
        if item["Id"] == 6416 and not _is_usb_storage_device(event_data):
            # Keep the checkpoint moving, but do not report unrelated USB devices.
            continue
        event_data.update({"record_id": record_id, "computer": computer})
        message = str(
            item.get("Message") or f"Windows Security event {item['Id']}"
        )[:4096].strip()
        if not message:
            message = f"Windows Security event {item['Id']}"
        events.append({
            "event_uid": str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"windows-security:{computer}:{record_id}:{item['Id']}:{item['TimeCreated']}",
            )),
            "schema_version": 1,
            "category": category,
            "event_type": event_type,
            "severity": severity,
            "source": "Windows Security",
            "event_code": str(item["Id"]),
            "message": message,
            "event_data": event_data,
            "occurred_at": occurred_at.astimezone(timezone.utc).isoformat().replace(
                "+00:00",
                "Z",
            ),
        })

    if len(raw["Events"]) >= _MAX_BATCH and record_ids:
        next_checkpoint = max(record_ids)
    else:
        # A short page means all matching events up to the current log tail were read.
        next_checkpoint = latest_record_id
    return events, next_checkpoint
