from __future__ import annotations

import json
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


_EVENT_MAP = {
    4624: ("authentication", "login.success", 2),
    4625: ("authentication", "login.failed", 7),
    4672: ("authentication", "privilege.special_assignment", 5),
    4720: ("account", "account.created", 7),
}
_ALLOWED_EVENT_FIELDS = {
    "TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName",
    "LogonType", "ProcessName", "TargetDomainName", "SubjectDomainName",
    "Status", "SubStatus", "PrivilegeList",
}

# Fixed query and output fields: no user-provided text is interpolated into PowerShell.
_POWERSHELL = r"""
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4624,4625,4672,4720); StartTime = (Get-Date).AddMinutes(-10) } -MaxEvents 100 -ErrorAction SilentlyContinue)
$result = @($events | ForEach-Object {
    [pscustomobject]@{
        Id = $_.Id
        RecordId = $_.RecordId
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        MachineName = $_.MachineName
        Message = $_.Message
        Xml = $_.ToXml()
    }
})
ConvertTo-Json -InputObject $result -Depth 4 -Compress
"""


def _event_data(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    values = {}
    for item in root.findall(".//{*}EventData/{*}Data"):
        name = item.attrib.get("Name")
        if name in _ALLOWED_EVENT_FIELDS and len(values) < 20:
            values[name] = (item.text or "")[:512]
    return values


def collect_security_events() -> list[dict]:
    """Read a small allowlist of Windows Security events using Get-WinEvent."""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()[:300]
        raise RuntimeError(
            "Could not read the Windows Security event log. Run with permission to read that log."
            + (f" Details: {detail}" if detail else "")
        )
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Windows event log returned invalid data.") from exc
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise RuntimeError("Windows event log returned an unexpected response.")

    events = []
    for item in raw:
        if not isinstance(item, dict) or item.get("Id") not in _EVENT_MAP:
            continue
        category, event_type, severity = _EVENT_MAP[item["Id"]]
        record_id = item.get("RecordId")
        computer = str(item.get("MachineName") or "windows-host")
        if record_id is None:
            continue
        try:
            occurred_at = datetime.fromisoformat(item["TimeCreated"].replace("Z", "+00:00"))
            event_data = _event_data(item["Xml"])
        except (KeyError, ValueError, ET.ParseError, TypeError):
            continue
        event_data.update({"record_id": int(record_id), "computer": computer})
        message = str(item.get("Message") or f"Windows Security event {item['Id']}")[:4096].strip()
        if not message:
            message = f"Windows Security event {item['Id']}"
        events.append({
            "event_uid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"windows-security:{computer}:{record_id}")),
            "schema_version": 1,
            "category": category,
            "event_type": event_type,
            "severity": severity,
            "source": "Windows Security",
            "event_code": str(item["Id"]),
            "message": message,
            "event_data": event_data,
            "occurred_at": occurred_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return events
