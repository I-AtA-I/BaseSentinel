# Windows event coverage

The Windows agent collects allowlisted events from the local Security event log and Microsoft Defender Operational channel. Each channel has its own durable record checkpoint.

## Current coverage

| Event ID | Event | BaseSentinel event type | Alert behavior |
| --- | --- | --- | --- |
| 4624 | Successful logon | `login.success` | Informational event |
| 4625 | Failed logon | `login.failed` | Alert after repeated failures |
| 4672 | Special privileges assigned to a logon | `privilege.special_assignment` | Event only |
| 4697 | Service installed | `service.installed` | High-priority alert |
| 4719 | System audit policy changed | `audit.policy_changed` | High-priority alert |
| 4720 | User account created | `account.created` | High-priority alert |
| 4722 | User account enabled | `account.enabled` | High-priority alert |
| 4723 | Password change attempted | `password.change_attempted` | Event only |
| 4724 | Password reset attempted | `password.reset` | High-priority alert |
| 4725 | User account disabled | `account.disabled` | Event only |
| 4726 | User account deleted | `account.deleted` | High-priority alert |
| 4732 | Member added to a security-enabled local group | `group.member_added` | High-priority alert |
| 4733 | Member removed from a security-enabled local group | `group.member_removed` | High-priority alert |
| 6416 | New external device recognized (USB storage only) | `device.usb_storage_recognized` | One correlated alert per agent and device ID |
| 1102 | Security audit log cleared | `security_log.cleared` | Critical alert |
| 1116 | Microsoft Defender malware detected | `malware.detected` | Critical alert |
| 1117 | Microsoft Defender remediation action | `malware.remediation_completed` | Informational event |
| 1118 | Microsoft Defender remediation failed | `malware.remediation_failed` | Critical alert |
| 1121 | Attack Surface Reduction blocked activity | `attack_surface_reduction.blocked` | High-priority alert |

## USB storage monitoring

USB storage detection uses Security event **6416** ("A new external device was recognized by the system"). The agent keeps only records whose device identifiers indicate USB mass storage; other newly recognized USB devices, such as keyboards, are ignored.

Windows does not necessarily write event 6416 unless the **Audit PNP Activity** success policy is enabled:

1. Open **Local Security Policy** (`secpol.msc`) on the monitored Windows device.
2. Navigate to **Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking**.
3. Open **Audit PNP Activity** and enable **Success**.
4. Ensure the agent account can read the Windows Security event log.

The agent checks this policy when collection starts. If Success auditing is disabled, it requests administrator approval through the standard Windows UAC prompt and applies only the Plug and Play Success audit setting. The collector itself continues running as the enrolled user. If approval is declined or a domain policy overrides the setting, USB recognition events may not be available and the agent reports a setup warning.

A recognized USB mass-storage device is stored as an individual event for the timeline. In Alerts, BaseSentinel correlates event 6416 records by agent and normalized `DeviceId`, so repeated recognition records for the same device update one alert and its occurrence count instead of creating a new alert for every record. The first event remains the alert source-event link; all raw recognition records remain independently available in Events. The occurrence count represents Windows recognition records, not confirmed physical plug-in sessions.

## Microsoft Defender telemetry

The agent also reads the Microsoft-Windows-Windows Defender/Operational channel. Events 1116 (malware detected) and 1118 (remediation failed) are correlated into one malware incident when they refer to the same endpoint, threat identifier/name, and normalized file path within a rolling 30-minute window. Different threats or paths remain separate incidents. The triggering process name is evidence, not part of the incident identity, so Defender records attributed to different processes do not create duplicate alerts. Event 1117 (remediation action completed) remains informational evidence and does not create a separate alert. Event 1121 creates a high-priority alert when an Attack Surface Reduction rule blocks activity. All original Defender events remain stored and visible for investigation; correlation changes the alert count, not the underlying event history. The collector uses a separate durable checkpoint, so Defender records do not interfere with the Security log checkpoint.

Defender event metadata is parsed from the named XML fields and PowerShell output is explicitly configured as UTF-8 to preserve localized messages. The Defender Operational channel must be enabled and readable by the agent account. If it is unavailable, the agent reports a telemetry warning and continues collecting the Security channel. Malware detection is based on Defender's own detections; BaseSentinel does not independently scan files or claim that an endpoint is malware-free.

**Coverage limitations and next telemetry sources:**
- Event 6416 reports when Windows first recognizes a new external device. It is not a guaranteed record of every later unplug/replug cycle. Repeated connection and removal monitoring requires separate Kernel-PnP channels and independent durable checkpoints.
- Event 4697 reports a newly installed Windows service; it does not prove that an executable is unsigned and does not cover every ordinary application installation. Reliable unsigned-program detection needs additional executable/signature inventory or AppLocker/Code Integrity telemetry.
- Process execution and suspicious command-line analytics are not yet collected. Reliable coverage needs Sysmon or Windows Security process-creation auditing (including command-line policy) and a separately validated event schema.
- Camera/microphone privacy-access events are not yet collected.
