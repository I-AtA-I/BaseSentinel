# Windows event coverage

The Windows agent collects an allowlist of events from the local Security event log.

## Current coverage

| Event ID | Event | BaseSentinel event type | Alert behavior |
| --- | --- | --- |
| 4624 | Successful logon | `login.success` |
| 4625 | Failed logon | `login.failed` |
| 4672 | Special privileges assigned to a logon | `privilege.special_assignment` |
| 4697 | Service installed | `service.installed` | High-priority alert |
| 4719 | System audit policy changed | `audit.policy_changed` | High-priority alert |
| 4720 | User account created | `account.created` |
| 4722 | User account enabled | `account.enabled` |
| 4723 | Password change attempted | `password.change_attempted` |
| 4724 | Password reset attempted | `password.reset` |
| 4725 | User account disabled | `account.disabled` |
| 4726 | User account deleted | `account.deleted` | High-priority alert |
| 4732 | Member added to a security-enabled local group | `group.member_added` | High-priority alert |
| 4733 | Member removed from a security-enabled local group | `group.member_removed` |
| 6416 | New external device recognized (USB storage only) | `device.usb_storage_recognized` | High-priority alert |
| 1102 | Security audit log cleared | `security_log.cleared` | Critical alert |

## USB storage monitoring

USB storage detection uses Security event **6416** ("A new external device was recognized by the system"). The agent keeps only records whose device identifiers indicate USB mass storage; other newly recognized USB devices, such as keyboards, are ignored.

Windows does not necessarily write event 6416 unless the **Audit PNP Activity** success policy is enabled:

1. Open **Local Security Policy** (`secpol.msc`) on the monitored Windows device.
2. Navigate to **Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking**.
3. Open **Audit PNP Activity** and enable **Success**.
4. Ensure the agent account can read the Windows Security event log.

The agent checks this policy when collection starts. If Success auditing is disabled, it requests administrator approval through the standard Windows UAC prompt and applies only the Plug and Play Success audit setting. The collector itself continues running as the enrolled user. If approval is declined or a domain policy overrides the setting, USB recognition events may not be available and the agent reports a setup warning.

A recognized USB mass-storage device is stored as an event for the timeline and also creates a high-priority alert in the Alerts view. The event remains available as evidence linked from that alert.

**Coverage limitations and next telemetry sources:**
- Event 6416 reports when Windows first recognizes a new external device. It is not a guaranteed record of every later unplug/replug cycle. Repeated connection and removal monitoring requires separate Kernel-PnP channels and independent durable checkpoints.
- Event 4697 reports a newly installed Windows service; it does not prove that an executable is unsigned and does not cover every ordinary application installation. Reliable unsigned-program detection needs additional executable/signature inventory or AppLocker/Code Integrity telemetry.
- This collector does not yet ingest Windows Defender malware-detection events or Windows camera/microphone privacy-access events. Those require dedicated event-channel collection and separate checkpoints. They must not be represented as monitored until that telemetry is implemented.
