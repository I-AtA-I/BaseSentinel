# Windows event coverage

The Windows agent collects an allowlist of events from the local Security event log.

## Current coverage

| Event ID | Event | BaseSentinel event type |
| --- | --- | --- |
| 4624 | Successful logon | `login.success` |
| 4625 | Failed logon | `login.failed` |
| 4672 | Special privileges assigned to a logon | `privilege.special_assignment` |
| 4697 | Service installed | `service.installed` |
| 4719 | System audit policy changed | `audit.policy_changed` |
| 4720 | User account created | `account.created` |
| 4722 | User account enabled | `account.enabled` |
| 4723 | Password change attempted | `password.change_attempted` |
| 4724 | Password reset attempted | `password.reset` |
| 4725 | User account disabled | `account.disabled` |
| 4726 | User account deleted | `account.deleted` |
| 4732 | Member added to a security-enabled local group | `group.member_added` |
| 4733 | Member removed from a security-enabled local group | `group.member_removed` |
| 6416 | New external device recognized (USB storage only) | `device.usb_storage_recognized` |
| 1102 | Security audit log cleared | `security_log.cleared` |

## USB storage monitoring

USB storage detection uses Security event **6416** ("A new external device was recognized by the system"). The agent keeps only records whose device identifiers indicate USB mass storage; other newly recognized USB devices, such as keyboards, are ignored.

Windows does not necessarily write event 6416 unless the **Audit PNP Activity** success policy is enabled:

1. Open **Local Security Policy** (`secpol.msc`) on the monitored Windows device.
2. Navigate to **Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking**.
3. Open **Audit PNP Activity** and enable **Success**.
4. Ensure the agent account can read the Windows Security event log.

The agent does not change local audit policy automatically. This avoids silently changing a machine's security configuration.

**Coverage limitation:** event 6416 reports when Windows first recognizes a new external device. It is not a guaranteed record of every later unplug/replug cycle. Repeated connection and removal monitoring requires collection from the separate Kernel-PnP event channels and their own durable checkpoints; that is not included in this change.
