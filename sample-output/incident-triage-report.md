# Incident triage report

Source: synthetic Microsoft Defender alert export

## Summary

- Alerts reviewed: 4
- High or critical alerts: 1

## Findings

### ALRT-1001: Suspicious PowerShell download activity

- Severity: high
- Status: new
- User: riley.mokoena@example.invalid
- Device: WS-117 (high criticality)
- Category: execution
- Signals: encoded command, external download, new process from office child process
- Recommended actions: collect process tree, isolate device pending review, reset user sessions

### ALRT-1002: Impossible travel sign-in pattern

- Severity: medium
- Status: new
- User: casey.naidoo@example.invalid
- Device: AAD-SIGNIN (high criticality)
- Category: identity
- Signals: two countries within short window, unfamiliar ASN
- Recommended actions: confirm user travel, review MFA detail, revoke sessions if unconfirmed

### ALRT-1003: Unusual archive staging on finance workstation

- Severity: medium
- Status: in_progress
- User: thabo.khumalo@example.invalid
- Device: WS-044 (high criticality)
- Category: collection
- Signals: large zip created, sensitive path touched
- Recommended actions: review file list, confirm business process, monitor outbound transfer

### ALRT-1004: Browser credential store access

- Severity: low
- Status: new
- User: morgan.patel@example.invalid
- Device: WS-203 (medium criticality)
- Category: credential_access
- Signals: credential store file read
- Recommended actions: check parent process, confirm browser update activity

