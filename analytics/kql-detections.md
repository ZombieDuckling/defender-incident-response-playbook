# KQL detection starters

These are neutral starter patterns for log analytics review. Field names may need adjustment for a real workspace.

## Suspicious PowerShell child process

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "FromBase64String", "DownloadString", "Invoke-WebRequest")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```

## Archive staging from sensitive paths

```kql
DeviceFileEvents
| where FileName endswith ".zip" or FileName endswith ".7z"
| where FolderPath has_any ("Finance", "Payroll", "Contracts")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, AccountName
```

## Sign-in risk requiring confirmation

```kql
SigninLogs
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, RiskLevelDuringSignIn, ConditionalAccessStatus
```
