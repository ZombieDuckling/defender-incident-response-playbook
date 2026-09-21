param(
    [Parameter(Mandatory=$true)] [string] $AlertsPath,
    [Parameter(Mandatory=$true)] [string] $DeviceInventoryPath,
    [Parameter(Mandatory=$true)] [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path $AlertsPath)) { throw "Alerts file not found: $AlertsPath" }
if (-not (Test-Path $DeviceInventoryPath)) { throw "Device inventory not found: $DeviceInventoryPath" }

$alerts = (Get-Content -Raw -Path $AlertsPath | ConvertFrom-Json).alerts
$devices = Import-Csv -Path $DeviceInventoryPath | Group-Object -Property device_id -AsHashTable -AsString

$severityOrder = @{ critical = 4; high = 3; medium = 2; low = 1 }
$ordered = $alerts | Sort-Object -Descending { $severityOrder[$_.severity.ToString().ToLowerInvariant()] }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Incident triage report")
$lines.Add("")
$lines.Add("Source: synthetic Microsoft Defender alert export")
$lines.Add("")
$lines.Add("## Summary")
$lines.Add("")
$lines.Add("- Alerts reviewed: $($alerts.Count)")
$lines.Add("- High or critical alerts: $(($alerts | Where-Object { $_.severity -in @('critical','high') }).Count)")
$lines.Add("")
$lines.Add("## Findings")
$lines.Add("")

foreach ($alert in $ordered) {
    $device = $devices[$alert.device]
    $criticality = if ($device) { $device.criticality } else { "unknown" }
    $lines.Add("### $($alert.alert_id): $($alert.title)")
    $lines.Add("")
    $lines.Add("- Severity: $($alert.severity)")
    $lines.Add("- Status: $($alert.status)")
    $lines.Add("- User: $($alert.user)")
    $lines.Add("- Device: $($alert.device) ($criticality criticality)")
    $lines.Add("- Category: $($alert.category)")
    $lines.Add("- Signals: $([string]::Join(', ', $alert.signals))")
    $lines.Add("- Recommended actions: $([string]::Join(', ', $alert.recommended_actions))")
    $lines.Add("")
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
$lines | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Wrote $OutputPath with $($alerts.Count) alerts."
