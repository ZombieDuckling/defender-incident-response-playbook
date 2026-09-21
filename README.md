# Defender incident response playbook

A public, safe incident response kit for Microsoft Defender alert review. It uses synthetic alerts only. The repo is built to show practical security engineer work for a Microsoft 365 environment: triage, containment decisions, evidence handling, escalation notes, and repeatable validation.

## What this repo contains

- `playbooks/incident-response-workflow.md`: operator workflow from intake to closure.
- `playbooks/escalation-matrix.md`: severity, owner, and evidence requirements.
- `scripts/Invoke-IncidentTriage.ps1`: PowerShell triage runner for exported alert JSON.
- `tools/build_sample_report.py`: local report builder used by CI.
- `data/synthetic-defender-alerts.json`: safe sample alert data.
- `data/synthetic-device-inventory.csv`: safe device context.
- `analytics/kql-detections.md`: starter KQL patterns for log analytics review.
- `sample-output/incident-triage-report.md`: generated sample report from synthetic data.
- `tests/`: validation checks for schema, report output, and documentation coverage.

## VAT IT role mapping

This project maps to security engineer work where the operator needs to investigate endpoint and identity alerts without exposing a real tenant.

- Microsoft 365 security operations: alert intake, impact assessment, and escalation.
- Endpoint response: device isolation decision points, evidence capture, and user impact notes.
- Identity investigation: sign-in risk, account control checks, and session review prompts.
- Automation: repeatable PowerShell and Python validation around exported evidence.
- Governance: evidence chain, severity rules, and closure criteria written for auditability.

## Safe data boundary

All included data is synthetic. Hostnames, users, IDs, alert names, and timestamps are examples for demonstrating workflow only. Do not paste tenant exports, access tokens, customer names, or private incident notes into this public repo.

## Quick start

Run the Python validation path:

```bash
python3 tools/build_sample_report.py --alerts data/synthetic-defender-alerts.json --devices data/synthetic-device-inventory.csv --output sample-output/incident-triage-report.md
python3 tests/validate_project.py
python3 -m unittest discover -s tests
```

Run the PowerShell triage script on a machine with PowerShell 7:

```powershell
pwsh -File scripts/Invoke-IncidentTriage.ps1 -AlertsPath data/synthetic-defender-alerts.json -DeviceInventoryPath data/synthetic-device-inventory.csv -OutputPath sample-output/incident-triage-report.md
```

## Workflow summary

1. Confirm alert source, time window, affected user, and affected device.
2. Classify severity using the rules in `playbooks/escalation-matrix.md`.
3. Capture evidence before containment where that is safe.
4. Decide whether to isolate the device, disable account sessions, block an indicator, or monitor.
5. Record owner, next action, containment status, and closure criteria.

## Repository status

This is a portfolio-ready demonstration kit. It is not production incident response policy and does not replace tenant-specific procedures.
