#!/usr/bin/env python3
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md",
    "LICENSE",
    "data/synthetic-defender-alerts.json",
    "data/synthetic-device-inventory.csv",
    "playbooks/incident-response-workflow.md",
    "playbooks/escalation-matrix.md",
    "scripts/Invoke-IncidentTriage.ps1",
    "tools/build_sample_report.py",
    "analytics/kql-detections.md",
    "sample-output/incident-triage-report.md",
]
FORBIDDEN_TERMS = [
    "Azure " + "Sentinel",
    "Microsoft " + "Sentinel",
    "AI-" + "powered",
    "revolution" + "ary",
    "cutting-" + "edge",
    "seam" + "less",
]


def main() -> int:
    missing = [item for item in REQUIRED if not (ROOT / item).exists()]
    if missing:
        raise SystemExit(f"Missing required files: {missing}")

    alerts = json.loads((ROOT / "data/synthetic-defender-alerts.json").read_text(encoding="utf-8"))["alerts"]
    if len(alerts) < 4:
        raise SystemExit("Expected at least 4 synthetic alerts")

    required_alert_fields = {"alert_id", "title", "severity", "status", "created_utc", "user", "device", "category", "signals", "recommended_actions", "evidence"}
    for alert in alerts:
        missing_fields = required_alert_fields - set(alert)
        if missing_fields:
            raise SystemExit(f"Alert {alert.get('alert_id', '<missing>')} missing {missing_fields}")
        if alert["severity"] not in {"critical", "high", "medium", "low"}:
            raise SystemExit(f"Invalid severity: {alert['severity']}")
        if not alert["user"].endswith("@example.invalid"):
            raise SystemExit(f"Synthetic user domain required: {alert['user']}")

    with (ROOT / "data/synthetic-device-inventory.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    device_ids = {row["device_id"] for row in rows}
    for alert in alerts:
        if alert["device"] not in device_ids:
            raise SystemExit(f"Missing device inventory entry for {alert['device']}")

    texts = []
    for path in ROOT.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            texts.append(path.read_text(encoding="utf-8"))
    combined = "\n".join(texts)
    em_dash = chr(8212)
    if em_dash in combined:
        raise SystemExit("Em dash found in repository text")
    for term in FORBIDDEN_TERMS:
        if term.lower() in combined.lower():
            raise SystemExit(f"Forbidden wording found: {term}")
    print(f"Validation passed: {len(alerts)} synthetic alerts, {len(rows)} inventory rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
