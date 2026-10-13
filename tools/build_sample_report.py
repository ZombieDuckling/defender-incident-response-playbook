#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def load_devices(path: Path):
    with path.open(newline="", encoding="utf-8") as handle:
        return {row["device_id"]: row for row in csv.DictReader(handle)}


def build_report(alerts_path: Path, devices_path: Path) -> str:
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))["alerts"]
    devices = load_devices(devices_path)
    ordered = sorted(alerts, key=lambda item: SEVERITY_ORDER[item["severity"]], reverse=True)
    high_or_critical = sum(1 for item in alerts if item["severity"] in {"critical", "high"})

    lines = [
        "# Incident triage report",
        "",
        "Source: synthetic Microsoft Defender alert export",
        "",
        "## Summary",
        "",
        f"- Alerts reviewed: {len(alerts)}",
        f"- High or critical alerts: {high_or_critical}",
        "",
        "## Findings",
        "",
    ]

    for alert in ordered:
        device = devices.get(alert["device"], {})
        criticality = device.get("criticality", "unknown")
        lines.extend([
            f"### {alert['alert_id']}: {alert['title']}",
            "",
            f"- Severity: {alert['severity']}",
            f"- Status: {alert['status']}",
            f"- User: {alert['user']}",
            f"- Device: {alert['device']} ({criticality} criticality)",
            f"- Category: {alert['category']}",
            f"- Signals: {', '.join(alert['signals'])}",
            f"- Evidence captured: {', '.join(alert['evidence'])}",
            f"- Recommended actions: {', '.join(alert['recommended_actions'])}",
            "",
        ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a report from synthetic alert data.")
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--devices", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(args.alerts, args.devices)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report + "\n", encoding="utf-8")
    count = len(json.loads(args.alerts.read_text(encoding="utf-8"))["alerts"])
    print(f"Wrote {args.output} with {count} alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
