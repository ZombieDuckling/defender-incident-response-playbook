import json
import unittest
from pathlib import Path

from tools.build_sample_report import build_report

ROOT = Path(__file__).resolve().parents[1]


class ReportBuilderTests(unittest.TestCase):
    def test_report_contains_alert_count_and_high_count(self):
        report = build_report(ROOT / "data/synthetic-defender-alerts.json", ROOT / "data/synthetic-device-inventory.csv")
        self.assertIn("Alerts reviewed: 4", report)
        self.assertIn("High or critical alerts: 1", report)

    def test_report_orders_high_severity_first(self):
        report = build_report(ROOT / "data/synthetic-defender-alerts.json", ROOT / "data/synthetic-device-inventory.csv")
        first_heading = next(line for line in report.splitlines() if line.startswith("### "))
        self.assertIn("ALRT-1001", first_heading)

    def test_report_includes_evidence_for_each_alert(self):
        report = build_report(ROOT / "data/synthetic-defender-alerts.json", ROOT / "data/synthetic-device-inventory.csv")
        alerts = json.loads((ROOT / "data/synthetic-defender-alerts.json").read_text(encoding="utf-8"))["alerts"]
        evidence_lines = [line for line in report.splitlines() if line.startswith("- Evidence captured:")]
        self.assertEqual(len(alerts), len(evidence_lines))
        self.assertIn("Evidence captured: powershell command line captured, file hash available, parent process winword.exe", report)

    def test_all_alerts_use_synthetic_domain(self):
        alerts = json.loads((ROOT / "data/synthetic-defender-alerts.json").read_text(encoding="utf-8"))["alerts"]
        self.assertTrue(all(alert["user"].endswith("@example.invalid") for alert in alerts))


if __name__ == "__main__":
    unittest.main()
