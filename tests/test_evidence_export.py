
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from main import SOCDashboard
from services.report_generator import ReportGenerator


class TestEvidenceExport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.original_report_dir = (
            ReportGenerator.REPORT_DIR
        )
        ReportGenerator.REPORT_DIR = Path(
            self.temp_dir.name
        )

        self.alert = Mock()
        self.alert.threat_type = "Potential Brute Force"
        self.alert.severity = "HIGH"
        self.alert.description = "8 failed logins"

        self.incident = Mock()
        self.incident.incident_id = "INC-TEST"
        self.incident.title = "Suspicious Login Activity"
        self.incident.severity = "HIGH"
        self.incident.status = "OPEN"
        self.incident.created_at = (
            "2026-09-29T10:00:00"
        )
        self.incident.alerts = [self.alert]
        self.incident.notes = [
            {
                "analyst": "SOC Analyst",
                "timestamp": "2026-09-29T11:00:00",
                "message": "Investigating login activity"
            }
        ]

        self.incident.to_dict.return_value = {
            "incident_id": "INC-TEST",
            "title": "Suspicious Login Activity",
            "severity": "HIGH",
            "status": "OPEN",
            "notes": self.incident.notes,
        }

        self.evidence = {
            "tracked_event_ids": 2,
            "missing_tracked_events": 1,
            "legacy_alerts": 1,
            "exact_matches": [
                {
                    "event_id": "EVENT-1",
                    "ip": "10.0.0.99",
                    "username": "admin",
                    "status": "FAILED",
                    "timestamp": "2026-09-29T10:00:00"
                }
            ],
            "legacy_matches": [
                {
                    "ip": "10.0.0.99",
                    "username": "admin",
                    "status": "FAILED",
                    "timestamp": "2026-09-29T09:59:00"
                }
            ],
        }

    def tearDown(self):
        ReportGenerator.REPORT_DIR = (
            self.original_report_dir
        )
        self.temp_dir.cleanup()

    def test_json_includes_correlated_evidence(self):
        path = ReportGenerator.export_incident(
            self.incident,
            evidence=self.evidence
        )

        with open(
            path,
            encoding="utf-8"
        ) as file:
            report = json.load(file)

        login = report["login_evidence"]

        self.assertEqual(
            login["collection_status"],
            "COMPLETED"
        )
        self.assertEqual(
            login["tracked_event_ids"],
            2
        )
        self.assertEqual(
            login["exact_match_count"],
            1
        )
        self.assertEqual(
            login["missing_tracked_events"],
            1
        )
        self.assertEqual(
            login["approximate_match_count"],
            1
        )
        self.assertEqual(
            login["exact_matches"][0]["event_id"],
            "EVENT-1"
        )
        self.assertEqual(
            report["incident"]["notes"],
            self.incident.notes
        )

    def test_json_without_evidence_is_compatible(self):
        path = ReportGenerator.export_incident(
            self.incident
        )

        with open(
            path,
            encoding="utf-8"
        ) as file:
            report = json.load(file)

        self.assertEqual(
            report["login_evidence"][
                "collection_status"
            ],
            "NOT_REQUESTED"
        )
        self.assertEqual(
            report["incident"]["incident_id"],
            "INC-TEST"
        )

    def test_pdf_with_evidence_is_created(self):
        path = ReportGenerator.export_incident_pdf(
            self.incident,
            evidence=self.evidence
        )

        self.assertTrue(path.exists())
        self.assertGreater(
            path.stat().st_size,
            1000
        )

        with open(path, "rb") as file:
            self.assertEqual(
                file.read(5),
                b"%PDF-"
            )

    def test_dashboard_export_both_uses_one_snapshot(self):
        dashboard = SOCDashboard.__new__(
            SOCDashboard
        )
        dashboard.manager = Mock()
        dashboard.manager.incidents = {
            "INC-TEST": self.incident
        }

        with (
            patch.object(
                dashboard,
                "view_incidents"
            ),
            patch.object(
                dashboard,
                "find_incident",
                return_value=self.incident
            ),
            patch(
                "builtins.input",
                side_effect=["INC-TEST", "3"]
            ),
            patch(
                "main.EvidenceCorrelator.find_evidence",
                return_value=self.evidence
            ) as find_evidence,
            patch(
                "main.ReportGenerator.export_incident"
            ) as export_json,
            patch(
                "main.ReportGenerator.export_incident_pdf"
            ) as export_pdf,
        ):
            dashboard.export_incident_report()

        find_evidence.assert_called_once_with(
            self.incident,
            dashboard.manager
        )

        export_json.assert_called_once_with(
            self.incident,
            evidence=self.evidence
        )

        export_pdf.assert_called_once_with(
            self.incident,
            evidence=self.evidence
        )

    def test_cancel_does_not_collect_evidence(self):
        dashboard = SOCDashboard.__new__(
            SOCDashboard
        )
        dashboard.manager = Mock()
        dashboard.manager.incidents = {
            "INC-TEST": self.incident
        }

        with (
            patch.object(
                dashboard,
                "view_incidents"
            ),
            patch.object(
                dashboard,
                "find_incident",
                return_value=self.incident
            ),
            patch(
                "builtins.input",
                side_effect=["INC-TEST", "4"]
            ),
            patch(
                "main.EvidenceCorrelator.find_evidence"
            ) as find_evidence,
        ):
            dashboard.export_incident_report()

        find_evidence.assert_not_called()


if __name__ == "__main__":
    unittest.main()