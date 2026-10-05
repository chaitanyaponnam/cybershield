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

        json_path = (
            Path(self.temp_dir.name)
            / "incident_test.json"
        )
        pdf_path = (
            Path(self.temp_dir.name)
            / "incident_test.pdf"
        )

        json_manifest = (
            Path(str(json_path) + ".sha256.json")
        )
        pdf_manifest = (
            Path(str(pdf_path) + ".sha256.json")
        )

        json_hash = "a" * 64
        pdf_hash = "b" * 64

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
                "main.ReportGenerator.export_incident",
                return_value=json_path
            ) as export_json,
            patch(
                "main.ReportGenerator.export_incident_pdf",
                return_value=pdf_path
            ) as export_pdf,
            patch(
                "main.EvidenceIntegrity.create_manifest",
                side_effect=[
                    json_manifest,
                    pdf_manifest
                ]
            ) as create_manifest,
            patch(
                "main.EvidenceIntegrity.calculate_hash",
                side_effect=[
                    json_hash,
                    pdf_hash
                ]
            ) as calculate_hash,
            patch(
                "main.AuditTrail.record_event"
            ) as record_event,
        ):
            dashboard.export_incident_report()

        # Evidence must be collected only once.
        find_evidence.assert_called_once_with(
            self.incident,
            dashboard.manager
        )

        # Both reports must use the same evidence snapshot.
        export_json.assert_called_once_with(
            self.incident,
            evidence=self.evidence
        )

        export_pdf.assert_called_once_with(
            self.incident,
            evidence=self.evidence
        )

        # A separate manifest must be created for each report.
        self.assertEqual(
            create_manifest.call_count,
            2
        )

        self.assertEqual(
            create_manifest.call_args_list[0].args,
            (json_path,)
        )

        self.assertEqual(
            create_manifest.call_args_list[1].args,
            (pdf_path,)
        )

        # SHA-256 must be calculated for both reports.
        self.assertEqual(
            calculate_hash.call_count,
            2
        )

        self.assertEqual(
            calculate_hash.call_args_list[0].args,
            (json_path,)
        )

        self.assertEqual(
            calculate_hash.call_args_list[1].args,
            (pdf_path,)
        )

        # Each exported report must create an audit event.
        self.assertEqual(
            record_event.call_count,
            2
        )

        record_event.assert_any_call(
            action="EXPORT",
            report_path=json_path,
            sha256=json_hash,
            status="CREATED",
            incident_id="INC-TEST"
        )

        record_event.assert_any_call(
            action="EXPORT",
            report_path=pdf_path,
            sha256=pdf_hash,
            status="CREATED",
            incident_id="INC-TEST"
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
            patch(
                "main.EvidenceIntegrity.create_manifest"
            ) as create_manifest,
            patch(
                "main.EvidenceIntegrity.calculate_hash"
            ) as calculate_hash,
            patch(
                "main.AuditTrail.record_event"
            ) as record_event,
        ):
            dashboard.export_incident_report()

        find_evidence.assert_not_called()
        create_manifest.assert_not_called()
        calculate_hash.assert_not_called()
        record_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()