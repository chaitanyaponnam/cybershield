
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

from main import SOCDashboard
from services.evidence_correlator import EvidenceCorrelator
from services.file_manager import FileManager


class TestEvidenceIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_data_dir = FileManager.DATA_DIR
        FileManager.DATA_DIR = Path(self.temp_dir.name)

        self.dashboard = SOCDashboard.__new__(
            SOCDashboard
        )
        self.dashboard.manager = Mock()

        self.alert = Mock(
            threat_type="Potential Brute Force",
            event_ids=["A"]
        )

        self.incident = Mock(
            incident_id="INC-1",
            alerts=[self.alert],
            notes=[],
            severity="HIGH",
            status="OPEN"
        )

        self.dashboard.manager.incidents = {
            "key": self.incident
        }

        FileManager.save_data(
            "login_logs.json",
            [
                {
                    "event_id": "A",
                    "ip": "10.0.0.99",
                    "username": "admin",
                    "status": "FAILED",
                    "timestamp": "2026-09-29T10:00:00"
                }
            ]
        )

    def tearDown(self):
        FileManager.DATA_DIR = self.old_data_dir
        self.temp_dir.cleanup()

    def test_view_evidence_from_investigation(self):
        output = io.StringIO()

        with (
            patch(
                "builtins.input",
                side_effect=["INC-1", "4", "5"]
            ),
            patch.object(
                self.dashboard,
                "view_incidents"
            ),
            patch.object(
                self.dashboard,
                "show_attack_details"
            ),
            redirect_stdout(output)
        ):
            self.dashboard.investigate_incident()

        self.assertIn(
            "Exact matches found: 1",
            output.getvalue()
        )

        self.dashboard.manager.update_incident.assert_not_called()

    def test_status_change_still_works(self):
        with (
            patch(
                "builtins.input",
                side_effect=["INC-1", "2"]
            ),
            patch.object(
                self.dashboard,
                "view_incidents"
            ),
            patch.object(
                self.dashboard,
                "show_attack_details"
            ),
            redirect_stdout(io.StringIO())
        ):
            self.dashboard.investigate_incident()

        self.dashboard.manager.update_incident.assert_called_once_with(
            "INC-1",
            "INVESTIGATING"
        )

    def test_legacy_identical_records_are_distinct(self):
        record = {
            "ip": "10.0.0.99",
            "username": "admin",
            "status": "FAILED",
            "timestamp": "2026-09-29T10:00:00"
        }

        FileManager.save_data(
            "login_logs.json",
            [record, dict(record)]
        )

        self.alert.event_ids = []
        self.alert.source_ip = "10.0.0.99"

        self.dashboard.manager.get_attack_window.return_value = (
            datetime.fromisoformat(
                "2026-09-29T10:00:00"
            ),
            datetime.fromisoformat(
                "2026-09-29T10:00:10"
            )
        )

        result = EvidenceCorrelator.find_evidence(
            self.incident,
            self.dashboard.manager
        )

        self.assertEqual(
            len(result["legacy_matches"]),
            2
        )

    def test_legacy_mixed_timezones(self):
        FileManager.save_data(
            "login_logs.json",
            [
                {
                    "event_id": "Z",
                    "ip": "10.0.0.99",
                    "username": "admin",
                    "status": "FAILED",
                    "timestamp": "2026-09-29T04:30:00Z"
                }
            ]
        )

        self.alert.event_ids = []
        self.alert.source_ip = "10.0.0.99"

        self.dashboard.manager.get_attack_window.return_value = (
            datetime.fromisoformat(
                "2026-09-29T10:00:00+05:30"
            ),
            datetime.fromisoformat(
                "2026-09-29T10:00:10+05:30"
            )
        )

        result = EvidenceCorrelator.find_evidence(
            self.incident,
            self.dashboard.manager
        )

        self.assertEqual(
            len(result["legacy_matches"]),
            1
        )


if __name__ == "__main__":
    unittest.main()