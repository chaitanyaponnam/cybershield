
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from services.file_manager import FileManager
from services.evidence_correlator import EvidenceCorrelator


class TestEvidenceCorrelator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_data_dir = FileManager.DATA_DIR
        FileManager.DATA_DIR = Path(self.temp_dir.name)

        self.events = [
            {
                "event_id": "A",
                "ip": "10.0.0.99",
                "username": "admin",
                "status": "FAILED",
                "timestamp": "2026-09-29T10:00:00"
            },
            {
                "event_id": "B",
                "ip": "10.0.0.99",
                "username": "admin",
                "status": "FAILED",
                "timestamp": "2026-09-29T10:00:10"
            },
            {
                "event_id": "C",
                "ip": "192.168.1.20",
                "username": "user1",
                "status": "SUCCESS",
                "timestamp": "2026-09-29T10:00:20"
            }
        ]

        FileManager.save_data(
            "login_logs.json",
            self.events
        )

        self.manager = Mock()

    def tearDown(self):
        FileManager.DATA_DIR = self.original_data_dir
        self.temp_dir.cleanup()

    @staticmethod
    def make_incident(event_ids):
        alert = Mock()
        alert.threat_type = "Potential Brute Force"
        alert.event_ids = event_ids
        alert.source_ip = "10.0.0.99"

        incident = Mock()
        incident.alerts = [alert]

        return incident

    def test_exact_event_id_matching(self):
        incident = self.make_incident(["A", "B"])

        result = EvidenceCorrelator.find_evidence(
            incident,
            self.manager
        )

        self.assertEqual(
            len(result["exact_matches"]),
            2
        )
        self.assertEqual(
            result["missing_tracked_events"],
            0
        )

    def test_missing_event_is_reported(self):
        incident = self.make_incident(["A", "MISSING"])

        result = EvidenceCorrelator.find_evidence(
            incident,
            self.manager
        )

        self.assertEqual(
            len(result["exact_matches"]),
            1
        )
        self.assertEqual(
            result["missing_tracked_events"],
            1
        )

    def test_duplicate_ids_count_once(self):
        incident = self.make_incident(["A", "A", "B"])

        result = EvidenceCorrelator.find_evidence(
            incident,
            self.manager
        )

        self.assertEqual(
            result["tracked_event_ids"],
            2
        )
        self.assertEqual(
            len(result["exact_matches"]),
            2
        )

    def test_legacy_evidence_by_ip_and_time(self):
        incident = self.make_incident([])
        self.manager.get_attack_window.return_value = (
            datetime.fromisoformat(
                "2026-09-29T10:00:00"
            ),
            datetime.fromisoformat(
                "2026-09-29T10:00:15"
            )
        )

        result = EvidenceCorrelator.find_evidence(
            incident,
            self.manager
        )

        self.assertEqual(
            len(result["legacy_matches"]),
            2
        )
        self.assertEqual(
            result["legacy_alerts"],
            1
        )

    def test_unrelated_events_are_excluded(self):
        incident = self.make_incident(["A"])

        result = EvidenceCorrelator.find_evidence(
            incident,
            self.manager
        )

        self.assertEqual(
            [
                event["event_id"]
                for event in result["exact_matches"]
            ],
            ["A"]
        )

    def test_read_only_operation(self):
        incident = self.make_incident(["A"])

        before = FileManager.load_data(
            "login_logs.json"
        )

        EvidenceCorrelator.find_evidence(
            incident,
            self.manager
        )

        after = FileManager.load_data(
            "login_logs.json"
        )

        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()