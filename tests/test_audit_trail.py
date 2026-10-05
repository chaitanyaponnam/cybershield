import tempfile
import unittest
from pathlib import Path

from services.audit_trail import AuditTrail


class TestAuditTrail(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.original_audit_file = (
            AuditTrail.AUDIT_FILE
        )

        AuditTrail.AUDIT_FILE = (
            Path(self.temp_dir.name)
            / "evidence_audit.json"
        )

        self.report_path = (
            Path(self.temp_dir.name)
            / "incident_test.pdf"
        )

    def tearDown(self):
        AuditTrail.AUDIT_FILE = (
            self.original_audit_file
        )

        self.temp_dir.cleanup()

    def test_empty_audit_trail(self):
        events = AuditTrail.load_events()

        self.assertEqual(
            events,
            []
        )

    def test_record_event(self):
        event = AuditTrail.record_event(
            action="EXPORT",
            report_path=self.report_path,
            sha256="abc123",
            status="CREATED",
            incident_id="INC-001"
        )

        self.assertEqual(
            event["action"],
            "EXPORT"
        )

        self.assertEqual(
            event["incident_id"],
            "INC-001"
        )

        self.assertEqual(
            event["status"],
            "CREATED"
        )

        events = AuditTrail.load_events()

        self.assertEqual(
            len(events),
            1
        )

    def test_multiple_events_are_preserved(self):
        AuditTrail.record_event(
            action="EXPORT",
            report_path=self.report_path,
            status="CREATED"
        )

        AuditTrail.record_event(
            action="VERIFY",
            report_path=self.report_path,
            status="VERIFIED"
        )

        events = AuditTrail.load_events()

        self.assertEqual(
            len(events),
            2
        )

        self.assertEqual(
            events[0]["action"],
            "EXPORT"
        )

        self.assertEqual(
            events[1]["action"],
            "VERIFY"
        )

    def test_filter_by_action(self):
        AuditTrail.record_event(
            action="EXPORT",
            report_path=self.report_path
        )

        AuditTrail.record_event(
            action="VERIFY",
            report_path=self.report_path
        )

        events = AuditTrail.get_events(
            action="VERIFY"
        )

        self.assertEqual(
            len(events),
            1
        )

        self.assertEqual(
            events[0]["action"],
            "VERIFY"
        )

    def test_filter_by_incident(self):
        AuditTrail.record_event(
            action="EXPORT",
            report_path=self.report_path,
            incident_id="INC-001"
        )

        AuditTrail.record_event(
            action="EXPORT",
            report_path=self.report_path,
            incident_id="INC-002"
        )

        events = AuditTrail.get_events(
            incident_id="INC-002"
        )

        self.assertEqual(
            len(events),
            1
        )

        self.assertEqual(
            events[0]["incident_id"],
            "INC-002"
        )

    def test_audit_ids_are_unique(self):
        first = AuditTrail.record_event(
            action="EXPORT",
            report_path=self.report_path
        )

        second = AuditTrail.record_event(
            action="VERIFY",
            report_path=self.report_path
        )

        self.assertNotEqual(
            first["audit_id"],
            second["audit_id"]
        )


if __name__ == "__main__":
    unittest.main()