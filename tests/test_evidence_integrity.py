
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from services.evidence_integrity import EvidenceIntegrity


class TestEvidenceIntegrity(unittest.TestCase):

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.report = (
            Path(self.temp_dir.name) / "incident_test.json"
        )

        self.report.write_text(
            '{"incident_id": "TEST-123"}',
            encoding="utf-8"
        )

    def test_manifest_creation(self):
        manifest_path = EvidenceIntegrity.create_manifest(
            self.report
        )

        self.assertTrue(manifest_path.is_file())

        with manifest_path.open(
            "r",
            encoding="utf-8"
        ) as file:
            manifest = json.load(file)

        self.assertEqual(
            manifest["algorithm"],
            "SHA-256"
        )

        self.assertEqual(
            manifest["report_filename"],
            self.report.name
        )

        self.assertEqual(
            len(manifest["sha256"]),
            64
        )

    def test_unchanged_report_is_verified(self):
        EvidenceIntegrity.create_manifest(self.report)

        result = EvidenceIntegrity.verify_report(
            self.report
        )

        self.assertEqual(
            result["status"],
            "VERIFIED"
        )

    def test_modified_report_is_detected(self):
        EvidenceIntegrity.create_manifest(self.report)

        self.report.write_text(
            '{"incident_id": "CHANGED"}',
            encoding="utf-8"
        )

        result = EvidenceIntegrity.verify_report(
            self.report
        )

        self.assertEqual(
            result["status"],
            "MODIFIED"
        )

    def test_missing_report_is_detected(self):
        EvidenceIntegrity.create_manifest(self.report)

        self.report.unlink()

        result = EvidenceIntegrity.verify_report(
            self.report
        )

        self.assertEqual(
            result["status"],
            "REPORT_MISSING"
        )

    def test_missing_manifest_is_detected(self):
        result = EvidenceIntegrity.verify_report(
            self.report
        )

        self.assertEqual(
            result["status"],
            "MANIFEST_MISSING"
        )

    def test_invalid_manifest_is_detected(self):
        manifest_path = (
            EvidenceIntegrity.get_manifest_path(
                self.report
            )
        )

        manifest_path.write_text(
            "This is not valid JSON",
            encoding="utf-8"
        )

        result = EvidenceIntegrity.verify_report(
            self.report
        )

        self.assertEqual(
            result["status"],
            "INVALID_MANIFEST"
        )


if __name__ == "__main__":
    unittest.main()