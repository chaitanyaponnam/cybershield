import unittest

from core.alert import Alert
from core.incident import Incident
from services.incident_filter import IncidentFilter


class TestIncidentFilter(unittest.TestCase):

    def setUp(self):
        self.incident_1 = Incident(
            "Brute Force Attack",
            "10.0.0.10"
        )

        self.incident_2 = Incident(
            "Sensitive Data Exposure",
            "10.0.0.20"
        )

        self.incident_3 = Incident(
            "File Integrity Violation",
            "LOCAL_FILE"
        )

        self.alert_1 = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.10",
            "Multiple failed login attempts detected."
        )

        self.alert_2 = Alert(
            "Sensitive Data Detected",
            "CRITICAL",
            "10.0.0.20",
            "Sensitive data detected in a document."
        )

        self.alert_3 = Alert(
            "File Integrity Violation",
            "HIGH",
            "LOCAL_FILE",
            "File modification detected."
        )

        self.incident_1.add_alert(self.alert_1)
        self.incident_2.add_alert(self.alert_2)
        self.incident_3.add_alert(self.alert_3)

        self.incident_1.update_status("OPEN")
        self.incident_2.update_status("INVESTIGATING")
        self.incident_3.update_status("RESOLVED")

        self.incidents = [
            self.incident_1,
            self.incident_2,
            self.incident_3
        ]

    def test_filter_by_severity(self):
        results = IncidentFilter.by_severity(
            self.incidents,
            "HIGH"
        )

        self.assertEqual(len(results), 2)
        self.assertIn(self.incident_1, results)
        self.assertIn(self.incident_3, results)

    def test_filter_by_status(self):
        results = IncidentFilter.by_status(
            self.incidents,
            "INVESTIGATING"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_2, results)

    def test_filter_by_threat_type(self):
        results = IncidentFilter.by_threat_type(
            self.incidents,
            "Potential Brute Force"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_1, results)

    def test_filter_by_source_ip(self):
        results = IncidentFilter.by_source_ip(
            self.incidents,
            "10.0.0.20"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_2, results)

    def test_search_by_incident_id(self):
        results = IncidentFilter.by_incident_id(
            self.incidents,
            self.incident_2.incident_id
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_2, results)

    def test_filter_returns_empty_when_no_match(self):
        results = IncidentFilter.by_severity(
            self.incidents,
            "LOW"
        )

        self.assertEqual(results, [])

    def test_filter_does_not_modify_incidents(self):
        original_incidents = list(self.incidents)

        IncidentFilter.by_severity(
            self.incidents,
            "HIGH"
        )

        self.assertEqual(
            self.incidents,
            original_incidents
        )

    def test_severity_filter_is_case_insensitive(self):
        results = IncidentFilter.by_severity(
            self.incidents,
            "high"
        )

        self.assertEqual(len(results), 2)

    def test_status_filter_is_case_insensitive(self):
        results = IncidentFilter.by_status(
            self.incidents,
            "investigating"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_2, results)

    def test_severity_filter_ignores_whitespace(self):
        results = IncidentFilter.by_severity(
            self.incidents,
            "  HIGH  "
        )

        self.assertEqual(len(results), 2)

    def test_threat_type_filter_is_case_insensitive(self):
        results = IncidentFilter.by_threat_type(
            self.incidents,
            "potential brute force"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_1, results)

    def test_source_ip_filter_ignores_whitespace(self):
        results = IncidentFilter.by_source_ip(
            self.incidents,
            " 10.0.0.20 "
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_2, results)

    def test_nonexistent_incident_id_returns_empty(self):
        results = IncidentFilter.by_incident_id(
            self.incidents,
            "does-not-exist"
        )

        self.assertEqual(results, [])

    def test_empty_incident_list(self):
        self.assertEqual(
            IncidentFilter.by_severity([], "HIGH"),
            []
        )

        self.assertEqual(
            IncidentFilter.by_status([], "OPEN"),
            []
        )

        self.assertEqual(
            IncidentFilter.by_threat_type(
                [],
                "Potential Brute Force"
            ),
            []
        )

        self.assertEqual(
            IncidentFilter.by_source_ip(
                [],
                "10.0.0.10"
            ),
            []
        )

        self.assertEqual(
            IncidentFilter.by_incident_id(
                [],
                "anything"
            ),
            []
        )

    def test_multiple_matching_alerts_return_incident_once(self):
        duplicate_alert = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.10",
            "Another brute force alert."
        )

        self.incident_1.add_alert(
            duplicate_alert
        )

        results = IncidentFilter.by_threat_type(
            self.incidents,
            "Potential Brute Force"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_1, results)

    def test_multiple_matching_source_ips_return_incident_once(self):
        duplicate_alert = Alert(
            "Potential Brute Force",
            "HIGH",
            "10.0.0.10",
            "Another alert from same source."
        )

        self.incident_1.add_alert(
            duplicate_alert
        )

        results = IncidentFilter.by_source_ip(
            self.incidents,
            "10.0.0.10"
        )

        self.assertEqual(len(results), 1)
        self.assertIn(self.incident_1, results)


if __name__ == "__main__":
    unittest.main()