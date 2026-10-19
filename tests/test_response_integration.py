
import unittest

from core.incident import Incident
from core.alert import Alert
from services.response_manager import ResponseManager


class TestResponseIntegration(unittest.TestCase):

    def setUp(self):
        self.manager = ResponseManager()
        self.incident = Incident(
            title="Suspicious Login Activity",
            correlation_key="10.0.0.99"
        )

    def test_response_action_uses_real_incident_id(self):
        record = self.manager.record_action(
            self.incident.incident_id,
            "ACKNOWLEDGE"
        )

        self.assertEqual(
            record["incident_id"],
            self.incident.incident_id
        )

    def test_response_action_does_not_change_incident_status(self):
        original_status = self.incident.status

        self.manager.record_action(
            self.incident.incident_id,
            "CONTAIN"
        )

        self.assertEqual(self.incident.status, original_status)

    def test_response_action_does_not_change_incident_alerts(self):
        self.incident.add_alert(
            Alert(
                threat_type="Potential Brute Force",
                severity="HIGH",
                source_ip="10.0.0.99",
                description="Multiple failed login attempts"
            )
        )

        original_alert_count = len(self.incident.alerts)

        self.manager.record_action(
            self.incident.incident_id,
            "ESCALATE"
        )

        self.assertEqual(
            len(self.incident.alerts),
            original_alert_count
        )

    def test_multiple_actions_preserve_order(self):
        actions = ["ACKNOWLEDGE", "ESCALATE", "CONTAIN", "RESOLVE"]

        for action in actions:
            self.manager.record_action(
                self.incident.incident_id,
                action
            )

        history = self.manager.get_history(
            self.incident.incident_id
        )

        self.assertEqual(
            [record["action"] for record in history],
            actions
        )

    def test_actions_for_separate_incidents_remain_separate(self):
        other_incident = Incident(
            title="File Integrity Violation",
            correlation_key="confidential.txt"
        )

        self.manager.record_action(
            self.incident.incident_id,
            "ACKNOWLEDGE"
        )
        self.manager.record_action(
            other_incident.incident_id,
            "CONTAIN"
        )

        self.assertEqual(
            self.manager.get_action_count(self.incident.incident_id),
            1
        )
        self.assertEqual(
            self.manager.get_action_count(other_incident.incident_id),
            1
        )

    def test_action_records_analyst_and_details(self):
        record = self.manager.record_action(
            self.incident.incident_id,
            "ESCALATE",
            performed_by="SOC Tier 2",
            details="Escalated for further investigation"
        )

        self.assertEqual(record["performed_by"], "SOC Tier 2")
        self.assertEqual(
            record["details"],
            "Escalated for further investigation"
        )


if __name__ == "__main__":
    unittest.main()
