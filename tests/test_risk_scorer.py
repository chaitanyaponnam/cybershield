import unittest

from core.alert import Alert
from core.incident import Incident
from services.risk_scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):

    def create_incident(
        self,
        severity="LOW",
        status="OPEN",
        alerts=None
    ):
        incident = Incident(
            "Test Incident",
            "TEST"
        )

        incident.severity = severity
        incident.status = status

        for alert in alerts or []:
            incident.add_alert(alert)

        return incident

    def test_low_risk_incident(self):
        incident = self.create_incident()

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 25)
        self.assertEqual(
            RiskScorer.classify(score),
            "MEDIUM"
        )

    def test_high_severity_increases_score(self):
        incident = self.create_incident(
            severity="HIGH"
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 45)

    def test_sensitive_data_has_highest_threat_score(self):
        alert = Alert(
            "Sensitive Data Detected",
            "CRITICAL",
            "10.0.0.10",
            "Sensitive data detected."
        )

        incident = self.create_incident(
            severity="CRITICAL",
            alerts=[alert]
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 75)

    def test_multiple_alerts_increase_score(self):
        alerts = [
            Alert(
                "Potential Brute Force",
                "HIGH",
                "10.0.0.10",
                "Brute force detected."
            ),
            Alert(
                "Potential Brute Force",
                "HIGH",
                "10.0.0.10",
                "Brute force detected."
            ),
            Alert(
                "Potential Brute Force",
                "HIGH",
                "10.0.0.10",
                "Brute force detected."
            ),
        ]

        incident = self.create_incident(
            severity="HIGH",
            alerts=alerts
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 70)

    def test_investigating_status_increases_score(self):
        incident = self.create_incident(
            severity="HIGH",
            status="INVESTIGATING"
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 50)

    def test_resolved_status_has_no_status_score(self):
        incident = self.create_incident(
            severity="HIGH",
            status="RESOLVED"
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 40)

    def test_score_is_capped_at_100(self):
        alerts = [
            Alert(
                "Sensitive Data Detected",
                "CRITICAL",
                "10.0.0.10",
                "Sensitive data detected."
            )
            for _ in range(10)
        ]

        incident = self.create_incident(
            severity="CRITICAL",
            status="INVESTIGATING",
            alerts=alerts
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 100)

    def test_risk_classification(self):
        self.assertEqual(
            RiskScorer.classify(0),
            "LOW"
        )

        self.assertEqual(
            RiskScorer.classify(24),
            "LOW"
        )

        self.assertEqual(
            RiskScorer.classify(25),
            "MEDIUM"
        )

        self.assertEqual(
            RiskScorer.classify(49),
            "MEDIUM"
        )

        self.assertEqual(
            RiskScorer.classify(50),
            "HIGH"
        )

        self.assertEqual(
            RiskScorer.classify(74),
            "HIGH"
        )

        self.assertEqual(
            RiskScorer.classify(75),
            "CRITICAL"
        )

        self.assertEqual(
            RiskScorer.classify(100),
            "CRITICAL"
        )

    def test_unknown_threat_uses_default_score(self):
        alert = Alert(
            "Unknown Threat",
            "LOW",
            "10.0.0.10",
            "Unknown activity."
        )

        incident = self.create_incident(
            alerts=[alert]
        )

        score = RiskScorer.calculate(
            incident
        )

        self.assertEqual(score, 30)

    def test_risk_scoring_is_read_only(self):
        alert = Alert(
            "Sensitive Data Detected",
            "CRITICAL",
            "10.0.0.10",
            "Sensitive data detected."
        )

        incident = self.create_incident(
            severity="CRITICAL",
            status="INVESTIGATING",
            alerts=[alert]
        )

        original_severity = incident.severity
        original_status = incident.status
        original_alert_count = len(
            incident.alerts
        )

        RiskScorer.calculate(
            incident
        )

        self.assertEqual(
            incident.severity,
            original_severity
        )

        self.assertEqual(
            incident.status,
            original_status
        )

        self.assertEqual(
            len(incident.alerts),
            original_alert_count
        )


if __name__ == "__main__":
    unittest.main()