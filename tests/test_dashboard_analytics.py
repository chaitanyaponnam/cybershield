import unittest
from unittest.mock import Mock

from services.dashboard_analytics import DashboardAnalytics


class TestDashboardAnalytics(unittest.TestCase):

    def create_alert(
        self,
        threat_type,
        source_ip=None
    ):
        alert = Mock()
        alert.threat_type = threat_type
        alert.source_ip = source_ip

        return alert

    def create_incident(
        self,
        severity,
        status,
        alerts
    ):
        incident = Mock()
        incident.severity = severity
        incident.status = status
        incident.alerts = alerts

        return incident

    def test_empty_incidents(self):
        analytics = DashboardAnalytics.calculate([])

        self.assertEqual(
            analytics["total_incidents"],
            0
        )

        self.assertEqual(
            analytics["total_alerts"],
            0
        )

        self.assertEqual(
            analytics["severity"],
            {}
        )

        self.assertEqual(
            analytics["status"],
            {}
        )

        self.assertEqual(
            analytics["threat_types"],
            {}
        )

        self.assertEqual(
            analytics["source_ips"],
            {}
        )

    def test_incident_and_alert_counts(self):
        incident1 = self.create_incident(
            "HIGH",
            "OPEN",
            [
                self.create_alert(
                    "Potential Brute Force",
                    "10.0.0.99"
                ),
                self.create_alert(
                    "Potential Brute Force",
                    "10.0.0.99"
                )
            ]
        )

        incident2 = self.create_incident(
            "CRITICAL",
            "INVESTIGATING",
            [
                self.create_alert(
                    "DLP Alert",
                    "10.0.0.50"
                )
            ]
        )

        analytics = DashboardAnalytics.calculate(
            [incident1, incident2]
        )

        self.assertEqual(
            analytics["total_incidents"],
            2
        )

        self.assertEqual(
            analytics["total_alerts"],
            3
        )

    def test_severity_counts(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "CRITICAL",
                "INVESTIGATING",
                []
            ),
            self.create_incident(
                "LOW",
                "RESOLVED",
                []
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        self.assertEqual(
            analytics["severity"]["HIGH"],
            2
        )

        self.assertEqual(
            analytics["severity"]["CRITICAL"],
            1
        )

        self.assertEqual(
            analytics["severity"]["LOW"],
            1
        )

        self.assertEqual(
            analytics["severity"].get(
                "MEDIUM",
                0
            ),
            0
        )

    def test_status_counts(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "MEDIUM",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "INVESTIGATING",
                []
            ),
            self.create_incident(
                "LOW",
                "RESOLVED",
                []
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        self.assertEqual(
            analytics["status"]["OPEN"],
            2
        )

        self.assertEqual(
            analytics["status"]["INVESTIGATING"],
            1
        )

        self.assertEqual(
            analytics["status"]["RESOLVED"],
            1
        )

    def test_threat_type_counts(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force"
                    ),
                    self.create_alert(
                        "Potential Brute Force"
                    ),
                    self.create_alert(
                        "DLP Alert"
                    )
                ]
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Integrity Alert"
                    )
                ]
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        self.assertEqual(
            analytics["threat_types"][
                "Potential Brute Force"
            ],
            2
        )

        self.assertEqual(
            analytics["threat_types"][
                "DLP Alert"
            ],
            1
        )

        self.assertEqual(
            analytics["threat_types"][
                "Integrity Alert"
            ],
            1
        )

    def test_source_ip_counts(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.99"
                    )
                ]
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Potential Brute Force",
                        "10.0.0.50"
                    )
                ]
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        self.assertEqual(
            analytics["source_ips"]["10.0.0.99"],
            2
        )

        self.assertEqual(
            analytics["source_ips"]["10.0.0.50"],
            1
        )

    def test_top_threats(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Brute Force"
                    ),
                    self.create_alert(
                        "Brute Force"
                    ),
                    self.create_alert(
                        "DLP Alert"
                    )
                ]
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        top = DashboardAnalytics.top_threats(
            analytics
        )

        self.assertEqual(
            top[0],
            ("Brute Force", 2)
        )

        self.assertEqual(
            top[1],
            ("DLP Alert", 1)
        )

    def test_top_source_ips(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Brute Force",
                        "10.0.0.99"
                    ),
                    self.create_alert(
                        "Brute Force",
                        "10.0.0.50"
                    )
                ]
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        top = DashboardAnalytics.top_source_ips(
            analytics
        )

        self.assertEqual(
            top[0],
            ("10.0.0.99", 2)
        )

        self.assertEqual(
            top[1],
            ("10.0.0.50", 1)
        )

    def test_severity_helper(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        self.assertEqual(
            DashboardAnalytics.get_severity_count(
                analytics,
                "HIGH"
            ),
            2
        )

        self.assertEqual(
            DashboardAnalytics.get_severity_count(
                analytics,
                "CRITICAL"
            ),
            0
        )

    def test_status_helper(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                []
            ),
            self.create_incident(
                "HIGH",
                "INVESTIGATING",
                []
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        self.assertEqual(
            DashboardAnalytics.get_status_count(
                analytics,
                "OPEN"
            ),
            1
        )

        self.assertEqual(
            DashboardAnalytics.get_status_count(
                analytics,
                "RESOLVED"
            ),
            0
        )

    def test_top_threat_limit(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert("Threat A"),
                    self.create_alert("Threat B"),
                    self.create_alert("Threat C")
                ]
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        top = DashboardAnalytics.top_threats(
            analytics,
            limit=2
        )

        self.assertEqual(
            len(top),
            2
        )

    def test_top_source_ip_limit(self):
        incidents = [
            self.create_incident(
                "HIGH",
                "OPEN",
                [
                    self.create_alert(
                        "Threat A",
                        "10.0.0.1"
                    ),
                    self.create_alert(
                        "Threat B",
                        "10.0.0.2"
                    ),
                    self.create_alert(
                        "Threat C",
                        "10.0.0.3"
                    )
                ]
            )
        ]

        analytics = DashboardAnalytics.calculate(
            incidents
        )

        top = DashboardAnalytics.top_source_ips(
            analytics,
            limit=2
        )

        self.assertEqual(
            len(top),
            2
        )


if __name__ == "__main__":
    unittest.main()