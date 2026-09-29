
from datetime import datetime
from uuid import uuid4


class Incident:

    SEVERITY_LEVELS = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    def __init__(self, title, correlation_key):
        self.incident_id = str(uuid4())
        self.title = title
        self.correlation_key = correlation_key
        self.alerts = []
        self.notes = []
        self.severity = "LOW"
        self.status = "OPEN"
        self.created_at = datetime.now().isoformat()

    def add_alert(self, alert):
        self.alerts.append(alert)

        current = self.SEVERITY_LEVELS[
            self.severity
        ]

        incoming = self.SEVERITY_LEVELS[
            alert.severity
        ]

        if incoming > current:
            self.severity = alert.severity

    def display(self):
        print(
            f"\nIncident ID: {self.incident_id}"
        )
        print(f"Title: {self.title}")
        print(f"Severity: {self.severity}")
        print(f"Status: {self.status}")
        print(
            f"Related Alerts: {len(self.alerts)}"
        )

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "correlation_key": self.correlation_key,
            "severity": self.severity,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at,
            "alerts": [
                alert.to_dict()
                for alert in self.alerts
            ]
        }

    def update_status(self, new_status):
        valid_statuses = {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED"
        }

        if new_status not in valid_statuses:
            raise ValueError(
                f"Invalid incident status: "
                f"{new_status}"
            )

        self.status = new_status

    @classmethod
    def from_dict(cls, data):
        """
        Restore an incident and its alerts
        from saved JSON.

        Older alerts without event_ids
        remain compatible.
        """
        from core.alert import Alert

        incident = cls(
            data["title"],
            data["correlation_key"]
        )

        incident.incident_id = data["incident_id"]
        incident.severity = data["severity"]
        incident.status = data["status"]
        incident.created_at = data["created_at"]
        incident.notes = data.get(
            "notes",
            []
        )

        for alert_data in data["alerts"]:
            alert = Alert(
                alert_data["threat_type"],
                alert_data["severity"],
                alert_data["source_ip"],
                alert_data["description"],
                affected_file=alert_data.get(
                    "affected_file"
                ),
                event_ids=alert_data.get(
                    "event_ids",
                    []
                )
            )

            alert.alert_id = (
                alert_data["alert_id"]
            )

            alert.timestamp = (
                alert_data["timestamp"]
            )

            incident.alerts.append(
                alert
            )

        return incident

    def add_note(self, analyst, message):
        if not analyst.strip() or not message.strip():
            raise ValueError(
                "Analyst and message cannot be empty."
            )

        note = {
            "analyst": analyst.strip(),
            "message": message.strip(),
            "timestamp": datetime.now().isoformat()
        }

        self.notes.append(note)

        return note