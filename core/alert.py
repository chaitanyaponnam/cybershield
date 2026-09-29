
from datetime import datetime
from uuid import uuid4


class Alert:

    def __init__(
        self,
        threat_type,
        severity,
        source_ip,
        description,
        affected_file=None,
        event_ids=None
    ):
        self.alert_id = str(uuid4())
        self.threat_type = threat_type
        self.severity = severity
        self.source_ip = source_ip
        self.description = description
        self.affected_file = affected_file
        self.timestamp = datetime.now().isoformat()

        # Optional IDs of the individual events
        # that contributed to this alert.
        self.event_ids = list(
            dict.fromkeys(event_ids or [])
        )

    def display(self):
        print(f"\nAlert ID: {self.alert_id}")
        print(f"Threat: {self.threat_type}")
        print(f"Severity: {self.severity}")
        print(f"Source IP: {self.source_ip}")

        if self.affected_file:
            print(
                f"Affected File: "
                f"{self.affected_file}"
            )

        print(
            f"Description: "
            f"{self.description}"
        )

        if self.event_ids:
            print(
                f"Tracked Login Events: "
                f"{len(self.event_ids)}"
            )

    def to_dict(self):
        return self.__dict__.copy()