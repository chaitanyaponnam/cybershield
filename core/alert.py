
from datetime import datetime
from uuid import uuid4


class Alert:

    def __init__(
        self,
        threat_type,
        severity,
        source_ip,
        description,
        affected_file=None
    ):
        self.alert_id = str(uuid4())
        self.threat_type = threat_type
        self.severity = severity
        self.source_ip = source_ip
        self.description = description
        self.affected_file = affected_file
        self.timestamp = datetime.now().isoformat()

    def display(self):
        print(f"\nAlert ID: {self.alert_id}")
        print(f"Threat: {self.threat_type}")
        print(f"Severity: {self.severity}")
        print(f"Source IP: {self.source_ip}")

        if self.affected_file:
            print(f"Affected File: {self.affected_file}")

        print(f"Description: {self.description}")

    def to_dict(self):
        return self.__dict__.copy()