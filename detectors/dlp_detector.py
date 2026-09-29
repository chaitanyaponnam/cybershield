
import re

from core.detector import ThreatDetector
from core.alert import Alert


class DLPDetector(ThreatDetector):

    PATTERNS = {
        "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "Indian Phone Number": r"(?<!\d)[6-9]\d{9}(?!\d)",
        "Test Account Number": r"\bACC-\d{8}\b"
    }

    def __init__(self):
        super().__init__("Data Loss Prevention Detector")

    def detect(self, events):
        if not self._enabled:
            return []

        alerts = []

        for event in events:
            filename = event["filename"]
            content = event["content"]

            for data_type, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, content)

                if matches:
                    alerts.append(
                        Alert(
                            "Sensitive Data Detected",
                            "MEDIUM",
                            "LOCAL_FILE",
                            f"{data_type}: {len(matches)} "
                            f"occurrence(s) in {filename}",
                            affected_file=filename
                        )
                    )

        return alerts