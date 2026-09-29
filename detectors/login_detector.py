
from collections import defaultdict
from datetime import datetime, timedelta

from core.detector import ThreatDetector
from core.alert import Alert


class LoginDetector(ThreatDetector):

    def __init__(self, threshold=5, window_minutes=5):
        super().__init__("Brute Force Detector")
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def detect(self, events):
        if not self._enabled:
            return []

        failures = defaultdict(list)
        alerts = []

        for event in events:
            if event["status"] != "FAILED":
                continue

            ip = event["ip"]
            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )

            failures[ip].append(timestamp)

        for ip, timestamps in failures.items():
            timestamps.sort()

            left = 0

            for right, current_time in enumerate(timestamps):
                while current_time - timestamps[left] > self.window:
                    left += 1

                count = right - left + 1

                if count >= self.threshold:
                    alerts.append(
                        Alert(
                            "Potential Brute Force",
                            "HIGH",
                            ip,
                            f"{count} failed logins within "
                            f"{self.window}"
                        )
                    )
                    break

        return alerts