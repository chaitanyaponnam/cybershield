
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

        # Collect failed login timestamps by source IP
        for event in events:
            if event["status"] != "FAILED":
                continue

            ip = event["ip"]
            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )

            failures[ip].append(timestamp)

        # Analyze each IP independently
        for ip, timestamps in failures.items():
            timestamps.sort()

            left = 0

            for right, current_time in enumerate(timestamps):

                # Keep only failures within the time window
                while current_time - timestamps[left] > self.window:
                    left += 1

                count = right - left + 1

                if count >= self.threshold:

                    # Record the actual attack window
                    attack_start = timestamps[left]
                    attack_end = current_time

                    alert = Alert(
                        "Potential Brute Force",
                        "HIGH",
                        ip,
                        (
                            f"{count} failed logins between "
                            f"{attack_start.isoformat()} and "
                            f"{attack_end.isoformat()}"
                        )
                    )

                    alerts.append(alert)

                    # Generate one alert per IP per scan
                    break

        return alerts