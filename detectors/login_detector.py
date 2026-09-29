
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

        # Collect failed logins by source IP.
        for event in events:
            if event["status"] != "FAILED":
                continue

            ip = event["ip"]
            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )

            failures[ip].append(timestamp)

        # Analyze each IP independently.
        for ip, timestamps in failures.items():
            timestamps.sort()

            left = 0
            right = 0

            while right < len(timestamps):
                current_time = timestamps[right]

                # Remove failures outside the window.
                while (
                    left <= right
                    and current_time - timestamps[left]
                    > self.window
                ):
                    left += 1

                count = right - left + 1

                if count >= self.threshold:
                    attack_start = timestamps[left]
                    attack_end = current_time

                    alerts.append(
                        Alert(
                            "Potential Brute Force",
                            "HIGH",
                            ip,
                            (
                                f"{count} failed logins between "
                                f"{attack_start.isoformat()} and "
                                f"{attack_end.isoformat()}"
                            )
                        )
                    )

                    # Start looking for another attack
                    # after this detected group.
                    right += 1
                    left = right
                    continue

                right += 1

        return alerts