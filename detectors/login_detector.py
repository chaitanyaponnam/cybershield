
from collections import defaultdict
from datetime import datetime, timedelta

from core.alert import Alert
from core.detector import ThreatDetector


class LoginDetector(ThreatDetector):

    def __init__(
        self,
        threshold=5,
        window_minutes=5,
        quiet_minutes=10
    ):
        super().__init__("Brute Force Detector")

        if threshold < 1:
            raise ValueError("Threshold must be at least 1")

        if window_minutes <= 0 or quiet_minutes <= 0:
            raise ValueError("Time periods must be positive")

        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.quiet_period = timedelta(minutes=quiet_minutes)

    def detect(self, events):
        if not self._enabled:
            return []

        failures = defaultdict(list)
        alerts = []

        for event in events:
            if event["status"] != "FAILED":
                continue

            timestamp = datetime.fromisoformat(
                event["timestamp"]
            )

            failures[event["ip"]].append(timestamp)

        for ip, timestamps in failures.items():
            timestamps.sort()

            # Divide the timeline into separate
            # periods of activity.
            groups = []
            current_group = []

            for timestamp in timestamps:
                if current_group:
                    gap = timestamp - current_group[-1]

                    if gap > self.quiet_period:
                        groups.append(current_group)
                        current_group = []

                current_group.append(timestamp)

            if current_group:
                groups.append(current_group)

            # Each activity group can produce
            # at most one brute-force alert.
            for group in groups:
                if not self.is_brute_force(group):
                    continue

                attack_start = group[0]
                attack_end = group[-1]

                alerts.append(
                    Alert(
                        "Potential Brute Force",
                        "HIGH",
                        ip,
                        (
                            f"{len(group)} failed logins between "
                            f"{attack_start.isoformat()} and "
                            f"{attack_end.isoformat()}"
                        )
                    )
                )

        return alerts

    def is_brute_force(self, timestamps):
        """
        Check whether the activity group contains
        enough failed logins within the detection window.
        """
        left = 0

        for right, current_time in enumerate(timestamps):
            while (
                current_time - timestamps[left]
                > self.window
            ):
                left += 1

            count = right - left + 1

            if count >= self.threshold:
                return True

        return False