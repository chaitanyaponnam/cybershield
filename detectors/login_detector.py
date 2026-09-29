
import hashlib
import json
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
            raise ValueError(
                "Threshold must be at least 1"
            )

        if window_minutes <= 0 or quiet_minutes <= 0:
            raise ValueError(
                "Time periods must be positive"
            )

        self.threshold = threshold
        self.window = timedelta(
            minutes=window_minutes
        )
        self.quiet_period = timedelta(
            minutes=quiet_minutes
        )

    @staticmethod
    def get_event_id(event):
        """
        Prefer an existing event ID supplied
        by the log source.

        Otherwise, derive a deterministic ID
        from the event's available fields.
        """
        if event.get("event_id") is not None:
            return str(event["event_id"])

        canonical_event = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            default=str
        )

        return hashlib.sha256(
            canonical_event.encode("utf-8")
        ).hexdigest()

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

            event_id = self.get_event_id(
                event
            )

            failures[event["ip"]].append(
                (timestamp, event_id)
            )

        for ip, entries in failures.items():
            # Sort by time, then by ID for
            # consistent processing.
            entries.sort(
                key=lambda item: (
                    item[0],
                    item[1]
                )
            )

            # Remove duplicate events within
            # the same scan.
            unique_entries = []
            seen_ids = set()

            for timestamp, event_id in entries:
                if event_id in seen_ids:
                    continue

                seen_ids.add(event_id)

                unique_entries.append(
                    (timestamp, event_id)
                )

            # Separate periods of activity
            # using the quiet period.
            groups = []
            current_group = []

            for entry in unique_entries:
                timestamp = entry[0]

                if current_group:
                    previous_time = (
                        current_group[-1][0]
                    )

                    gap = (
                        timestamp - previous_time
                    )

                    if gap > self.quiet_period:
                        groups.append(
                            current_group
                        )

                        current_group = []

                current_group.append(
                    entry
                )

            if current_group:
                groups.append(
                    current_group
                )

            for group in groups:
                timestamps = [
                    timestamp
                    for timestamp, event_id in group
                ]

                if not self.is_brute_force(
                    timestamps
                ):
                    continue

                attack_start = (
                    group[0][0]
                )

                attack_end = (
                    group[-1][0]
                )

                event_ids = [
                    event_id
                    for timestamp, event_id in group
                ]

                alerts.append(
                    Alert(
                        "Potential Brute Force",
                        "HIGH",
                        ip,
                        (
                            f"{len(event_ids)} "
                            f"failed logins between "
                            f"{attack_start.isoformat()} "
                            f"and "
                            f"{attack_end.isoformat()}"
                        ),
                        event_ids=event_ids
                    )
                )

        return alerts

    def is_brute_force(self, timestamps):
        """
        Check whether a group contains
        enough failures within the
        detection window.
        """
        left = 0

        for right, current_time in enumerate(
            timestamps
        ):
            while (
                current_time - timestamps[left]
                > self.window
            ):
                left += 1

            count = (
                right - left + 1
            )

            if count >= self.threshold:
                return True

        return False