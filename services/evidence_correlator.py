
from datetime import timedelta

from services.event_timeline import EventTimeline
from services.log_history import LogHistory


class EvidenceCorrelator:
    """Read-only lookup of saved login events for a security incident."""

    @staticmethod
    def parse_timestamp(value):
        return EventTimeline.parse_timestamp(value)

    @classmethod
    def find_evidence(
        cls,
        incident,
        incident_manager,
        legacy_tolerance_minutes=0
    ):
        if legacy_tolerance_minutes < 0:
            raise ValueError("Legacy tolerance cannot be negative.")

        events = LogHistory.load_events()
        tracked_ids = set()
        legacy_alerts = []

        for alert in incident.alerts:
            if alert.threat_type != "Potential Brute Force":
                continue

            ids = getattr(alert, "event_ids", None) or []

            if ids:
                tracked_ids.update(ids)
            else:
                legacy_alerts.append(alert)

        exact_matches = []
        exact_ids_found = set()

        for event in events:
            if not isinstance(event, dict):
                continue

            event_id = event.get("event_id")

            if (
                event_id in tracked_ids
                and event_id not in exact_ids_found
            ):
                exact_matches.append(event)
                exact_ids_found.add(event_id)

        # Preserve separate historical records even when
        # their contents happen to be identical.
        legacy_positions = set()
        tolerance = timedelta(
            minutes=legacy_tolerance_minutes
        )

        for alert in legacy_alerts:
            window = incident_manager.get_attack_window(alert)

            if not window:
                continue

            start = cls._normalize_datetime(window[0])
            end = cls._normalize_datetime(window[1])

            if start is None or end is None:
                continue

            start -= tolerance
            end += tolerance

            for position, event in enumerate(events):
                if not isinstance(event, dict):
                    continue

                if event.get("ip") != alert.source_ip:
                    continue

                if (
                    str(event.get("status", "")).upper()
                    != "FAILED"
                ):
                    continue

                if event.get("event_id") in exact_ids_found:
                    continue

                timestamp = cls.parse_timestamp(
                    event.get("timestamp")
                )

                if (
                    timestamp is not None
                    and start <= timestamp <= end
                ):
                    legacy_positions.add(position)

        legacy_matches = [
            events[position]
            for position in sorted(legacy_positions)
        ]

        exact_matches.sort(key=cls._sort_key)
        legacy_matches.sort(key=cls._sort_key)

        return {
            "exact_matches": exact_matches,
            "legacy_matches": legacy_matches,
            "tracked_event_ids": len(tracked_ids),
            "missing_tracked_events": len(
                tracked_ids - exact_ids_found
            ),
            "legacy_alerts": len(legacy_alerts),
        }

    @classmethod
    def _normalize_datetime(cls, value):
        if isinstance(value, str):
            return cls.parse_timestamp(value)

        if hasattr(value, "isoformat"):
            return cls.parse_timestamp(
                value.isoformat()
            )

        return None

    @classmethod
    def _sort_key(cls, event):
        timestamp = cls.parse_timestamp(
            event.get("timestamp")
        )

        # Invalid timestamps appear last.
        return (timestamp is None, timestamp)

    @staticmethod
    def display(result):
        print("\n===== INCIDENT LOGIN EVIDENCE =====")
        print(
            "Tracked event IDs:",
            result["tracked_event_ids"]
        )
        print(
            "Exact matches found:",
            len(result["exact_matches"])
        )
        print(
            "Missing tracked events:",
            result["missing_tracked_events"]
        )
        print(
            "Legacy alerts:",
            result["legacy_alerts"]
        )

        for heading, events in (
            (
                "EXACT EVENT-ID MATCHES",
                result["exact_matches"]
            ),
            (
                "APPROXIMATE LEGACY MATCHES",
                result["legacy_matches"]
            ),
        ):
            print(f"\n===== {heading} =====")

            if not events:
                print("No matches found.")

            for event in events:
                print("-" * 45)
                print(
                    "Time:",
                    event.get("timestamp", "Unknown")
                )
                print(
                    "Source IP:",
                    event.get("ip", "Unknown")
                )
                print(
                    "Username:",
                    event.get("username", "Unknown")
                )
                print(
                    "Status:",
                    event.get("status", "Unknown")
                )
                print(
                    "Event ID:",
                    event.get("event_id")
                    or "Legacy event"
                )

        if result["legacy_matches"]:
            print(
                "\nLegacy matches are approximate, "
                "not verified event-ID links."
            )