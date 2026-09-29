
from datetime import datetime, timezone

from services.log_history import LogHistory


class EventTimeline:
    """Read-only access to historical login events."""

    @staticmethod
    def parse_timestamp(value):
        if not isinstance(value, str):
            return None

        try:
            timestamp = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            return None

        # Treat older timestamps without a timezone
        # as local system time.
        if timestamp.tzinfo is None:
            timestamp = timestamp.astimezone()

        return timestamp.astimezone(timezone.utc)

    @classmethod
    def search(
        cls,
        source_ip=None,
        status=None,
        start_time=None,
        end_time=None
    ):
        events = LogHistory.load_events()

        start = (
            cls.parse_timestamp(start_time)
            if start_time else None
        )

        end = (
            cls.parse_timestamp(end_time)
            if end_time else None
        )

        if start_time and start is None:
            raise ValueError(
                "Invalid start time. Use ISO format."
            )

        if end_time and end is None:
            raise ValueError(
                "Invalid end time. Use ISO format."
            )

        if start and end and start > end:
            raise ValueError(
                "Start time must be before end time."
            )

        results = []

        for event in events:
            if not isinstance(event, dict):
                continue

            if (
                source_ip
                and event.get("ip") != source_ip
            ):
                continue

            if (
                status
                and str(
                    event.get("status", "")
                ).upper() != status.upper()
            ):
                continue

            timestamp = cls.parse_timestamp(
                event.get("timestamp")
            )

            if timestamp is None:
                continue

            if start and timestamp < start:
                continue

            if end and timestamp > end:
                continue

            results.append(
                (timestamp, event)
            )

        results.sort(key=lambda item: item[0])

        return [
            event
            for _, event in results
        ]

    @staticmethod
    def summarize(events):
        return {
            "total": len(events),
            "successful": sum(
                str(
                    event.get("status", "")
                ).upper() == "SUCCESS"
                for event in events
            ),
            "failed": sum(
                str(
                    event.get("status", "")
                ).upper() == "FAILED"
                for event in events
            ),
            "unique_source_ips": len({
                event.get("ip")
                for event in events
                if event.get("ip")
            })
        }

    @classmethod
    def display(cls, events):
        print("\n===== SOC EVENT TIMELINE =====")

        if not events:
            print("No matching login events.")
            return

        for event in events:
            print("-" * 45)
            print(
                "Time:",
                event.get(
                    "timestamp", "Unknown"
                )
            )
            print(
                "Source IP:",
                event.get("ip", "Unknown")
            )
            print(
                "Username:",
                event.get(
                    "username", "Unknown"
                )
            )
            print(
                "Status:",
                event.get(
                    "status", "Unknown"
                )
            )
            print(
                "Event ID:",
                event.get(
                    "event_id",
                    "Legacy event"
                )
            )

        summary = cls.summarize(events)

        print("\n===== TIMELINE SUMMARY =====")
        print("Total events:", summary["total"])
        print(
            "Successful:",
            summary["successful"]
        )
        print("Failed:", summary["failed"])
        print(
            "Unique source IPs:",
            summary["unique_source_ips"]
        )