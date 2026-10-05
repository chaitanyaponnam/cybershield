import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class AuditTrail:
    """Maintain an append-only audit history for evidence operations."""

    AUDIT_FILE = Path("data/evidence_audit.json")

    @classmethod
    def load_events(cls):
        if not cls.AUDIT_FILE.exists():
            return []

        try:
            with cls.AUDIT_FILE.open(
                "r",
                encoding="utf-8"
            ) as file:
                data = json.load(file)

        except (OSError, json.JSONDecodeError):
            return []

        if not isinstance(data, list):
            return []

        return data

    @classmethod
    def save_events(cls, events):
        cls.AUDIT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with cls.AUDIT_FILE.open(
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                events,
                file,
                indent=4
            )

    @classmethod
    def record_event(
        cls,
        action,
        report_path,
        sha256=None,
        status=None,
        incident_id=None
    ):
        events = cls.load_events()

        event = {
            "audit_id": str(uuid4()),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "action": action,
            "report_path": str(
                Path(report_path).resolve()
            ),
            "report_filename": Path(
                report_path
            ).name,
            "incident_id": incident_id,
            "sha256": sha256,
            "status": status
        }

        events.append(event)

        cls.save_events(events)

        return event

    @classmethod
    def get_events(
        cls,
        action=None,
        incident_id=None
    ):
        events = cls.load_events()

        if action:
            events = [
                event
                for event in events
                if event.get("action") == action
            ]

        if incident_id:
            events = [
                event
                for event in events
                if event.get("incident_id")
                == incident_id
            ]

        return events

    @classmethod
    def display_events(cls, events=None):
        if events is None:
            events = cls.load_events()

        print("\n===== EVIDENCE AUDIT TRAIL =====")

        if not events:
            print("No evidence audit events found.")
            return

        for event in events:
            print(
                f"\nAudit ID: "
                f"{event.get('audit_id', 'Unknown')}"
            )

            print(
                f"Timestamp: "
                f"{event.get('timestamp', 'Unknown')}"
            )

            print(
                f"Action: "
                f"{event.get('action', 'Unknown')}"
            )

            print(
                f"Report: "
                f"{event.get('report_filename', 'Unknown')}"
            )

            incident_id = event.get(
                "incident_id"
            )

            if incident_id:
                print(
                    f"Incident ID: {incident_id}"
                )

            status = event.get("status")

            if status:
                print(
                    f"Status: {status}"
                )

            sha256 = event.get("sha256")

            if sha256:
                print(
                    f"SHA-256: {sha256}"
                )