
import hashlib
from datetime import datetime

from core.incident import Incident
from services.file_manager import FileManager


class IncidentManager:

    def __init__(self):
        self.incidents = {}
        self.load_incidents()

    def load_incidents(self):
        saved_data = FileManager.load_data("incidents.json")

        for data in saved_data:
            incident = Incident.from_dict(data)
            self.incidents[incident.correlation_key] = incident

    @staticmethod
    def alert_fingerprint(alert):
        evidence = "|".join([
            alert.threat_type,
            alert.source_ip,
            alert.affected_file or "",
            alert.description
        ])

        return hashlib.sha256(
            evidence.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def get_attack_window(alert):
        if alert.threat_type != "Potential Brute Force":
            return None

        marker = " failed logins between "

        if marker not in alert.description:
            return None

        try:
            window = alert.description.split(marker, 1)[1]
            start_text, end_text = window.split(" and ", 1)

            start = datetime.fromisoformat(start_text)
            end = datetime.fromisoformat(end_text)

            if end < start:
                return None

            return start, end

        except (ValueError, IndexError):
            return None

    def get_correlation_details(self, alert):

        if alert.affected_file:
            key = f"FILE:{alert.affected_file}"
            title = (
                f"File Security Incident: "
                f"{alert.affected_file}"
            )

        elif alert.source_ip != "LOCAL_FILE":
            window = self.get_attack_window(alert)

            if window:
                start, end = window

                key = (
                    f"IP:{alert.source_ip}:"
                    f"{start.isoformat()}:"
                    f"{end.isoformat()}"
                )

                title = (
                    f"Suspicious Login Activity: "
                    f"{alert.source_ip} "
                    f"({start.isoformat()} to "
                    f"{end.isoformat()})"
                )

            else:
                # Maintain compatibility with older alerts.
                key = f"IP:{alert.source_ip}"
                title = (
                    f"Suspicious Login Activity: "
                    f"{alert.source_ip}"
                )

        else:
            key = f"ALERT:{alert.alert_id}"
            title = alert.threat_type

        return key, title

    def find_matching_attack(self, alert):
        """
        Find an existing incident for the same IP
        with an overlapping attack window.

        Legacy alerts without a recorded window
        are not merged automatically.
        """
        incoming = self.get_attack_window(alert)

        if incoming is None:
            return None

        incoming_start, incoming_end = incoming

        for incident in self.incidents.values():
            for existing in incident.alerts:
                if existing.source_ip != alert.source_ip:
                    continue

                existing_window = self.get_attack_window(
                    existing
                )

                if existing_window is None:
                    continue

                existing_start, existing_end = existing_window

                overlaps = (
                    incoming_start <= existing_end
                    and existing_start <= incoming_end
                )

                if overlaps:
                    return incident

        return None

    def update_attack_evidence(self, incident, alert):
        """
        Keep the earliest start and latest end
        observed for an ongoing attack.

        Preserve the incident's ID, key, status
        and investigation notes.
        """
        incoming = self.get_attack_window(alert)

        if incoming is None:
            return

        incoming_start, incoming_end = incoming

        for index, existing in enumerate(incident.alerts):
            if existing.source_ip != alert.source_ip:
                continue

            existing_window = self.get_attack_window(
                existing
            )

            if existing_window is None:
                continue

            existing_start, existing_end = existing_window

            overlaps = (
                incoming_start <= existing_end
                and existing_start <= incoming_end
            )

            if not overlaps:
                continue

            # Ignore older or identical scan results.
            if (
                incoming_start >= existing_start
                and incoming_end <= existing_end
            ):
                return

            combined_start = min(
                existing_start,
                incoming_start
            )

            combined_end = max(
                existing_end,
                incoming_end
            )

            # Keep the newer evidence while ensuring
            # its recorded window includes all activity.
            old_count = self.get_failure_count(existing)
            new_count = self.get_failure_count(alert)

            # If windows overlap, adding their counts
            # would double-count shared events.
            # Use the larger observed count instead.
            count = max(old_count, new_count)

            alert.description = (
                f"{count} failed logins between "
                f"{combined_start.isoformat()} and "
                f"{combined_end.isoformat()}"
            )

            incident.alerts[index] = alert

            incident.title = (
                f"Suspicious Login Activity: "
                f"{alert.source_ip} "
                f"({combined_start.isoformat()} to "
                f"{combined_end.isoformat()})"
            )

            return

    @staticmethod
    def get_failure_count(alert):
        try:
            return int(
                alert.description.split(
                    " failed logins between ", 1
                )[0]
            )
        except (ValueError, IndexError):
            return 0

    def correlate(self, alerts):

        for alert in alerts:
            fingerprint = self.alert_fingerprint(alert)

            already_processed = any(
                self.alert_fingerprint(existing)
                == fingerprint
                for incident in self.incidents.values()
                for existing in incident.alerts
            )

            if already_processed:
                continue

            matching = self.find_matching_attack(alert)

            if matching is not None:
                self.update_attack_evidence(
                    matching,
                    alert
                )
                continue

            key, title = self.get_correlation_details(
                alert
            )

            if key not in self.incidents:
                self.incidents[key] = Incident(
                    title,
                    key
                )

            self.incidents[key].add_alert(alert)

        return list(self.incidents.values())

    def update_incident(self, incident_id, status):

        for incident in self.incidents.values():
            if incident.incident_id == incident_id:
                incident.update_status(status)
                self.save_incidents()
                return True

        return False

    def add_investigation_note(
        self,
        incident_id,
        analyst,
        message
    ):
        for incident in self.incidents.values():
            if incident.incident_id == incident_id:
                incident.add_note(
                    analyst,
                    message
                )
                self.save_incidents()
                return True

        return False

    def save_incidents(self):
        FileManager.save_data(
            "incidents.json",
            [
                incident.to_dict()
                for incident in self.incidents.values()
            ]
        )