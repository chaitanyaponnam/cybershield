
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
        """
        Extract the attack window from the updated
        LoginDetector's alert description.

        Return None for older alerts or other detectors.
        """
        if alert.threat_type != "Potential Brute Force":
            return None

        if " failed logins between " not in alert.description:
            return None

        try:
            window = alert.description.split(
                " failed logins between ", 1
            )[1]

            start_text, end_text = window.split(
                " and ", 1
            )

            start = datetime.fromisoformat(start_text)
            end = datetime.fromisoformat(end_text)

            if end < start:
                return None

            return start.isoformat(), end.isoformat()

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
            attack_window = self.get_attack_window(alert)

            if attack_window:
                start, end = attack_window

                key = (
                    f"IP:{alert.source_ip}:"
                    f"{start}:{end}"
                )

                title = (
                    f"Suspicious Login Activity: "
                    f"{alert.source_ip} "
                    f"({start} to {end})"
                )

            else:
                # Preserve the original correlation
                # format for older login alerts.
                key = f"IP:{alert.source_ip}"
                title = (
                    f"Suspicious Login Activity: "
                    f"{alert.source_ip}"
                )

        else:
            key = f"ALERT:{alert.alert_id}"
            title = alert.threat_type

        return key, title

    def correlate(self, alerts):

        for alert in alerts:
            fingerprint = self.alert_fingerprint(alert)

            # Check all existing incidents first.
            # This prevents a previously saved alert
            # from being duplicated after the upgrade.
            already_processed = any(
                self.alert_fingerprint(existing) == fingerprint
                for incident in self.incidents.values()
                for existing in incident.alerts
            )

            if already_processed:
                continue

            key, title = self.get_correlation_details(alert)

            if key not in self.incidents:
                self.incidents[key] = Incident(title, key)

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
                incident.add_note(analyst, message)
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