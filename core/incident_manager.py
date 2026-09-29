
from core.incident import Incident
from services.file_manager import FileManager
import hashlib



class IncidentManager:

    def __init__(self):
        self.incidents = {}
        self.load_incidents()

    def load_incidents(self):
        saved_data = FileManager.load_data(
            "incidents.json"
        )

        for data in saved_data:
            incident = Incident.from_dict(data)

            self.incidents[
                incident.correlation_key
            ] = incident

    def correlate(self, alerts):
        for alert in alerts:

            if alert.affected_file:
                key = f"FILE:{alert.affected_file}"
                title = (
                    f"File Security Incident: "
                    f"{alert.affected_file}"
                )

            elif alert.source_ip != "LOCAL_FILE":
                key = f"IP:{alert.source_ip}"
                title = (
                    f"Suspicious Login Activity: "
                    f"{alert.source_ip}"
                )

            else:
                key = f"ALERT:{alert.alert_id}"
                title = alert.threat_type

            if key not in self.incidents:
                self.incidents[key] = Incident(
                    title,
                    key
                )

            incident = self.incidents[key]

            # Avoid duplicate alert IDs
            existing_fingerprints = {
                self.alert_fingerprint(item)
                for item in incident.alerts
            }
            new_fingerprint = self.alert_fingerprint(alert)

            if new_fingerprint not in existing_fingerprints:
                incident.add_alert(alert)

        return list(self.incidents.values())

    def update_incident(self, incident_id, status):
        for incident in self.incidents.values():
            if incident.incident_id == incident_id:
                incident.update_status(status)
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