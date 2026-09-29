
import hashlib
from datetime import datetime, timedelta

from core.incident import Incident
from services.file_manager import FileManager


class IncidentManager:

    def __init__(self, correlation_gap_minutes=10):
        if correlation_gap_minutes < 0:
            raise ValueError(
                "Correlation gap cannot be negative"
            )

        self.correlation_gap = timedelta(
            minutes=correlation_gap_minutes
        )

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
        Extract start and end times from
        brute-force alert descriptions.

        Return None for legacy alerts and
        other alert types.
        """
        if alert.threat_type != "Potential Brute Force":
            return None

        marker = " failed logins between "

        if marker not in alert.description:
            return None

        try:
            window = alert.description.split(
                marker, 1
            )[1]

            start_text, end_text = window.split(
                " and ", 1
            )

            start = datetime.fromisoformat(
                start_text
            )

            end = datetime.fromisoformat(
                end_text
            )

            if end < start:
                return None

            return start, end

        except (ValueError, IndexError):
            return None

    @staticmethod
    def get_failure_count(alert):
        """
        Read the reported failed-login count
        from a brute-force alert.
        """
        try:
            return int(
                alert.description.split(
                    " failed logins between ", 1
                )[0]
            )

        except (ValueError, IndexError):
            return 0

    def get_correlation_details(self, alert):
        """
        Generate an incident key and title.

        Existing keys remain unchanged when
        an incident receives new evidence.
        """
        if alert.affected_file:
            key = (
                f"FILE:{alert.affected_file}"
            )

            title = (
                f"File Security Incident: "
                f"{alert.affected_file}"
            )

        elif alert.source_ip != "LOCAL_FILE":
            attack_window = self.get_attack_window(
                alert
            )

            if attack_window:
                start, end = attack_window

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
                # Legacy correlation format.
                key = f"IP:{alert.source_ip}"

                title = (
                    f"Suspicious Login Activity: "
                    f"{alert.source_ip}"
                )

        else:
            key = f"ALERT:{alert.alert_id}"
            title = alert.threat_type

        return key, title

    def windows_are_nearby(
        self,
        first_start,
        first_end,
        second_start,
        second_end
    ):
        """
        Return True if two attack windows
        overlap or have a gap no greater
        than the configured correlation gap.
        """
        return (
            first_start
            <= second_end + self.correlation_gap
            and second_start
            <= first_end + self.correlation_gap
        )

    def find_matching_attack(self, alert):
        """
        Find an existing brute-force incident
        from the same IP with an overlapping
        or nearby attack window.
        """
        incoming = self.get_attack_window(
            alert
        )

        if incoming is None:
            return None

        incoming_start, incoming_end = incoming

        for incident in self.incidents.values():
            for existing in incident.alerts:
                if (
                    existing.source_ip
                    != alert.source_ip
                ):
                    continue

                existing_window = (
                    self.get_attack_window(
                        existing
                    )
                )

                if existing_window is None:
                    continue

                existing_start, existing_end = (
                    existing_window
                )

                if self.windows_are_nearby(
                    incoming_start,
                    incoming_end,
                    existing_start,
                    existing_end
                ):
                    return incident

        return None

    def update_attack_evidence(
        self,
        incident,
        alert
    ):
        """
        Update an existing incident when
        an attack continues.

        Preserve:
        - Incident ID
        - Correlation key
        - Investigation status
        - Investigation notes
        """
        incoming = self.get_attack_window(
            alert
        )

        if incoming is None:
            return

        incoming_start, incoming_end = incoming

        for index, existing in enumerate(
            incident.alerts
        ):
            if (
                existing.source_ip
                != alert.source_ip
            ):
                continue

            existing_window = (
                self.get_attack_window(
                    existing
                )
            )

            if existing_window is None:
                continue

            existing_start, existing_end = (
                existing_window
            )

            nearby = self.windows_are_nearby(
                incoming_start,
                incoming_end,
                existing_start,
                existing_end
            )

            if not nearby:
                continue

            # Ignore older evidence that is
            # already covered by this incident.
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

            old_count = self.get_failure_count(
                existing
            )

            new_count = self.get_failure_count(
                alert
            )

            # Avoid double-counting events
            # from overlapping scan windows.
            count = max(
                old_count,
                new_count
            )

            alert.description = (
                f"{count} failed logins between "
                f"{combined_start.isoformat()} and "
                f"{combined_end.isoformat()}"
            )

            # Replace the older evidence.
            incident.alerts[index] = alert

            # Update the displayed title without
            # changing the saved correlation key.
            incident.title = (
                f"Suspicious Login Activity: "
                f"{alert.source_ip} "
                f"({combined_start.isoformat()} to "
                f"{combined_end.isoformat()})"
            )

            return

    def correlate(self, alerts):
        """
        Group alerts into incidents and
        prevent duplicate findings.
        """
        for alert in alerts:
            fingerprint = self.alert_fingerprint(
                alert
            )

            already_processed = any(
                self.alert_fingerprint(existing)
                == fingerprint
                for incident in self.incidents.values()
                for existing in incident.alerts
            )

            if already_processed:
                continue

            matching = self.find_matching_attack(
                alert
            )

            if matching is not None:
                self.update_attack_evidence(
                    matching,
                    alert
                )
                continue

            key, title = (
                self.get_correlation_details(
                    alert
                )
            )

            if key not in self.incidents:
                self.incidents[key] = Incident(
                    title,
                    key
                )

            self.incidents[key].add_alert(
                alert
            )

        return list(
            self.incidents.values()
        )

    def update_incident(
        self,
        incident_id,
        status
    ):
        for incident in self.incidents.values():
            if incident.incident_id == incident_id:
                incident.update_status(
                    status
                )

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