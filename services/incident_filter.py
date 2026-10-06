class IncidentFilter:
    """Provide read-only filtering for SOC incidents."""

    @staticmethod
    def by_severity(incidents, severity):
        severity = severity.strip().upper()

        return [
            incident
            for incident in incidents
            if getattr(incident, "severity", "").upper()
            == severity
        ]

    @staticmethod
    def by_status(incidents, status):
        status = status.strip().upper()

        return [
            incident
            for incident in incidents
            if getattr(incident, "status", "").upper()
            == status
        ]

    @staticmethod
    def by_threat_type(incidents, threat_type):
        threat_type = threat_type.strip().lower()

        results = []

        for incident in incidents:
            alerts = getattr(
                incident,
                "alerts",
                []
            )

            for alert in alerts:
                current_threat = getattr(
                    alert,
                    "threat_type",
                    ""
                )

                if (
                    current_threat.strip().lower()
                    == threat_type
                ):
                    results.append(incident)
                    break

        return results

    @staticmethod
    def by_source_ip(incidents, source_ip):
        source_ip = source_ip.strip()

        results = []

        for incident in incidents:
            alerts = getattr(
                incident,
                "alerts",
                []
            )

            for alert in alerts:
                current_source_ip = getattr(
                    alert,
                    "source_ip",
                    ""
                )

                if current_source_ip == source_ip:
                    results.append(incident)
                    break

        return results

    @staticmethod
    def by_incident_id(incidents, incident_id):
        incident_id = incident_id.strip()

        return [
            incident
            for incident in incidents
            if getattr(
                incident,
                "incident_id",
                ""
            ) == incident_id
        ]