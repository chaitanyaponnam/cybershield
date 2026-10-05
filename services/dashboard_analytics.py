from collections import Counter


class DashboardAnalytics:
    """Calculate SOC dashboard metrics from security incidents."""

    @staticmethod
    def calculate(incidents):
        """
        Calculate dashboard analytics from a collection
        of incident objects.
        """

        incidents = list(incidents)

        severity_counts = Counter()
        status_counts = Counter()
        threat_counts = Counter()
        source_ip_counts = Counter()

        total_alerts = 0

        for incident in incidents:
            severity = getattr(
                incident,
                "severity",
                "UNKNOWN"
            )

            status = getattr(
                incident,
                "status",
                "UNKNOWN"
            )

            severity_counts[severity] += 1
            status_counts[status] += 1

            alerts = getattr(
                incident,
                "alerts",
                []
            )

            for alert in alerts:
                total_alerts += 1

                threat_type = getattr(
                    alert,
                    "threat_type",
                    "Unknown Threat"
                )

                threat_counts[threat_type] += 1

                source_ip = getattr(
                    alert,
                    "source_ip",
                    None
                )

                if source_ip:
                    source_ip_counts[source_ip] += 1

        return {
            "total_incidents": len(incidents),
            "total_alerts": total_alerts,
            "severity": dict(severity_counts),
            "status": dict(status_counts),
            "threat_types": dict(threat_counts),
            "source_ips": dict(source_ip_counts)
        }

    @staticmethod
    def top_threats(analytics, limit=5):
        """Return the most common threat types."""

        return sorted(
            analytics.get(
                "threat_types",
                {}
            ).items(),
            key=lambda item: item[1],
            reverse=True
        )[:limit]

    @staticmethod
    def top_source_ips(analytics, limit=5):
        """Return the most common source IP addresses."""

        return sorted(
            analytics.get(
                "source_ips",
                {}
            ).items(),
            key=lambda item: item[1],
            reverse=True
        )[:limit]

    @staticmethod
    def get_severity_count(
        analytics,
        severity
    ):
        """Return the number of incidents for a severity."""

        return analytics.get(
            "severity",
            {}
        ).get(
            severity,
            0
        )

    @staticmethod
    def get_status_count(
        analytics,
        status
    ):
        """Return the number of incidents for a status."""

        return analytics.get(
            "status",
            {}
        ).get(
            status,
            0
        )