class RiskScorer:
    """Calculate SOC incident risk scores."""

    SEVERITY_SCORES = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 30,
        "CRITICAL": 40,
    }

    THREAT_SCORES = {
        "SENSITIVE DATA DETECTED": 25,
        "FILE INTEGRITY VIOLATION": 20,
        "POTENTIAL BRUTE FORCE": 20,
    }

    STATUS_SCORES = {
        "OPEN": 5,
        "INVESTIGATING": 10,
        "RESOLVED": 0,
    }

    @staticmethod
    def calculate(incident):
        severity = getattr(
            incident,
            "severity",
            "LOW"
        ).strip().upper()

        status = getattr(
            incident,
            "status",
            "OPEN"
        ).strip().upper()

        alerts = getattr(
            incident,
            "alerts",
            []
        )

        severity_score = RiskScorer.SEVERITY_SCORES.get(
            severity,
            10
        )

        alert_score = min(
            len(alerts) * 5,
            25
        )

        threat_score = RiskScorer._threat_score(
            alerts
        )

        status_score = RiskScorer.STATUS_SCORES.get(
            status,
            5
        )

        return min(
            severity_score
            + alert_score
            + threat_score
            + status_score,
            100
        )

    @staticmethod
    def _threat_score(alerts):
        highest_score = 10

        for alert in alerts:
            threat_type = getattr(
                alert,
                "threat_type",
                ""
            ).strip().upper()

            score = RiskScorer.THREAT_SCORES.get(
                threat_type,
                10
            )

            highest_score = max(
                highest_score,
                score
            )

        return highest_score

    @staticmethod
    def classify(score):
        if score >= 75:
            return "CRITICAL"

        if score >= 50:
            return "HIGH"

        if score >= 25:
            return "MEDIUM"

        return "LOW"