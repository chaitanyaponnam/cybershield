
import json
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


class ReportGenerator:
    REPORT_DIR = (
        Path(__file__).resolve().parent.parent
        / "reports"
    )

    @staticmethod
    def prepare_evidence(evidence):
        """
        Convert the evidence-correlator result into
        a consistent report section.
        """
        if evidence is None:
            return {
                "collection_status": "NOT_REQUESTED",
                "tracked_event_ids": 0,
                "exact_match_count": 0,
                "missing_tracked_events": 0,
                "legacy_alerts": 0,
                "approximate_match_count": 0,
                "exact_matches": [],
                "legacy_matches": [],
            }

        exact_matches = evidence.get(
            "exact_matches", []
        )
        legacy_matches = evidence.get(
            "legacy_matches", []
        )

        return {
            "collection_status": "COMPLETED",
            "tracked_event_ids": evidence.get(
                "tracked_event_ids", 0
            ),
            "exact_match_count": len(exact_matches),
            "missing_tracked_events": evidence.get(
                "missing_tracked_events", 0
            ),
            "legacy_alerts": evidence.get(
                "legacy_alerts", 0
            ),
            "approximate_match_count": len(
                legacy_matches
            ),
            "exact_matches": exact_matches,
            "legacy_matches": legacy_matches,
        }

    @classmethod
    def build_report(cls, incident, evidence=None):
        return {
            "report_type": "CyberShield Incident Report",
            "generated_at": datetime.now().isoformat(),
            "incident": incident.to_dict(),
            "login_evidence": cls.prepare_evidence(
                evidence
            ),
        }

    @classmethod
    def make_report_path(cls, incident, extension):
        cls.REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        filename = (
            f"incident_{incident.incident_id}_"
            f"{timestamp}.{extension}"
        )

        return cls.REPORT_DIR / filename

    @classmethod
    def export_incident(cls, incident, evidence=None):
        report_path = cls.make_report_path(
            incident, "json"
        )

        report = cls.build_report(
            incident, evidence
        )

        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                report,
                file,
                indent=4
            )

        return report_path

    @staticmethod
    def safe_text(value):
        """
        Escape user-controlled values before
        placing them inside PDF paragraphs.
        """
        if value is None:
            return "Unknown"

        return escape(str(value))

    @classmethod
    def add_evidence_events(
        cls,
        elements,
        heading,
        events,
        styles
    ):
        elements.append(
            Paragraph(
                heading,
                styles["Heading3"]
            )
        )

        if not events:
            elements.append(
                Paragraph(
                    "No matching events found.",
                    styles["Normal"]
                )
            )
            elements.append(Spacer(1, 10))
            return

        for index, event in enumerate(
            events, start=1
        ):
            elements.append(
                Paragraph(
                    f"<b>Event {index}</b>",
                    styles["Normal"]
                )
            )

            fields = (
                ("Time", "timestamp"),
                ("Source IP", "ip"),
                ("Username", "username"),
                ("Status", "status"),
                ("Event ID", "event_id"),
            )

            for label, key in fields:
                value = event.get(key)

                if key == "event_id" and not value:
                    value = "Unavailable"

                elements.append(
                    Paragraph(
                        f"<b>{label}:</b> "
                        f"{cls.safe_text(value)}",
                        styles["Normal"]
                    )
                )

            elements.append(Spacer(1, 10))

    @classmethod
    def export_incident_pdf(
        cls,
        incident,
        evidence=None
    ):
        report_path = cls.make_report_path(
            incident, "pdf"
        )

        report = cls.build_report(
            incident, evidence
        )
        login_evidence = report["login_evidence"]

        document = SimpleDocTemplate(
            str(report_path),
            pagesize=(595, 842),
            leftMargin=45,
            rightMargin=45,
            topMargin=45,
            bottomMargin=45
        )

        styles = getSampleStyleSheet()
        styles["Title"].alignment = TA_CENTER

        elements = []

        elements.append(
            Paragraph(
                "CYBERSHIELD INCIDENT REPORT",
                styles["Title"]
            )
        )
        elements.append(Spacer(1, 20))

        details = [
            ["Incident ID", incident.incident_id],
            ["Title", incident.title],
            ["Severity", incident.severity],
            ["Status", incident.status],
            ["Created", incident.created_at],
            [
                "Related Alerts",
                str(len(incident.alerts))
            ],
        ]

        # Paragraph cells wrap long incident IDs
        # and titles instead of overflowing.
        table_data = [
            [
                Paragraph(
                    cls.safe_text(label),
                    styles["Normal"]
                ),
                Paragraph(
                    cls.safe_text(value),
                    styles["Normal"]
                ),
            ]
            for label, value in details
        ]

        table = Table(
            table_data,
            colWidths=[120, 380]
        )

        table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    8
                ),
            ])
        )

        elements.append(table)
        elements.append(Spacer(1, 20))

        # Existing detected-alert section.
        elements.append(
            Paragraph(
                "DETECTED ALERTS",
                styles["Heading2"]
            )
        )

        if not incident.alerts:
            elements.append(
                Paragraph(
                    "No alerts recorded.",
                    styles["Normal"]
                )
            )

        for alert in incident.alerts:
            elements.append(
                Paragraph(
                    f"<b>{cls.safe_text(alert.threat_type)}</b>"
                    f" - {cls.safe_text(alert.severity)}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    cls.safe_text(alert.description),
                    styles["Normal"]
                )
            )

            elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 15))

        # Existing investigation-notes section.
        elements.append(
            Paragraph(
                "INVESTIGATION NOTES",
                styles["Heading2"]
            )
        )

        if not incident.notes:
            elements.append(
                Paragraph(
                    "No investigation notes recorded.",
                    styles["Normal"]
                )
            )

        for note in incident.notes:
            elements.append(
                Paragraph(
                    f"<b>Analyst:</b> "
                    f"{cls.safe_text(note.get('analyst'))}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Time:</b> "
                    f"{cls.safe_text(note.get('timestamp'))}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    cls.safe_text(note.get("message")),
                    styles["Normal"]
                )
            )

            elements.append(Spacer(1, 12))

        elements.append(Spacer(1, 15))

        # New Phase 24 evidence section.
        elements.append(
            Paragraph(
                "CORRELATED LOGIN EVIDENCE",
                styles["Heading2"]
            )
        )

        if (
            login_evidence["collection_status"]
            == "NOT_REQUESTED"
        ):
            elements.append(
                Paragraph(
                    "Login evidence was not requested "
                    "for this report.",
                    styles["Normal"]
                )
            )

        else:
            summary = (
                (
                    "Tracked event IDs",
                    "tracked_event_ids"
                ),
                (
                    "Exact matches found",
                    "exact_match_count"
                ),
                (
                    "Missing tracked events",
                    "missing_tracked_events"
                ),
                (
                    "Legacy alerts",
                    "legacy_alerts"
                ),
                (
                    "Approximate legacy matches",
                    "approximate_match_count"
                ),
            )

            for label, key in summary:
                elements.append(
                    Paragraph(
                        f"<b>{label}:</b> "
                        f"{login_evidence[key]}",
                        styles["Normal"]
                    )
                )

            elements.append(Spacer(1, 15))

            cls.add_evidence_events(
                elements,
                "EXACT EVENT-ID MATCHES",
                login_evidence["exact_matches"],
                styles
            )

            cls.add_evidence_events(
                elements,
                "APPROXIMATE LEGACY MATCHES",
                login_evidence["legacy_matches"],
                styles
            )

            elements.append(
                Paragraph(
                    "Legacy matches are approximate. "
                    "Matching source IP and timestamps "
                    "do not establish a verified "
                    "event-ID link.",
                    styles["Normal"]
                )
            )

        document.build(elements)

        return report_path