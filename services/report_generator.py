
import json
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from xml.sax.saxutils import escape


class ReportGenerator:

    REPORT_DIR = (
        Path(__file__).resolve().parent.parent
        / "reports"
    )

    @classmethod
    def export_incident(cls, incident):
        cls.REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = (
            f"incident_{incident.incident_id}_"
            f"{timestamp}.json"
        )

        report_path = cls.REPORT_DIR / filename

        report = {
            "report_type": "CyberShield Incident Report",
            "generated_at": datetime.now().isoformat(),
            "incident": incident.to_dict()
        }

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
    
    @classmethod
    def export_incident_pdf(cls, incident):
        cls.REPORT_DIR.mkdir(
            parents=True,
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = (
            f"incident_{incident.incident_id}_"
            f"{timestamp}.pdf"
        )

        report_path = cls.REPORT_DIR / filename

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
            ["Related Alerts", str(len(incident.alerts))]
        ]

        table = Table(
            details,
            colWidths=[120, 380]
        )

        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (0, -1),
                 colors.lightgrey),
                ("GRID", (0, 0), (-1, -1),
                 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1),
                 "TOP"),
                ("PADDING", (0, 0), (-1, -1), 8)
            ])
        )

        elements.append(table)
        elements.append(Spacer(1, 20))

        elements.append(
            Paragraph(
                "DETECTED ALERTS",
                styles["Heading2"]
            )
        )

        for alert in incident.alerts:
            elements.append(
                Paragraph(
                    f"<b>{escape(alert.threat_type)}</b>"
                    f" - {escape(alert.severity)}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    escape(alert.description),
                    styles["Normal"]
                )
            )

            elements.append(Spacer(1, 10))

        elements.append(Spacer(1, 15))

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
                    f"{escape(note['analyst'])}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    f"<b>Time:</b> "
                    f"{escape(note['timestamp'])}",
                    styles["Normal"]
                )
            )

            elements.append(
                Paragraph(
                    escape(note["message"]),
                    styles["Normal"]
                )
            )

            elements.append(Spacer(1, 12))

        document.build(elements)

        return report_path