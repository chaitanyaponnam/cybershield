
from datetime import datetime
from pathlib import Path

from detectors.login_detector import LoginDetector
from detectors.dlp_detector import DLPDetector
from detectors.integrity_detector import IntegrityDetector
from services.file_manager import FileManager


class SecurityEngine:

    def __init__(self):
        self.login_detector = LoginDetector()
        self.dlp_detector = DLPDetector()
        self.integrity_detector = IntegrityDetector()

    def run_scan(self):
        print("\n===== CYBERSHIELD SECURITY SCAN =====")

        all_alerts = []

        # 1. Analyze saved login events
        print("\n[1] Analyzing login activity...")

        login_events = FileManager.load_data(
            "login_logs.json"
        )

        login_alerts = self.login_detector.detect(
            login_events
        )

        all_alerts.extend(login_alerts)

        # 2. Scan test documents
        print("\n[2] Scanning sensitive documents...")

        test_directory = (
            Path(__file__).resolve().parent.parent
            / "test_files"
        )

        files = list(test_directory.glob("*.txt"))
        dlp_events = []

        for path in files:
            dlp_events.append({
                "filename": path.name,
                "content": path.read_text(
                    encoding="utf-8"
                )
            })

        dlp_alerts = self.dlp_detector.detect(
            dlp_events
        )

        all_alerts.extend(dlp_alerts)

        # 3. Verify file integrity
        print("\n[3] Checking file integrity...")

        integrity_alerts = (
            self.integrity_detector.detect(files)
        )

        all_alerts.extend(integrity_alerts)

        # 4. Generate consolidated report
        print("\n===== SECURITY SCAN RESULTS =====")

        print(f"Login alerts: {len(login_alerts)}")
        print(f"DLP alerts: {len(dlp_alerts)}")
        print(
            f"Integrity alerts: {len(integrity_alerts)}"
        )
        print(f"Total alerts: {len(all_alerts)}")

        report = {
            "scan_time": datetime.now().isoformat(),
            "total_alerts": len(all_alerts),
            "alerts": [
                alert.to_dict()
                for alert in all_alerts
            ]
        }

        FileManager.save_data(
            "security_report.json",
            report
        )

        return all_alerts