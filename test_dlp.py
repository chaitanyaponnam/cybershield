
from pathlib import Path

from detectors.dlp_detector import DLPDetector
from services.file_manager import FileManager


file_path = Path("test_files/confidential.txt")

content = file_path.read_text(encoding="utf-8")

events = [{
    "filename": file_path.name,
    "content": content
}]

detector = DLPDetector()

alerts = detector.detect(events)

print("===== DLP SCAN RESULTS =====")
print(f"Total Alerts: {len(alerts)}")

for alert in alerts:
    alert.display()

FileManager.save_data(
    "dlp_alerts.json",
    [alert.to_dict() for alert in alerts]
)