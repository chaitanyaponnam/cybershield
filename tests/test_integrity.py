
from detectors.integrity_detector import IntegrityDetector
from services.file_manager import FileManager


detector = IntegrityDetector()

files = [
    "test_files/confidential.txt"
]

print("===== FILE INTEGRITY MONITOR =====")

print("1. Create baseline")
print("2. Scan files")

choice = input("Enter your choice: ")

if choice == "1":
    detector.create_baseline(files)

elif choice == "2":
    alerts = detector.detect(files)

    print(f"\nTotal Alerts: {len(alerts)}")

    for alert in alerts:
        alert.display()

    FileManager.save_data(
        "integrity_alerts.json",
        [alert.to_dict() for alert in alerts]
    )

else:
    print("Invalid choice!")